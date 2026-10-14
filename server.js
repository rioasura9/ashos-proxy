/*
 * AshOS proxy v2 — password-protected forward proxy + page-fetch mode.
 *
 * Two ways to use it:
 *  1. As a real proxy in a browser / phone proxy settings (HTTP proxy with
 *     Basic auth). HTTPS sites go through CONNECT tunnels, plain-HTTP sites
 *     are forwarded. This is what "use the network as proxy" means.
 *  2. Page-fetch mode for the AshOS Browser app: /?u=<url>&k=<password>
 *     fetches the page server-side and re-serves it WITHOUT the
 *     X-Frame-Options / CSP headers that block iframe embedding.
 *
 * Auth: every proxied request needs the password.
 *   - Forward-proxy mode: standard `Proxy-Authorization: Basic` header
 *     (browsers send this automatically from proxy settings).
 *   - Fetch mode: `k` query parameter.
 * The password comes from the PROXY_PASSWORD env var. The server REFUSES
 * to start without it — never run an open relay.
 *
 * Safety: private/internal target addresses are blocked (SSRF protection),
 * responses are capped at 6 MB, port 25 (SMTP) is blocked.
 * PROXY_ALLOW_PRIVATE=1 disables the private-IP block — for local testing
 * ONLY, never enable it on a public server.
 *
 * Zero dependencies. Run:  PROXY_PASSWORD=secret node server.js
 * (listens on $PORT or 3000). Sevalla start command: `node server.js`.
 */
"use strict";
const http = require("node:http");
const net = require("node:net");
const dns = require("node:dns").promises;
const crypto = require("node:crypto");

const PORT = parseInt(process.env.PORT || "3000", 10);
const PASSWORD = process.env.PROXY_PASSWORD || "";
const USERNAME = "ashborn";
const ALLOW_PRIVATE = process.env.PROXY_ALLOW_PRIVATE === "1";
const MAX_BYTES = 6 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 15000;

if (!PASSWORD) {
  console.error("FATAL: PROXY_PASSWORD env var is not set. Refusing to start without a password.");
  process.exit(1);
}
if (ALLOW_PRIVATE) console.warn("WARNING: PROXY_ALLOW_PRIVATE=1 — private-IP block disabled (testing only).");

function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/* Standard proxy auth: Proxy-Authorization: Basic base64(user:pass) */
function checkBasicAuth(req) {
  const h = req.headers["proxy-authorization"] || "";
  const m = /^Basic (.+)$/.exec(h.trim());
  if (!m) return false;
  let decoded;
  try {
    decoded = Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return false;
  }
  return timingSafeEqual(decoded, USERNAME + ":" + PASSWORD);
}

/* Key auth for the ?u= fetch mode (iframes can't send headers). */
function checkKey(reqUrl) {
  return timingSafeEqual(reqUrl.searchParams.get("k") || "", PASSWORD);
}

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return (
      p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 169 && p[1] === 254)
    );
  }
  const l = ip.toLowerCase();
  return l === "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd");
}

/* Returns true when the hostname resolves only to public addresses. */
async function safeHost(hostname) {
  if (ALLOW_PRIVATE) return true;
  let addrs;
  try {
    addrs = await dns.lookup(hostname, { all: true });
  } catch {
    return false;
  }
  if (!addrs.length) return false;
  return !addrs.some((a) => isPrivate(a.address));
}

/* ---------------- CONNECT tunneling (HTTPS through the proxy) ---------------- */
function handleConnect(req, clientSocket, head) {
  if (!checkBasicAuth(req)) {
    clientSocket.end(
      "HTTP/1.1 407 Proxy Authentication Required\r\n" +
        'Proxy-Authenticate: Basic realm="AshOS Proxy"\r\n' +
        "Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    return;
  }
  const m = /^([^:[\]]+|\[[^\]]+\])(?::(\d+))?$/.exec(req.url || "");
  if (!m) {
    clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }
  const host = m[1];
  const port = parseInt(m[2] || "443", 10);
  if (port === 25 || port < 1 || port > 65535) {
    clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }
  safeHost(host).then((ok) => {
    if (!ok) {
      clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const srv = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) srv.write(head);
      clientSocket.pipe(srv);
      srv.pipe(clientSocket);
    });
    srv.setTimeout(120000);
    const done = () => {
      try { clientSocket.destroy(); } catch {}
      try { srv.destroy(); } catch {}
    };
    const fail = (msg) => {
      try { clientSocket.end(msg); } catch {}
      setTimeout(done, 200);
    };
    srv.on("error", () => fail("HTTP/1.1 502 Bad Gateway\r\n\r\n"));
    srv.on("timeout", done);
    clientSocket.on("error", done);
    clientSocket.on("close", () => { try { srv.destroy(); } catch {} });
  }).catch(() => {
    try { clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch {}
    setTimeout(() => { try { clientSocket.destroy(); } catch {} }, 200);
  });
}

/* ---------------- plain-HTTP forwarding (absolute-URI requests) ---------------- */
async function handleForward(req, res, target) {
  if (!checkBasicAuth(req)) {
    res.writeHead(407, { "Proxy-Authenticate": 'Basic realm="AshOS Proxy"', "Content-Length": "0" });
    res.end();
    return;
  }
  const ok = await safeHost(target.hostname);
  if (!ok) {
    res.writeHead(403, { "content-type": "text/plain" });
    res.end("Blocked.");
    return;
  }
  try {
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (["proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "upgrade"].includes(lk)) continue;
      headers[k] = v;
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    let upstream;
    try {
      upstream = await fetch(target.toString(), {
        method: req.method,
        headers,
        body: ["GET", "HEAD"].includes(req.method) ? undefined : req,
        duplex: "half",
        signal: ctl.signal,
        redirect: "manual",
      });
    } finally {
      clearTimeout(timer);
    }
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BYTES) {
      res.writeHead(413, { "content-type": "text/plain" });
      res.end("Too large.");
      return;
    }
    const out = {};
    upstream.headers.forEach((v, k) => {
      if (["transfer-encoding", "connection", "keep-alive"].includes(k.toLowerCase())) return;
      out[k] = v;
    });
    res.writeHead(upstream.status, out);
    res.end(buf);
  } catch {
    res.writeHead(504, { "content-type": "text/plain" });
    res.end("Could not reach that site.");
  }
}

/* ---------------- ?u= page-fetch mode (for the AshOS Browser iframe) ---------------- */
function rewriteHtml(html, target, selfBase) {
  const prox = (u) => selfBase + "/?u=" + encodeURIComponent(u);
  html = html.replace(
    /(<(?:a|form)\b[^>]*?\b(?:href|action)\s*=\s*")([^"]*)(")/gi,
    (m, pre, link, post) => {
      if (/^(javascript:|mailto:|tel:|#)/i.test(link)) return m;
      let abs;
      try {
        abs = new URL(link, target).toString();
      } catch {
        return m;
      }
      if (!/^https?:/i.test(abs)) return m;
      return pre + prox(abs) + post;
    }
  );
  const dir = target.origin + target.pathname.replace(/[^/]*$/, "");
  const base = '<base href="' + dir + '">';
  if (/<head[^>]*>/i.test(html)) html = html.replace(/<head[^>]*>/i, (h) => h + base);
  else html = base + html;
  return html;
}

async function safeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (!url.hostname) return null;
  if (!(await safeHost(url.hostname))) return null;
  return url;
}

async function handleFetch(req, res, reqUrl, selfBase) {
  if (!checkKey(reqUrl)) {
    res.writeHead(403, { "content-type": "text/plain" });
    res.end("Wrong or missing proxy key.");
    return;
  }
  const target = await safeUrl(reqUrl.searchParams.get("u") || "");
  if (!target) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Blocked or invalid URL.");
    return;
  }
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    let upstream;
    try {
      upstream = await fetch(target.toString(), {
        signal: ctl.signal,
        redirect: "follow",
        headers: {
          "user-agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 AshOS-EmberWeb/1.0",
          "accept-language": "en-US,en;q=0.9",
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });
    } finally {
      clearTimeout(timer);
    }
    if (!upstream.ok) {
      res.writeHead(502, { "content-type": "text/plain" });
      res.end("The site answered with an error (" + upstream.status + ").");
      return;
    }
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BYTES) {
      res.writeHead(413, { "content-type": "text/plain" });
      res.end("That page is too large to proxy.");
      return;
    }
    const ct = upstream.headers.get("content-type") || "application/octet-stream";
    if (ct.includes("text/html")) {
      const out = rewriteHtml(buf.toString("utf8"), new URL(upstream.url), selfBase);
      // Deliberately NOT forwarding x-frame-options / content-security-policy.
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(out);
    } else {
      res.writeHead(200, { "content-type": ct });
      res.end(buf);
    }
  } catch {
    res.writeHead(504, { "content-type": "text/plain" });
    res.end("Could not reach that site (timeout or connection failed).");
  }
}

/* ---------------- main server ---------------- */
const server = http.createServer(async (req, res) => {
  let reqUrl;
  try {
    reqUrl = new URL(req.url, "http://x");
  } catch {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("Bad request");
    return;
  }

  const proto = req.headers["x-forwarded-proto"] || "http";
  const selfBase = proto + "://" + req.headers.host;

  // Plain-HTTP forward-proxy requests arrive as absolute URIs.
  if (/^https?:\/\//i.test(req.url || "")) {
    let target;
    try {
      target = new URL(req.url);
    } catch {
      res.writeHead(400);
      res.end("Bad request");
      return;
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      res.writeHead(400);
      res.end("Bad request");
      return;
    }
    await handleForward(req, res, target);
    return;
  }

  const u = reqUrl.searchParams.get("u");
  if (reqUrl.pathname === "/" && !u) {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("AshOS proxy v2 is running. Page-fetch mode: /?u=<url>&k=<key>.");
    return;
  }
  if (u) {
    await handleFetch(req, res, reqUrl, selfBase);
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("Not found.");
});

server.on("connect", handleConnect);

server.listen(PORT, () => console.log("AshOS proxy v2 listening on port " + PORT));

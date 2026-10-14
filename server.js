/*
 * AshOS web proxy — gives the AshOS Browser app real internet access.
 *
 * Why it exists: many sites (Google, etc.) send X-Frame-Options /
 * Content-Security-Policy headers that forbid loading inside an iframe.
 * No client-side trick can bypass that — it's enforced by the browser.
 * This tiny server fetches the page itself and re-serves it WITHOUT those
 * headers, so the AshOS browser iframe can display it.
 *
 * Zero dependencies. Run:  node server.js   (listens on $PORT or 3000)
 * Deploy as a Sevalla "Application": start command `node server.js`.
 */
"use strict";
const http = require("node:http");
const dns = require("node:dns").promises;
const net = require("node:net");

const PORT = parseInt(process.env.PORT || "3000", 10);
const MAX_BYTES = 6 * 1024 * 1024; // 6 MB per response
const FETCH_TIMEOUT_MS = 15000;

/* Block private / internal addresses (SSRF protection). */
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

async function safeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (!url.hostname) return null;
  try {
    const addrs = await dns.lookup(url.hostname, { all: true });
    if (addrs.length === 0 || addrs.some((a) => isPrivate(a.address))) return null;
  } catch {
    return null;
  }
  return url;
}

/* Rewrite an HTML page so it works through the proxy:
 *  - <a href> and <form action> go back through the proxy (keeps you inside)
 *  - <base> injected so relative images / CSS / scripts resolve correctly   */
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

  const u = reqUrl.searchParams.get("u");
  if (reqUrl.pathname === "/" && !u) {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("AshOS web proxy is running. Browse via /?u=<url>");
    return;
  }

  const target = await safeUrl(u || "");
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
      // NOTE: we deliberately do NOT forward x-frame-options /
      // content-security-policy — that is the whole point of the proxy.
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(out);
    } else {
      res.writeHead(200, { "content-type": ct });
      res.end(buf);
    }
  } catch (e) {
    res.writeHead(504, { "content-type": "text/plain" });
    res.end("Could not reach that site (timeout or connection failed).");
  }
});

server.listen(PORT, () => console.log("AshOS proxy listening on port " + PORT));

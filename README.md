# AshOS web proxy

Gives the AshOS **Browser** app real internet access. Many sites (Google, etc.)
send `X-Frame-Options` / `Content-Security-Policy` headers that forbid loading
inside an iframe — no client-side trick can bypass that, it's enforced by the
browser. This tiny server fetches pages itself and re-serves them *without*
those headers, so the AshOS browser can display them.

Zero dependencies, plain Node.js 18+.

## Deploy on Sevalla (as an Application)

1. Create a new GitHub repo, e.g. `ashos-proxy`, and upload `server.js` +
   `package.json` (Add file → Upload files, like you did for AshOS).
2. In Sevalla: **Home → Deploy an application** → connect the repo.
3. Build settings: turn OFF "Build site before publishing" (or leave the
   build command empty) — there is nothing to build.
4. **Start command:** `node server.js` (the server listens on `$PORT`,
   which Sevalla provides).
5. Deploy. You get a URL like `https://ashos-proxy-xxxx.sevalla.app`.
   Open it in your browser — you should see
   "AshOS web proxy is running."

## Connect it to AshOS

1. Open your AshOS site → **Settings → Network**.
2. Paste the proxy URL (e.g. `https://ashos-proxy-xxxx.sevalla.app`) into
   **Web proxy** and close Settings.
3. Open the **Browser** app — pages now load through the proxy.

## Notes

- This is an open relay: anyone with the URL can browse through it on your
  dime. Don't post the proxy URL publicly; the AshOS site URL is fine to share.
- Google may still misbehave through the proxy (it detects datacenter IPs
  and bot-like fetching). Most normal sites work fine.
- The proxy blocks private/internal addresses (SSRF protection) and caps
  responses at 6 MB.

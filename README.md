# AshOS proxy v2

Password-protected forward proxy + page-fetch mode. Two jobs:

1. **Real proxy for your devices** — put it in Chrome's or your phone's proxy
   settings (HTTP proxy with Basic auth). HTTPS sites tunnel through CONNECT,
   plain-HTTP sites are forwarded.
2. **Page-fetch mode for the AshOS Browser app** — `/?u=<url>&k=<key>`
   fetches a page server-side and re-serves it *without* the
   `X-Frame-Options` / `Content-Security-Policy` headers that forbid iframe
   embedding (no client-side trick can bypass those — they're enforced by
   the browser).

Zero dependencies, plain Node.js 18+.

## Setup

**Password:** the server reads it from the `PROXY_PASSWORD` env var and
**refuses to start without it**. Pick a strong one, never commit it to git.

**Sevalla (Application):**
1. Repo with `server.js` + `package.json` (this folder).
2. **Environment variables** → add `PROXY_PASSWORD` = your password.
3. Start command: `node server.js` (uses `$PORT`). Build: off.
4. Open the app URL — you should see "AshOS proxy v2 is running."

## Use it as your proxy

- **Chrome (PC):** Settings → System → Open proxy settings → Manual setup:
  address = your app host (e.g. `ashos-proxy-zgzb2.sevalla.app`), port `443`,
  as an **HTTPS** proxy. Username `ashborn`, password = your `PROXY_PASSWORD`.
  (Or use a SwitchyOmega-style extension — easier to toggle.)
- **Android:** the built-in Wi-Fi proxy settings don't support passwords —
  you need a proxy app that supports proxy authentication.
- **AshOS Browser:** Settings → Network → Web proxy = app URL,
  Proxy key = your password.

## Safety notes

- Never run it without the password — an open proxy gets abused within
  days and burns your bandwidth / risks the hosting account.
- Bandwidth: Sevalla charges $0.10/GB past the free 100 GB/month.
  Fine for browsing; don't stream through it.
- The proxy blocks private/internal target addresses and port 25 (SMTP),
  and caps responses at 6 MB.
- `PROXY_ALLOW_PRIVATE=1` disables the private-IP block — local testing
  only, never on a public server.

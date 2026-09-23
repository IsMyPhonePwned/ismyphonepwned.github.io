droid2web v0.3.24 (23 Sep 2026) — static website release

Contents are ready to deploy as-is (HTML + JS + CSS + WASM + rules).

Local preview:
  python3 -m http.server 8080 --directory .
  open http://localhost:8080/

Notes:
  - Serve over http(s); file:// will not load ES modules / workers reliably.
  - CDN assets (Prism, vis-network) are loaded from the network in index.html.
  - Bump the repo-root VERSION and DATE files before running scripts/build-release.sh.

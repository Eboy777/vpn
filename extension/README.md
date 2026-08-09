# Virgo VPN extension

Manifest V3 extension for current and previous stable Chrome/Yandex Browser releases.

## Local UI preview

Serve this directory over loopback and open one of the preview states:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory extension
```

```text
http://127.0.0.1:8765/popup.html?preview=onboarding
http://127.0.0.1:8765/popup.html?preview=pairing
http://127.0.0.1:8765/popup.html?preview=main
http://127.0.0.1:8765/popup.html?preview=tariffs
http://127.0.0.1:8765/popup.html?preview=locations
http://127.0.0.1:8765/popup.html?preview=settings
```

Preview mode contains no real tokens and does not change browser proxy settings.

## Unpacked extension

1. Replace both placeholder HTTPS origins in `src/config.js` with the two deployed API proxy
   origins. Never put the private FastAPI origin in this file.
2. Set `userAgreementUrl` and `supportUrl` when those pages are published. The agreement link is
   visible but intentionally inactive while `userAgreementUrl` is empty.
3. Load this `extension` directory as an unpacked extension.
4. Copy its stable extension ID to backend `ALLOWED_EXTENSION_ORIGINS_JSON` in the exact form
   `chrome-extension://<id>`.
5. Confirm that `/api/status` returns both configured API hostnames in the same order in
   `vpn.bypass_list`.

Chrome Web Store/Yandex release packages must use a stable store identity. A random unpacked ID is
only suitable for a local test profile.

## Checks

With Node.js installed:

```bash
npm --prefix extension test
```

The tests cover primary/fallback behavior, global `Retry-After`, HTTPS proxy configuration,
credential challenge matching, popup secret minimization, QR generation, and approved UI copy.

The real browser gate additionally requires two working API ingress domains and a real GOST HTTPS
proxy. A static preview cannot prove `CONNECT`, proxy authentication, automatic node failover, or
Yandex Browser compatibility.

# NPVT → V2Ray/Xray (Hardened GitHub Pages build)

Static, client-side NPVT1 / NPVTSUB1 decoder and config extractor.

## Publish on GitHub Pages
1. Upload `index.html` to the root of a GitHub repository.
2. Repository Settings → Pages.
3. Source: Deploy from a branch.
4. Branch: `main`, folder: `/ (root)`.

## Hardened behavior
- NPVT1 and NPVTSUB1 container handling.
- Full embedded V2Ray/Xray JSON discovery, including nested/alternate JSON field names.
- Structured NPV v4 reconstruction when `v2rayJson` is empty.
- Verified structured types: VLESS (`configType=5`) and Shadowsocks (`configType=3`).
- Explicitly named structured VMess/Trojan/SOCKS profiles are also handled.
- VLESS/VMess/Trojan/Shadowsocks share URI generation.
- TCP/RAW, WebSocket, HTTP, gRPC, HTTPUpgrade, XHTTP, mKCP; TLS and REALITY fields.
- WebSocket Host extraction from both `wsSettings.headers.Host` and legacy host fields.
- IPv6 URI formatting.
- Embedded share-link recovery.
- Unknown future layouts are preserved as raw decrypted JSON and marked unsupported instead of guessed.
- Downloadable diagnostics report for unsupported/new profile layouts.

Everything runs locally in the browser. Uploaded files are not sent to a server.

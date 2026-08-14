# NPVT → V2Ray/Xray Converter

Static browser-only GitHub Pages app for recovering authorized NPV Tunnel
`NPVT1` / `NPVTSUB1` configs and extracting embedded V2Ray/Xray profiles.

## Features

- Reads `.npvt`, `.npv`, or pasted NPVT text.
- Decrypts entirely in the browser.
- Extracts the embedded full V2Ray/Xray JSON.
- Generates import links for VLESS, VMess, Trojan, and Shadowsocks when the
  corresponding outbound has enough information.
- Supports multiple decrypted profiles where present.
- Copy/download buttons; no backend and no upload endpoint.

## Deploy on GitHub Pages

A self-contained one-file build is also provided separately as `npvt-converter-standalone.html`; rename it to `index.html` if you want a one-file repository.


1. Create a GitHub repository.
2. Put `index.html`, `style.css`, `app.js`, and `whitebox-data.js` in the repository root.
3. Push/commit the files to your default branch.
4. Open **Settings → Pages**.
5. Under **Build and deployment**, choose **Deploy from a branch**.
6. Select your branch (usually `main`) and `/ (root)`, then save.

GitHub Pages documentation:
https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site

## Local test

Because this app is plain static HTML, you can either open `index.html` directly
or run a tiny local HTTP server, for example:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000`.

## Attribution

The NPVT white-box decryption routine and lookup data are adapted from the
MIT-licensed project:

- ENIGMATIC-MAN/DECRYPTION_SCRIPTS
- NPVT script authors: HABIBI (`@HABIBI_1ST`) and NullptrO (`@NullptrO`)
- https://github.com/ENIGMATIC-MAN/DECRYPTION_SCRIPTS

Use only with configurations you are authorized to recover.

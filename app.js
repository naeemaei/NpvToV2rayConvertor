
"use strict";

const $ = (id) => document.getElementById(id);
const fileInput = $("fileInput");
const rawInput = $("rawInput");
const dropZone = $("dropZone");
const convertBtn = $("convertBtn");
const clearBtn = $("clearBtn");
const statusEl = $("status");
const resultsEl = $("results");
const cardsEl = $("cards");
const summaryEl = $("summary");

let currentDecrypted = null;
let currentLinks = [];

function setStatus(message, kind = "") {
  statusEl.textContent = message;
  statusEl.className = "status" + (kind ? ` ${kind}` : "");
}

function bytesFromBase64(value) {
  const cleaned = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = cleaned + "=".repeat((4 - (cleaned.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function utf8ToBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function base64Url(text) {
  return utf8ToBase64(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function whiteboxEncryptBlock(block) {
  const [p2, p3, p4, p5] = WHITEBOX_STATE;
  let state = Array.from(block);
  const perm = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

  for (let r = 0; r < 2; r++) {
    state = perm.map((idx) => state[idx]);
    if (r === 1) break;

    const midState = new Array(16).fill(0);
    for (let col = 0; col < 4; col++) {
      const t = [0,1,2,3].map((i) => p3[r][col * 4 + i][state[col * 4 + i]] >>> 0);
      for (let row = 0; row < 4; row++) {
        const idx = col * 24 + row * 6;
        const shHi = 28 - row * 8;
        const shLo = 24 - row * 8;

        const x1Hi = p2[r][idx][(t[0] >>> shHi) & 0xF][(t[1] >>> shHi) & 0xF];
        const x2Hi = p2[r][idx + 1][(t[2] >>> shHi) & 0xF][(t[3] >>> shHi) & 0xF];
        const hiVal = p2[r][idx + 4][x1Hi][x2Hi];

        const x1Lo = p2[r][idx + 2][(t[0] >>> shLo) & 0xF][(t[1] >>> shLo) & 0xF];
        const x2Lo = p2[r][idx + 3][(t[2] >>> shLo) & 0xF][(t[3] >>> shLo) & 0xF];
        const loVal = p2[r][idx + 5][x1Lo][x2Lo];

        midState[col * 4 + row] = ((hiVal << 4) | loVal) & 0xFF;
      }
    }

    const newState = new Array(16).fill(0);
    for (let col = 0; col < 4; col++) {
      const t = [0,1,2,3].map((i) => p5[r][col * 4 + i][midState[col * 4 + i]] >>> 0);
      for (let row = 0; row < 4; row++) {
        const idx = col * 24 + row * 6;
        const shHi = 28 - row * 8;
        const shLo = 24 - row * 8;

        const x1Hi = p2[r][idx][(t[0] >>> shHi) & 0xF][(t[1] >>> shHi) & 0xF];
        const x2Hi = p2[r][idx + 1][(t[2] >>> shHi) & 0xF][(t[3] >>> shHi) & 0xF];
        const hiVal = p2[r][idx + 4][x1Hi][x2Hi];

        const x1Lo = p2[r][idx + 2][(t[0] >>> shLo) & 0xF][(t[1] >>> shLo) & 0xF];
        const x2Lo = p2[r][idx + 3][(t[2] >>> shLo) & 0xF][(t[3] >>> shLo) & 0xF];
        const loVal = p2[r][idx + 5][x1Lo][x2Lo];

        newState[col * 4 + row] = ((hiVal << 4) | loVal) & 0xFF;
      }
    }
    state = newState;
  }

  for (let i = 0; i < 16; i++) state[i] = p4[i][state[i]];
  return Uint8Array.from(state);
}

function incrementCounter(iv) {
  for (let k = 15; k >= 0; k--) {
    iv[k] = (iv[k] + 1) & 0xFF;
    if (iv[k] !== 0) break;
  }
}

function decryptPayload(base64Payload) {
  const raw = bytesFromBase64(base64Payload);
  if (raw.length <= 16) throw new Error("Encrypted payload is too short.");

  const iv = raw.slice(0, 16);
  const ciphertext = raw.slice(16);
  const plaintext = new Uint8Array(ciphertext.length);

  let keystream = null;
  for (let j = 0; j < ciphertext.length; j++) {
    const offset = j % 16;
    if (offset === 0) {
      keystream = whiteboxEncryptBlock(iv);
      incrementCounter(iv);
    }
    plaintext[j] = ciphertext[j] ^ keystream[offset];
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(plaintext);
}

function decryptNpvt(rawText) {
  let text = rawText.replace(/^\uFEFF/, "").trim();
  let kind = "";

  if (text.startsWith("NPVTSUB1")) {
    kind = "NPVTSUB1";
    text = text.slice(8).trim();
  } else if (text.startsWith("NPVT1")) {
    kind = "NPVT1";
    text = text.slice(5).trim();
  } else {
    throw new Error("Unsupported file. Expected NPVT1 or NPVTSUB1 header.");
  }

  const payloads = text.split(",");
  if (payloads.length < 2 || !payloads[1].trim()) {
    throw new Error("NPVT payload field #2 was not found.");
  }

  const decryptedText = decryptPayload(payloads[1].trim());
  let parsed;
  try {
    parsed = JSON.parse(decryptedText);
  } catch {
    throw new Error("Decryption completed, but the plaintext is not valid JSON.");
  }

  return { kind, parsed, decryptedText };
}

function safeJsonParse(value) {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return null; }
}

function getProfiles(parsed) {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object") {
    // Some subscription wrappers may contain arrays under a property.
    for (const key of ["configs", "profiles", "items", "data"]) {
      if (Array.isArray(parsed[key])) return parsed[key];
    }
    return [parsed];
  }
  return [];
}

function streamQuery(stream = {}) {
  const q = new URLSearchParams();
  const network = stream.network || "tcp";
  const security = stream.security || "none";

  q.set("security", security);
  q.set("type", network);

  if (network === "ws") {
    const ws = stream.wsSettings || {};
    if (ws.host) q.set("host", ws.host);
    if (ws.path) q.set("path", ws.path);
  } else if (network === "grpc") {
    const grpc = stream.grpcSettings || {};
    if (grpc.serviceName) q.set("serviceName", grpc.serviceName);
    if (grpc.authority) q.set("authority", grpc.authority);
    if (grpc.multiMode) q.set("mode", "multi");
  } else if (network === "http" || network === "h2") {
    const h2 = stream.httpSettings || stream.httpupgradeSettings || {};
    if (Array.isArray(h2.host) && h2.host[0]) q.set("host", h2.host[0]);
    if (h2.path) q.set("path", h2.path);
  } else if (network === "tcp") {
    const tcp = stream.tcpSettings || {};
    if (tcp.header?.type && tcp.header.type !== "none") q.set("headerType", tcp.header.type);
  }

  if (security === "tls") {
    const tls = stream.tlsSettings || {};
    if (tls.serverName) q.set("sni", tls.serverName);
    if (tls.fingerprint) q.set("fp", tls.fingerprint);
    if (Array.isArray(tls.alpn) && tls.alpn.length) q.set("alpn", tls.alpn.join(","));
    if (tls.allowInsecure) q.set("allowInsecure", "1");
  } else if (security === "reality") {
    const reality = stream.realitySettings || {};
    if (reality.serverName) q.set("sni", reality.serverName);
    if (reality.fingerprint) q.set("fp", reality.fingerprint);
    if (reality.publicKey) q.set("pbk", reality.publicKey);
    if (reality.shortId) q.set("sid", reality.shortId);
    if (reality.spiderX) q.set("spx", reality.spiderX);
  }

  return q;
}

function encodeHash(text) {
  return encodeURIComponent(text || "NPVT config");
}

function vlessLink(outbound, name) {
  const vnext = outbound.settings?.vnext?.[0];
  const user = vnext?.users?.[0];
  if (!vnext || !user?.id) return null;

  const q = streamQuery(outbound.streamSettings || {});
  q.set("encryption", user.encryption || "none");
  if (user.flow) q.set("flow", user.flow);

  return `vless://${encodeURIComponent(user.id)}@${hostForUri(vnext.address)}:${vnext.port}?${q.toString()}#${encodeHash(name)}`;
}

function trojanLink(outbound, name) {
  const server = outbound.settings?.servers?.[0];
  if (!server?.address || !server?.port || !server?.password) return null;
  const q = streamQuery(outbound.streamSettings || {});
  return `trojan://${encodeURIComponent(server.password)}@${hostForUri(server.address)}:${server.port}?${q.toString()}#${encodeHash(name)}`;
}

function vmessLink(outbound, name) {
  const vnext = outbound.settings?.vnext?.[0];
  const user = vnext?.users?.[0];
  if (!vnext || !user?.id) return null;

  const s = outbound.streamSettings || {};
  const network = s.network || "tcp";
  const tls = s.tlsSettings || {};
  const ws = s.wsSettings || {};
  const grpc = s.grpcSettings || {};

  const legacy = {
    v: "2",
    ps: name || "NPVT VMess",
    add: String(vnext.address || ""),
    port: String(vnext.port || ""),
    id: String(user.id || ""),
    aid: String(user.alterId ?? 0),
    scy: String(user.security || "auto"),
    net: network,
    type: "none",
    host: network === "ws" ? (ws.host || "") : (network === "grpc" ? (grpc.authority || "") : ""),
    path: network === "ws" ? (ws.path || "") : (network === "grpc" ? (grpc.serviceName || "") : ""),
    tls: s.security === "tls" ? "tls" : "",
    sni: tls.serverName || "",
    alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : "",
    fp: tls.fingerprint || ""
  };

  return "vmess://" + utf8ToBase64(JSON.stringify(legacy));
}

function shadowsocksLink(outbound, name) {
  const server = outbound.settings?.servers?.[0];
  if (!server?.address || !server?.port || !server?.method || server.password == null) return null;
  const auth = base64Url(`${server.method}:${server.password}`);
  return `ss://${auth}@${hostForUri(server.address)}:${server.port}#${encodeHash(name)}`;
}

function hostForUri(host) {
  const value = String(host || "");
  return value.includes(":") && !value.startsWith("[") ? `[${value}]` : value;
}

function linkForOutbound(outbound, name) {
  const protocol = String(outbound?.protocol || "").toLowerCase();
  if (protocol === "vless") return vlessLink(outbound, name);
  if (protocol === "vmess") return vmessLink(outbound, name);
  if (protocol === "trojan") return trojanLink(outbound, name);
  if (protocol === "shadowsocks") return shadowsocksLink(outbound, name);
  return null;
}

function extractConfigs(parsed) {
  const profiles = getProfiles(parsed);
  const found = [];

  profiles.forEach((profile, profileIndex) => {
    const name = profile?.name || profile?.remarks || profile?.v2rayProfile?.remarks || `Profile ${profileIndex + 1}`;
    const candidates = [];

    if (profile?.v2rayProfile?.v2rayJson) candidates.push(profile.v2rayProfile.v2rayJson);
    if (profile?.v2rayJson) candidates.push(profile.v2rayJson);
    if (profile?.config && typeof profile.config === "object") candidates.push(profile.config);

    // A decrypted object can itself already be a V2Ray/Xray config.
    if (Array.isArray(profile?.outbounds)) candidates.push(profile);

    const unique = [];
    const seen = new Set();

    candidates.forEach((candidate) => {
      const config = safeJsonParse(candidate);
      if (!config || typeof config !== "object") return;
      const key = JSON.stringify(config);
      if (seen.has(key)) return;
      seen.add(key);
      unique.push(config);
    });

    unique.forEach((config, configIndex) => {
      const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
      const proxyOutbounds = outbounds.filter((o) =>
        ["vless", "vmess", "trojan", "shadowsocks"].includes(String(o?.protocol || "").toLowerCase())
      );

      if (!proxyOutbounds.length) {
        found.push({
          name,
          protocol: "json",
          link: null,
          json: config,
          profile
        });
        return;
      }

      proxyOutbounds.forEach((outbound, outboundIndex) => {
        const protocol = String(outbound.protocol).toLowerCase();
        const suffix = proxyOutbounds.length > 1 ? ` ${outboundIndex + 1}` : "";
        found.push({
          name: name + suffix,
          protocol,
          link: linkForOutbound(outbound, name + suffix),
          json: config,
          outbound,
          profile
        });
      });
    });
  });

  return found;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getServerMeta(item) {
  const o = item.outbound;
  if (!o) return "Full JSON profile";
  const p = item.protocol;
  if (p === "vless" || p === "vmess") {
    const v = o.settings?.vnext?.[0];
    return v ? `${v.address}:${v.port}` : "V2Ray outbound";
  }
  if (p === "trojan" || p === "shadowsocks") {
    const s = o.settings?.servers?.[0];
    return s ? `${s.address}:${s.port}` : "Proxy outbound";
  }
  return "V2Ray/Xray JSON";
}

function filenameSafe(name) {
  return String(name || "config")
    .normalize("NFKD")
    .replace(/[^\p{L}\p{N}._ -]+/gu, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80) || "config";
}

function downloadText(filename, text, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

function renderResults(decrypted, items) {
  currentDecrypted = decrypted.parsed;
  currentLinks = items.map((x) => x.link).filter(Boolean);

  summaryEl.textContent =
    `${decrypted.kind}: ${items.length} extracted config${items.length === 1 ? "" : "s"}, ` +
    `${currentLinks.length} import link${currentLinks.length === 1 ? "" : "s"}.`;

  cardsEl.innerHTML = items.map((item, i) => {
    const jsonText = JSON.stringify(item.json, null, 2);
    return `
      <article class="card">
        <div class="card-head">
          <div class="card-title">
            <h3 title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</h3>
            <div class="meta">${escapeHtml(getServerMeta(item))}</div>
          </div>
          <span class="proto">${escapeHtml(item.protocol)}</span>
        </div>

        ${item.link ? `
          <div class="field-label">Import link</div>
          <div class="codebox" id="link-${i}">${escapeHtml(item.link)}</div>
          <div class="inline-actions">
            <button class="secondary" data-copy-link="${i}">Copy link</button>
            <button class="secondary" data-download-link="${i}">Download link</button>
          </div>
        ` : `<div class="meta">No standard share URI could be generated; use the JSON below.</div>`}

        <details>
          <summary>Full V2Ray/Xray JSON</summary>
          <pre>${escapeHtml(jsonText)}</pre>
          <div class="inline-actions">
            <button class="secondary" data-copy-json="${i}">Copy JSON</button>
            <button class="secondary" data-download-json="${i}">Download JSON</button>
          </div>
        </details>
      </article>
    `;
  }).join("");

  cardsEl.querySelectorAll("[data-copy-link]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const item = items[Number(btn.dataset.copyLink)];
      await copyText(item.link);
      btn.textContent = "Copied";
      setTimeout(() => btn.textContent = "Copy link", 1000);
    });
  });

  cardsEl.querySelectorAll("[data-download-link]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = items[Number(btn.dataset.downloadLink)];
      downloadText(`${filenameSafe(item.name)}.${item.protocol}.txt`, item.link + "\n");
    });
  });

  cardsEl.querySelectorAll("[data-copy-json]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const item = items[Number(btn.dataset.copyJson)];
      await copyText(JSON.stringify(item.json, null, 2));
      btn.textContent = "Copied";
      setTimeout(() => btn.textContent = "Copy JSON", 1000);
    });
  });

  cardsEl.querySelectorAll("[data-download-json]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = items[Number(btn.dataset.downloadJson)];
      downloadText(
        `${filenameSafe(item.name)}.json`,
        JSON.stringify(item.json, null, 2) + "\n",
        "application/json;charset=utf-8"
      );
    });
  });

  $("copyAllBtn").disabled = currentLinks.length === 0;
  $("downloadAllBtn").disabled = currentLinks.length === 0;
  resultsEl.classList.remove("hidden");
}

async function convert() {
  setStatus("");
  resultsEl.classList.add("hidden");

  const raw = rawInput.value.trim();
  if (!raw) {
    setStatus("Choose a file or paste NPVT text first.", "error");
    return;
  }

  try {
    convertBtn.disabled = true;
    convertBtn.textContent = "Decrypting…";

    // Yield once so the UI can update before CPU work.
    await new Promise((resolve) => requestAnimationFrame(resolve));

    const decrypted = decryptNpvt(raw);
    const items = extractConfigs(decrypted.parsed);

    if (!items.length) {
      currentDecrypted = decrypted.parsed;
      currentLinks = [];
      renderResults(decrypted, [{
        name: "Decrypted NPVT data",
        protocol: "json",
        link: null,
        json: decrypted.parsed,
        profile: decrypted.parsed
      }]);
      setStatus("Decrypted successfully, but no embedded standard V2Ray/Xray outbound was found.", "ok");
    } else {
      renderResults(decrypted, items);
      setStatus("Decrypted successfully. Everything stayed in this browser tab.", "ok");
    }
  } catch (err) {
    console.error(err);
    setStatus(err?.message || "Could not decrypt this file.", "error");
  } finally {
    convertBtn.disabled = false;
    convertBtn.textContent = "Decrypt & Convert";
  }
}

fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  rawInput.value = await file.text();
  setStatus(`Loaded ${file.name} (${Math.ceil(file.size / 1024)} KB).`);
  convert();
});

["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropZone.classList.add("drag");
  });
});
["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag");
  });
});
dropZone.addEventListener("drop", async (e) => {
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  rawInput.value = await file.text();
  setStatus(`Loaded ${file.name} (${Math.ceil(file.size / 1024)} KB).`);
  convert();
});

convertBtn.addEventListener("click", convert);

clearBtn.addEventListener("click", () => {
  fileInput.value = "";
  rawInput.value = "";
  cardsEl.innerHTML = "";
  resultsEl.classList.add("hidden");
  currentDecrypted = null;
  currentLinks = [];
  setStatus("");
});

$("copyAllBtn").addEventListener("click", async () => {
  if (!currentLinks.length) return;
  await copyText(currentLinks.join("\n"));
  setStatus("All import links copied.", "ok");
});

$("downloadAllBtn").addEventListener("click", () => {
  if (!currentLinks.length) return;
  downloadText("npvt-v2ray-links.txt", currentLinks.join("\n") + "\n");
});

$("downloadDecryptedBtn").addEventListener("click", () => {
  if (currentDecrypted == null) return;
  downloadText(
    "decrypted-npvt.json",
    JSON.stringify(currentDecrypted, null, 2) + "\n",
    "application/json;charset=utf-8"
  );
});

import init, {
  requestAppleDevice,
  muxLockdownHandshake,
  lockdownQueryType,
  lockdownPair,
  prefetchPairHostKeys,
  lockdownFetchWithPlistXml,
  lockdownBattery,
  lockdownDiagnostics,
  lockdownCrashReports,
  lockdownSysdiagnoseList,
  lockdownSysdiagnoseDownload,
  lockdownSyslog,
  lockdownScreenshot,
  lockdownPcap,
} from "../pkg-idevice/idevice_wasm.js";

/* -----------------------------
 * Optional: dns-packet for proper DNS dissection (name compression, AAAA, CNAME chains, …).
 * Lazy-loaded from a CDN so the rest of the page works offline; on failure we fall back to a
 * lightweight inline DNS parser (qname only) which still surfaces the question name.
 * ----------------------------- */
let dnsPacketLib = null;
let dnsPacketLibLoading = null;
function ensureDnsPacketLib() {
  if (dnsPacketLib) return Promise.resolve(dnsPacketLib);
  if (dnsPacketLibLoading) return dnsPacketLibLoading;
  dnsPacketLibLoading = import("https://esm.sh/dns-packet@5.6.1?bundle")
    .then((m) => { dnsPacketLib = m.default || m; return dnsPacketLib; })
    .catch((e) => {
      console.warn("[idevice-wasm] dns-packet load failed, using fallback:", e);
      dnsPacketLib = { __fallback: true };
      return dnsPacketLib;
    });
  return dnsPacketLibLoading;
}
// Prefetch dns-packet when the user opens network capture (keeps page load snappy).

/* -----------------------------
 * State
 * ----------------------------- */
/** @type {USBDevice | null} */
let dev = null;
/** Full XML pair record currently in use (generated or loaded). */
let plistXmlText = null;
/** {name, data: Uint8Array}[] from the last crash report run. */
let lastFiles = [];
/** {path, name, sizeBytes}[] from the last sysdiagnose list. */
let lastSysdiagnoseEntries = [];
/** Currently running button (only one at a time). */
let busyBtn = null;

/* -----------------------------
 * DOM helpers
 * ----------------------------- */
const $ = (id) => document.getElementById(id);
const out = $("out");
const hasOut = !!out;
const filesArea = $("files-area");
const filesTable = $("files-table")?.querySelector("tbody") ?? null;
const sysdiagnoseArea = $("sysdiagnose-area");
const sysdiagnoseTable = $("sysdiagnose-table")?.querySelector("tbody") ?? null;

const verbose = () => !!$("verbose")?.checked;
const pairMode = () => /** @type {HTMLInputElement} */ (document.querySelector('input[name="pair"]:checked')).value;
const hostId = () => $("hostid")?.value.trim() || "";
const systemBuid = () => $("buid")?.value.trim() || "";
const tlsClientAuth = () => $("tls-client-auth")?.value || "host";
const tlsSni = () => $("tls-sni")?.value || "device";

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

function shortId(s) { return s ? s.slice(0, 8) + "…" : "—"; }

/* -----------------------------
 * Status bar
 * ----------------------------- */
function setStatus(id, state, value) {
  const node = $(id);
  if (!node) return;
  node.dataset.state = state; // off | ok | warn
  node.classList.toggle("ok", state === "ok");
  node.classList.toggle("warn", state === "warn");
  $(`${id}-val`).textContent = value;
}
function refreshStatus() {
  if (dev) {
    const name = dev.productName || "Apple device";
    const sn = dev.serialNumber ? ` · ${shortId(dev.serialNumber)}` : "";
    setStatus("st-device", "ok", name + sn);
  } else {
    setStatus("st-device", "off", "Not connected");
  }
  if (plistXmlText) {
    try {
      const d = readPlistRootDictStrings(plistXmlText);
      const h = d.HostID ? shortId(d.HostID) : "?";
      setStatus("st-pair", "ok", `Loaded · HostID ${h}`);
    } catch {
      setStatus("st-pair", "warn", "Loaded (parse error)");
    }
  } else {
    setStatus("st-pair", "off", "None");
  }
  refreshButtonStates();
}

/* -----------------------------
 * Output log (timestamped)
 * ----------------------------- */
function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
function logLine(level, text) {
  if (!hasOut || !out) { console.log("[idevice]", level, text); return; }
  const cls = { info: "info", ok: "ok", warn: "warn", err: "err", step: "step" }[level] || "info";
  out.insertAdjacentHTML(
    "beforeend",
    `<span class="ts">${nowStamp()}</span> <span class="${cls}">${escapeHtml(text)}</span>\n`
  );
  out.scrollTop = out.scrollHeight;
}
function logBlock(text) {
  if (!hasOut || !out) { console.log(text); return; }
  out.insertAdjacentHTML("beforeend", `${escapeHtml(text)}\n`);
  out.scrollTop = out.scrollHeight;
}
function setOutput(text) {
  if (out) out.textContent = text;
}

/* -----------------------------
 * Button busy state + prereq gating
 * ----------------------------- */
function refreshButtonStates() {
  for (const b of document.querySelectorAll(".btn[data-needs]")) {
    const needs = (b.getAttribute("data-needs") || "").split(",").filter(Boolean);
    let reason = "";
    if (needs.includes("dev") && !dev) reason = "Pick a device first.";
    else if (needs.includes("plist") && !plistXmlText)
      reason = "Load or generate a pair record first.";
    else if (needs.includes("auth")) {
      const m = pairMode();
      if (m === "plist" && !plistXmlText) reason = "Load a pair-record XML first, or pick Generate.";
    }
    b.disabled = !!reason || !!busyBtn;
    if (reason) b.title = reason;
  }
}
function setBusy(btn, msg) {
  busyBtn = btn;
  btn.dataset.running = "1";
  setStatus("st-job", "warn", msg || "Running…");
  refreshButtonStates();
}
function clearBusy(btn, ok = true, msg) {
  delete btn.dataset.running;
  busyBtn = null;
  setStatus("st-job", ok ? "ok" : "off", msg || (ok ? "Done" : "Failed"));
  refreshButtonStates();
}
async function runBusy(btn, label, fn) {
  if (busyBtn) return;
  busyBtn = btn;
  btn.dataset.running = "1";
  const work = fn();
  setStatus("st-job", "warn", label + "…");
  refreshButtonStates();
  logLine("step", `▶ ${label}`);
  try {
    await work;
    logLine("ok", `✓ ${label} done`);
    clearBusy(btn, true, `${label} ✓`);
  } catch (e) {
    logLine("err", `✗ ${label}: ${e}`);
    clearBusy(btn, false, `${label} ✗`);
  }
}

function maybePrefetchPairKeys() {
  if (!dev) return;
  const m = pairMode();
  if (m === "random" || m === "legacy") prefetchPairHostKeys();
}

/* -----------------------------
 * Pair record helpers
 * ----------------------------- */
function readPlistRootDictStrings(xmlText) {
  const d = new DOMParser().parseFromString(xmlText, "application/xml");
  if (d.querySelector("parsererror")) throw new Error("Invalid plist XML");
  const dict = d.querySelector("plist dict");
  if (!dict) throw new Error("No dict found in plist");
  /** @type {Record<string, string>} */
  const out = {};
  let pendingKey = null;
  for (const el of dict.children) {
    if (!(el instanceof Element)) continue;
    if (el.tagName === "key") pendingKey = (el.textContent ?? "").trim();
    else if (pendingKey !== null) {
      if (el.tagName === "string") out[pendingKey] = el.textContent ?? "";
      pendingKey = null;
    }
  }
  return out;
}
function setPlist(xml, sourceLabel, opts = {}) {
  plistXmlText = xml;
  try { localStorage.setItem("idevice-rs.pairRecordXml", xml); } catch {}
  try {
    const d = readPlistRootDictStrings(xml);
    if (d.HostID) $("hostid").value = d.HostID;
    if (d.SystemBUID) $("buid").value = d.SystemBUID;
    $("pair-summary-ids").innerHTML =
      `HostID = <strong>${escapeHtml(d.HostID || "?")}</strong><br>SystemBUID = ${escapeHtml(d.SystemBUID || "?")}`;
  } catch {
    $("pair-summary-ids").textContent = "(unparseable XML)";
  }
  $("pair-summary").hidden = false;
  if (!opts.quiet) {
    logLine("ok", `Pair record ${sourceLabel} (${(xml.length / 1024).toFixed(1)} KiB)`);
  }
  refreshStatus();
}
function clearPlist() {
  plistXmlText = null;
  try { localStorage.removeItem("idevice-rs.pairRecordXml"); } catch {}
  $("pair-summary").hidden = true;
  $("hostid").value = "";
  $("buid").value = "";
  const fn = $("plist-file-name");
  if (fn) fn.textContent = "No file chosen";
  logLine("info", "Pair record cleared");
  refreshStatus();
}
function downloadPlist() {
  if (!plistXmlText) return;
  const blob = new Blob([plistXmlText], { type: "application/xml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "pair-record.plist";
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  logLine("info", "pair-record.plist downloaded");
}
async function copyPlist() {
  if (!plistXmlText) return;
  try {
    await navigator.clipboard.writeText(plistXmlText);
    logLine("ok", "Pair record XML copied to clipboard");
  } catch (e) {
    logLine("err", "Clipboard write failed: " + e);
  }
}

/* -----------------------------
 * Device snapshot card
 * ----------------------------- */
/**
 * Parse the sectioned `format_lockdown_device_report` text into
 * `{ section: { label: value } }`. Both Diagnostics and Fetch-with-plist emit it.
 */
function parseDeviceReport(text) {
  const sections = {};
  let current = null;
  const lines = String(text).split(/\r?\n/);
  let pendingMultilineLabel = null;
  let pendingMultilineLines = [];
  const flushMultiline = () => {
    if (pendingMultilineLabel && current) {
      sections[current] = sections[current] || {};
      sections[current][pendingMultilineLabel] = pendingMultilineLines.join("\n").trim();
    }
    pendingMultilineLabel = null;
    pendingMultilineLines = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const next = lines[i + 1];
    if (next && /^-{3,}$/.test(next.trim()) && line.trim().length) {
      flushMultiline();
      current = line.trim();
      sections[current] = sections[current] || {};
      i++;
      continue;
    }
    if (!current) continue;
    // Sub-block multi-line capture (e.g. battery dict): "Label:" then indented lines.
    if (pendingMultilineLabel) {
      if (/^\s{2,}\S/.test(line)) {
        pendingMultilineLines.push(line.replace(/^\s+/, ""));
        continue;
      } else {
        flushMultiline();
      }
    }
    const scalar = line.match(/^\s{2}(\S.*?)\s*:\s*(.*)$/);
    if (scalar) {
      sections[current][scalar[1]] = scalar[2];
      continue;
    }
    const ml = line.match(/^([\w.\s/()]+):\s*$/);
    if (ml && !line.startsWith(" ")) {
      pendingMultilineLabel = ml[1].trim();
      pendingMultilineLines = [];
      continue;
    }
  }
  flushMultiline();
  return sections;
}

/** Render a section group with `{ label, val, [warn] }[]` rows. */
function renderGroup(title, rows) {
  const wrap = document.createElement("div");
  wrap.className = "group";
  const t = document.createElement("div");
  t.className = "gtitle";
  t.textContent = title;
  wrap.appendChild(t);
  for (const r of rows) {
    if (r.val === undefined || r.val === null || r.val === "") continue;
    const row = document.createElement("div");
    row.className = "row";
    const lbl = document.createElement("span");
    lbl.className = "lbl";
    lbl.textContent = r.label;
    const val = document.createElement("span");
    val.className = "val" + (r.warn ? " warn" : "") + (r.muted ? " muted" : "");
    val.textContent = r.val;
    row.appendChild(lbl);
    row.appendChild(val);
    wrap.appendChild(row);
    if (r.bar !== undefined) {
      const bw = document.createElement("div");
      bw.className = "bar-wrap";
      const b = document.createElement("div");
      b.className = "bar";
      b.style.width = `${Math.max(0, Math.min(100, r.bar))}%`;
      bw.appendChild(b);
      wrap.appendChild(bw);
    }
  }
  return wrap;
}

/** Parse a string from the report that looks like "256000000000  (~238.42 GiB)". */
function bytesAndPretty(v) {
  if (!v) return null;
  const m = String(v).match(/^(\d+)/);
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  return { bytes: n, pretty: fmtBytes(n) };
}

/** Pull a single key from a dict-style multi-line value (e.g. battery block). */
function pickFromBlock(block, key) {
  if (!block) return undefined;
  for (const line of String(block).split(/\r?\n/)) {
    const m = line.match(/^([\w.]+)\s*:\s*(.+?)\s*$/);
    if (m && m[1] === key) return m[2];
  }
  return undefined;
}

/**
 * Build a structured "Device snapshot" view from the diagnostics text and show it
 * above the Output log. Hidden when no parseable data is present.
 */
function renderDeviceCard(reportText) {
  const cardSec = $("device-card-section");
  const grid = $("device-card-grid");
  const meta = $("device-card-meta");
  grid.innerHTML = "";

  const parsed = parseDeviceReport(reportText);
  const id = parsed["Identity"] || {};
  const net = parsed["Network / cellular"] || {};
  const loc = parsed["Locale / time"] || {};
  const act = parsed["Activation / security"] || {};
  const storeS = parsed["Storage (disk_usage)"] || {};
  const batBlock = (parsed["Battery (com.apple.mobile.battery)"] || {})["Mobile.battery"];

  // No useful keys at all → keep the card hidden.
  const haveAny =
    Object.keys(id).length || Object.keys(net).length || Object.keys(act).length ||
    Object.keys(storeS).length || batBlock;
  if (!haveAny) {
    cardSec.hidden = true;
    return;
  }

  // --- Identity ---
  const marketing = id["MarketingName"];
  const product = id["ProductType"];
  const ver = id["ProductVersion"];
  const build = id["BuildVersion"];
  const headline =
    (marketing && marketing !== "Error: GetProhibited" ? marketing : product) +
    (ver ? ` · iOS ${ver}` : "") +
    (build ? ` (${build})` : "");
  meta.textContent = headline;

  grid.appendChild(renderGroup("Identity", [
    { label: "Name", val: id["DeviceName"] },
    { label: "Marketing", val: id["MarketingName"], muted: id["MarketingName"]?.startsWith("Error") },
    { label: "Model", val: id["ProductType"] },
    { label: "HW model", val: id["HardwareModel"] },
    { label: "Model #", val: id["ModelNumber"] },
    { label: "Region", val: id["RegionInfo"] },
    { label: "iOS", val: id["ProductVersion"] },
    { label: "Build", val: id["BuildVersion"] },
    { label: "Class", val: id["DeviceClass"] },
    { label: "CPU", val: id["CPUArchitecture"] },
    { label: "ChipID", val: id["ChipID"] },
    { label: "BoardId", val: id["BoardId"] },
  ]));

  grid.appendChild(renderGroup("Identifiers", [
    { label: "UDID", val: id["UniqueDeviceID"] },
    { label: "Serial", val: id["SerialNumber"] },
    { label: "WiFi MAC", val: net["WiFiAddress"] },
    { label: "Eth MAC", val: net["EthernetAddress"], muted: net["EthernetAddress"]?.startsWith("Error") },
    { label: "BT MAC", val: net["BluetoothAddress"] },
  ]));

  const imeiOk = net["InternationalMobileEquipmentIdentity"] && !net["InternationalMobileEquipmentIdentity"].startsWith("Error");
  grid.appendChild(renderGroup("Cellular", [
    { label: "IMEI", val: net["InternationalMobileEquipmentIdentity"], muted: !imeiOk },
    { label: "MEID", val: net["MobileEquipmentIdentifier"], muted: net["MobileEquipmentIdentifier"]?.startsWith("Error") },
    { label: "ICCID", val: net["IntegratedCircuitCardIdentity"], muted: net["IntegratedCircuitCardIdentity"]?.startsWith("Error") },
    { label: "IMSI", val: net["InternationalMobileSubscriberIdentity"], muted: net["InternationalMobileSubscriberIdentity"]?.startsWith("Error") },
    { label: "Phone", val: net["PhoneNumber"], muted: net["PhoneNumber"]?.startsWith("Error") },
  ]));

  grid.appendChild(renderGroup("Locale / time", [
    { label: "TimeZone", val: loc["TimeZone"] },
    { label: "Epoch", val: loc["TimeIntervalSince1970"] },
    { label: "Language", val: loc["Language"], muted: loc["Language"]?.startsWith("Error") },
    { label: "Locale", val: loc["Locale"], muted: loc["Locale"]?.startsWith("Error") },
  ]));

  const passProtected = String(act["PasswordProtected"] || "").toLowerCase() === "true";
  grid.appendChild(renderGroup("Activation / security", [
    { label: "ActivationState", val: act["ActivationState"], warn: act["ActivationState"] && act["ActivationState"] !== "Activated" },
    { label: "Acknowledged", val: act["ActivationStateAcknowledged"] },
    { label: "BrickState", val: act["BrickState"], warn: String(act["BrickState"] || "").toLowerCase() === "true" },
    { label: "DeveloperMode", val: act["DeveloperModeStatus"] },
    { label: "Passcode", val: passProtected ? "yes" : (act["PasswordProtected"] || ""), warn: !passProtected && act["PasswordProtected"] !== undefined },
    { label: "TrustedHost", val: act["TrustedHostAttached"] },
  ]));

  // Storage with usage bar.
  const storageRows = [];
  const total = bytesAndPretty(storeS["TotalDiskCapacity (disk_usage)"] || storeS["TotalDiskCapacity (mobile.disk_usage)"]);
  const sysCap = bytesAndPretty(storeS["TotalSystemCapacity"]);
  const dataCap = bytesAndPretty(storeS["TotalDataCapacity"]);
  const dataAvail = bytesAndPretty(storeS["TotalDataAvailable"] || storeS["AmountDataAvailable"]);
  if (total) storageRows.push({ label: "Total", val: total.pretty });
  if (sysCap) storageRows.push({ label: "System", val: sysCap.pretty });
  if (dataCap) storageRows.push({ label: "Data", val: dataCap.pretty });
  if (dataAvail) storageRows.push({ label: "Free", val: dataAvail.pretty });
  if (dataCap && dataAvail) {
    const used = dataCap.bytes - dataAvail.bytes;
    const pct = (used / dataCap.bytes) * 100;
    storageRows.push({
      label: "Used",
      val: `${fmtBytes(Math.max(0, used))} (${pct.toFixed(1)}%)`,
      warn: pct > 90,
      bar: pct,
    });
  }
  if (storageRows.length) grid.appendChild(renderGroup("Storage", storageRows));

  // Battery block — pull headline keys.
  if (batBlock) {
    const cap = pickFromBlock(batBlock, "BatteryCurrentCapacity");
    const charging = (pickFromBlock(batBlock, "BatteryIsCharging") || pickFromBlock(batBlock, "IsCharging") || "").toLowerCase();
    const externalConn = (pickFromBlock(batBlock, "ExternalConnected") || "").toLowerCase();
    const fullyCharged = (pickFromBlock(batBlock, "FullyCharged") || "").toLowerCase();
    const hasBattery = (pickFromBlock(batBlock, "HasBattery") || "").toLowerCase();
    const rows = [];
    if (cap) rows.push({
      label: "Charge",
      val: `${cap}%`,
      bar: Number(cap),
      warn: Number(cap) < 20,
    });
    if (charging) rows.push({ label: "Charging", val: charging });
    if (externalConn) rows.push({ label: "Plugged", val: externalConn });
    if (fullyCharged) rows.push({ label: "Full", val: fullyCharged });
    if (hasBattery) rows.push({ label: "HasBattery", val: hasBattery });
    if (rows.length) grid.appendChild(renderGroup("Battery", rows));
  }

  cardSec.hidden = false;
}

/* -----------------------------
 * Crash reports — file table
 * ----------------------------- */
function renderFiles(items) {
  lastFiles = items || [];
  if (!filesTable) return;
  filesTable.innerHTML = "";
  if (!lastFiles.length) {
    if (filesArea) filesArea.hidden = true;
    return;
  }
  if (filesArea) filesArea.hidden = false;
  const total = lastFiles.reduce((a, f) => a + (f.data?.length || 0), 0);
  const totalRow = document.createElement("tr");
  totalRow.innerHTML = `<td colspan="3" style="color:var(--muted);">${lastFiles.length} file(s) · ${fmtBytes(total)}</td><td></td>`;
  filesTable.appendChild(totalRow);
  lastFiles.forEach((f, i) => {
    const tr = document.createElement("tr");
    const size = f.data?.length || 0;
    tr.innerHTML = `<td style="color:var(--muted)">${i + 1}</td><td class="name">${escapeHtml(f.name)}</td><td class="size">${fmtBytes(size)}</td><td class="actions"></td>`;
    const td = tr.querySelector("td.actions");
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost";
    btn.textContent = "Save";
    btn.addEventListener("click", () => downloadFile(f));
    td.appendChild(btn);
    filesTable.appendChild(tr);
  });
}
function downloadFile(f) {
  const name = (f.name || "file").replace(/\//g, "_");
  const type = /\.tar(\.gz)?$|-tar\.gz$|\.tgz$/i.test(name)
    ? "application/gzip"
    : "application/octet-stream";
  const blob = new Blob([f.data], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function downloadAllFiles() {
  lastFiles.forEach((f, i) => setTimeout(() => downloadFile(f), i * 80));
}

/* -----------------------------
 * Sysdiagnose — list + per-file download
 * ----------------------------- */
function renderSysdiagnoseList(entries, debugText) {
  lastSysdiagnoseEntries = entries || [];
  if (!sysdiagnoseTable) return;
  sysdiagnoseTable.innerHTML = "";
  const debugWrap = $("sysdiagnose-debug-wrap");
  const debugPre = $("sysdiagnose-debug");
  if (debugText) {
    debugWrap.hidden = false;
    debugPre.textContent = debugText;
  } else {
    debugWrap.hidden = true;
    debugPre.textContent = "";
  }
  if (!lastSysdiagnoseEntries.length) {
    sysdiagnoseArea.hidden = !debugText;
    if (debugText) {
      debugWrap.open = true;
      $("sysdiagnose-hint").textContent =
        "No finished archives matched — expand AFC list debug below to see what was on the device.";
    }
    return;
  }
  sysdiagnoseArea.hidden = false;
  const total = lastSysdiagnoseEntries.reduce((a, e) => a + (e.sizeBytes || 0), 0);
  $("sysdiagnose-hint").textContent =
    `${lastSysdiagnoseEntries.length} archive(s) on device · ${fmtBytes(total)} total (sizes from AFC metadata). Click Download to pull one file at a time.`;
  lastSysdiagnoseEntries.forEach((entry, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td style="color:var(--muted)">${i + 1}</td>` +
      `<td class="name">${escapeHtml(entry.name)}</td>` +
      `<td class="size">${fmtBytes(entry.sizeBytes || 0)}</td>` +
      `<td class="actions"></td>`;
    const td = tr.querySelector("td.actions");
    const btn = document.createElement("button");
    btn.className = "btn btn-ghost";
    btn.textContent = "Download";
    btn.addEventListener("click", () => downloadSysdiagnoseArchive(btn, entry));
    td.appendChild(btn);
    sysdiagnoseTable.appendChild(tr);
  });
  sysdiagnoseArea.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
async function downloadSysdiagnoseArchive(btn, entry) {
  if (busyBtn) return;
  const label = `Sysdiagnose · ${entry.name}`;
  setBusy(btn, label);
  logLine("step", `▶ ${label}`);
  try {
    const keep = $("sysdiagnose-keep").checked;
    const res = await lockdownSysdiagnoseDownload(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni(),
      entry.path,
      undefined
    );
    const data = res.data;
    const name = res.name || entry.name;
    downloadFile({ name, data });
    logLine("ok", `✓ Downloaded ${name} · ${fmtBytes(data.length)} · keep on device=${keep}`);
    clearBusy(btn, true, "Downloaded");
  } catch (e) {
    logLine("err", `✗ ${label}: ${e}`);
    clearBusy(btn, false, "Failed");
  }
}

/* -----------------------------
 * Pair-mode segmented control
 * ----------------------------- */
function refreshPairPanel() {
  const m = pairMode();
  $("pair-generate-panel").hidden = m === "plist";
  $("pair-load-panel").hidden = m !== "plist";
  maybePrefetchPairKeys();
  refreshButtonStates();
}

/* -----------------------------
 * Wire up controls
 * ----------------------------- */
for (const el of document.querySelectorAll('input[name="pair"]')) {
  el.addEventListener("change", refreshPairPanel);
}

$("btn-plist-browse")?.addEventListener("click", () => {
  $("plist-file")?.click();
});

$("plist-file")?.addEventListener("change", async (ev) => {
  const input = /** @type {HTMLInputElement} */ (ev.target);
  const file = input.files?.[0];
  if (!file) return;
  try {
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf);
    const magic = String.fromCharCode(...u8.slice(0, 6));
    if (magic === "bplist") {
      $("plist-status").textContent =
        "Binary plist — convert to XML first (e.g. `plutil -convert xml1 file.plist`).";
      return;
    }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(u8);
    const dict = readPlistRootDictStrings(text);
    if (!dict.HostID || !dict.SystemBUID) {
      $("plist-status").textContent =
        "Plist has no HostID / SystemBUID at the root dict (wrong file or nested structure).";
      return;
    }
    setPlist(text, `loaded from ${file.name}`);
    $("plist-status").textContent = `Loaded ${file.name} — HostID + SystemBUID filled.`;
    const fn = $("plist-file-name");
    if (fn) fn.textContent = file.name;
  } catch (e) {
    $("plist-status").textContent = String(e);
  }
});

$("btn-pair-copy")?.addEventListener("click", copyPlist);
$("btn-pair-download")?.addEventListener("click", downloadPlist);
$("btn-pair-clear")?.addEventListener("click", clearPlist);
$("btn-out-clear")?.addEventListener("click", () => { out.innerHTML = ""; });
$("btn-out-copy")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(out.textContent || "");
    logLine("ok", "Log copied to clipboard");
  } catch (e) {
    logLine("err", "Clipboard write failed: " + e);
  }
});
$("btn-files-clear")?.addEventListener("click", () => renderFiles([]));
$("btn-files-download-all")?.addEventListener("click", downloadAllFiles);

/* -----------------------------
 * Boot
 * ----------------------------- */
setOutput("");
/**
 * Surface a clear, actionable error when the page is loaded outside of a WebUSB-capable
 * environment (file://, Firefox/Safari, hardened policy…) instead of letting the user
 * find out via an opaque WASM crash on the first "Pick device" click.
 */
function diagnoseWebUsbAvailability() {
  try {
    if (typeof navigator === "undefined") return "no `navigator` global (running outside a browser?)";
    if (window.isSecureContext === false) {
      return "this page must be served from a secure context — use https:// or http://localhost. " +
        "file:// and plain http:// over LAN are blocked by the browser. " +
        "Run `bash scripts/serve.sh` (or `cd web && python3 -m http.server 8080`) and open http://localhost:8080.";
    }
    if (!navigator.usb || typeof navigator.usb.requestDevice !== "function") {
      const ua = (navigator.userAgent || "").toLowerCase();
      if (ua.includes("firefox")) {
        return "Firefox does not implement WebUSB. Open this page in Chrome / Edge / Brave / Arc / Opera.";
      }
      if (ua.includes("safari") && !ua.includes("chrome") && !ua.includes("chromium")) {
        return "Safari does not implement WebUSB. Open this page in Chrome / Edge / Brave / Arc / Opera.";
      }
      return "`navigator.usb` is missing — likely an enterprise USB policy or extension is blocking it. " +
        "Try a fresh user profile and `chrome://flags`.";
    }
    return null;
  } catch (e) {
    return `WebUSB preflight crashed: ${e}`;
  }
}
const webUsbProblem = diagnoseWebUsbAvailability();
if (webUsbProblem) {
  const banner = document.createElement("div");
  banner.className = "pcap-banner danger";
  banner.style.margin = "0 0 0.85rem";
  banner.innerHTML =
    `<span class="b-title">WebUSB unavailable</span>` +
    `<span class="b-msg">${webUsbProblem.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</span>` +
    `<a class="btn btn-ghost" href="https://developer.mozilla.org/en-US/docs/Web/API/WebUSB_API" target="_blank" rel="noopener">Docs</a>`;
  const _ws = document.querySelector(".idevice-workspace");
  if (_ws) _ws.insertBefore(banner, _ws.firstChild);
  logLine("err", `WebUSB preflight: ${webUsbProblem}`);
  // Keep the rest of the page loadable for offline pcap inspection / pair-record parsing,
  // but disable every action that needs an actual device.
  for (const btn of document.querySelectorAll("button[data-needs]")) {
    btn.disabled = true;
    btn.title = "Disabled: WebUSB is not available in this browser/context.";
  }
  const pickBtn = document.getElementById("btn-pick");
  if (pickBtn) {
    pickBtn.disabled = true;
    pickBtn.title = "Disabled: WebUSB is not available in this browser/context.";
  }
}
logLine("info", "Loading WASM…");
try {
  await init();
  logLine("ok",
    webUsbProblem
      ? "WASM loaded — fix the WebUSB issue above to use device actions."
      : "WASM loaded — pick an Apple device to begin.");
} catch (e) {
  logLine("err", "WASM init failed (run ./scripts/build-wasm.sh): " + e);
}

try {
  const cached = localStorage.getItem("idevice-rs.pairRecordXml");
  if (cached && cached.includes("<plist")) {
    setPlist(cached, "restored from localStorage cache", { quiet: true });
  }
} catch {}

refreshPairPanel();
refreshStatus();

/* -----------------------------
 * Actions
 * ----------------------------- */
$("btn-pick").addEventListener("click", async () => {
  try {
    dev = await requestAppleDevice();
    prefetchPairHostKeys();
    logLine("ok", `Device authorized: ${dev.productName || "?"} (${dev.serialNumber || "?"})`);
    setStatus("st-job", "off", "Idle");
  } catch (e) {
    logLine("err", "Pick device: " + e);
  }
  refreshStatus();
});

$("btn-mux").addEventListener("click", (ev) =>
  runBusy(ev.currentTarget, "Mux handshake", async () => {
    const r = await muxLockdownHandshake(dev, verbose());
    logBlock(r);
  })
);

$("btn-qt").addEventListener("click", (ev) =>
  runBusy(ev.currentTarget, "QueryType", async () => {
    const r = await lockdownQueryType(dev, verbose());
    logBlock(r);
  })
);

$("btn-pair").addEventListener("click", (ev) => {
  const m = pairMode();
  if (m !== "random" && m !== "legacy") {
    logLine("warn", "Switch to Generate · random or Generate · legacy first.");
    return;
  }
  if (busyBtn || !dev) return;
  const btn = ev.currentTarget;
  busyBtn = btn;
  btn.dataset.running = "1";
  const pairWork = lockdownPair(dev, m, verbose());
  setStatus("st-job", "warn", `Pair (${m})…`);
  refreshButtonStates();
  logLine("info", "Pair started — unlock the iPhone for the Trust prompt.");
  pairWork
    .then((xml) => {
      setPlist(xml, "generated and saved");
      queueMicrotask(() => downloadPlist());
      logLine("ok", "Pair record cached locally — actions below will reuse it without Trust.");
      clearBusy(btn, true, `Pair (${m}) ✓`);
    })
    .catch((e) => {
      logLine("err", `✗ Pair (${m}): ${e}`);
      clearBusy(btn, false, `Pair (${m}) ✗`);
    });
});

/** Same as runBusy but also drives the action card's state pill. */
async function runBusyCard(btn, cardId, label, fn) {
  if (busyBtn) return;
  setBusy(btn, label + "…");
  setCardState(cardId, "running", label + "…");
  logLine("step", `▶ ${label}`);
  try {
    await fn();
    logLine("ok", `✓ ${label} done`);
    clearBusy(btn, true, `${label} ✓`);
    setCardState(cardId, "ok", `${label} ✓`);
  } catch (e) {
    logLine("err", `✗ ${label}: ${e}`);
    clearBusy(btn, false, `${label} ✗`);
    setCardState(cardId, "err", "Failed");
  }
}

$("btn-bat").addEventListener("click", (ev) =>
  runBusyCard(ev.currentTarget, "card-lockdown", "Battery", async () => {
    const r = await lockdownBattery(
      dev, pairMode(), hostId(), systemBuid(), verbose(),
      plistXmlText ?? "", tlsClientAuth(), tlsSni()
    );
    logBlock(r);
  })
);

$("btn-diag").addEventListener("click", (ev) =>
  runBusyCard(ev.currentTarget, "card-lockdown", "Diagnostics", async () => {
    const r = await lockdownDiagnostics(
      dev, pairMode(), hostId(), systemBuid(), verbose(),
      plistXmlText ?? "", tlsClientAuth(), tlsSni()
    );
    logBlock(r);
    renderDeviceCard(r);
  })
);

$("btn-plist-fetch").addEventListener("click", (ev) =>
  runBusyCard(ev.currentTarget, "card-lockdown", "Fetch with plist", async () => {
    if (!plistXmlText) throw new Error("No pair record loaded");
    const r = await lockdownFetchWithPlistXml(
      dev, plistXmlText, verbose(), tlsClientAuth(), tlsSni()
    );
    logBlock(r);
    renderDeviceCard(r);
  })
);

/* -----------------------------
 * Screenshot capture (com.apple.mobile.screenshotr)
 * ----------------------------- */
let screenshotState = { url: null, blob: null, ext: "png", mime: "image/png" };

function screenshotReset() {
  if (screenshotState.url) {
    URL.revokeObjectURL(screenshotState.url);
    screenshotState.url = null;
  }
  screenshotState.blob = null;
  $("screenshot-img").removeAttribute("src");
  $("screenshot-area").hidden = true;
  $("btn-screenshot-save").disabled = true;
  $("btn-screenshot-clear").disabled = true;
  $("screenshot-status").textContent = "";
}

$("btn-screenshot-clear").addEventListener("click", () => {
  screenshotReset();
  logLine("info", "Screenshot cleared");
});

$("btn-screenshot-save").addEventListener("click", () => {
  if (!screenshotState.blob) return;
  const a = document.createElement("a");
  a.href = screenshotState.url;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.download = `screenshot-${stamp}.${screenshotState.ext}`;
  a.click();
  logLine("info", `${a.download} downloaded (${fmtBytes(screenshotState.blob.size)})`);
});

$("btn-screenshot").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  if (busyBtn) return;
  screenshotReset();
  $("screenshot-area").hidden = false;
  $("screenshot-status").textContent = "capturing…";
  setBusy(btn, "Screenshot…");
  setCardState("card-screenshot", "running", "Capturing");
  logLine("step", "▶ Take screenshot (com.apple.mobile.screenshotr)");
  try {
    const res = await lockdownScreenshot(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni()
    );
    if (!(res && res.data instanceof Uint8Array)) {
      throw new Error("screenshot: WASM returned no image data");
    }
    const blob = new Blob([res.data], { type: res.mime || "image/png" });
    const url = URL.createObjectURL(blob);
    screenshotState.url = url;
    screenshotState.blob = blob;
    screenshotState.ext = res.extension || "png";
    screenshotState.mime = res.mime || "image/png";
    $("screenshot-img").src = url;
    $("screenshot-status").textContent =
      `${fmtBytes(res.byteLength | 0)} · ${res.extension || "?"}`;
    $("btn-screenshot-save").disabled = false;
    $("btn-screenshot-clear").disabled = false;
    logLine("ok",
      `✓ Screenshot ${fmtBytes(res.byteLength | 0)} (${res.extension}/${res.mime})`);
    clearBusy(btn, true, `Screenshot ✓ (${res.extension})`);
    setCardState("card-screenshot", "ok", `${res.extension.toUpperCase()} · ${fmtBytes(res.byteLength | 0)}`);
  } catch (e) {
    $("screenshot-status").textContent = `error: ${e}`;
    logLine("err", `✗ Screenshot: ${e}`);
    clearBusy(btn, false, "Screenshot ✗");
    setCardState("card-screenshot", "err", "Failed");
  }
});

/* -----------------------------
 * Syslog live stream
 * ----------------------------- */
let syslogState = {
  running: false,
  stopRequested: false,
  bytes: 0,
  blob: null,        // Uint8Array from the WASM call after it returns
  lastFlushAt: 0,    // throttle DOM updates
  pendingHtml: "",
  filter: "",
  mirrorToLog: false,
  autoScroll: true,
};
function syslogReset() {
  $("syslog-out").innerHTML = "";
  $("syslog-area").hidden = true;
  $("syslog-status").textContent = "";
  $("btn-syslog-save").disabled = true;
  $("btn-syslog-clear").disabled = true;
  syslogState.bytes = 0;
  syslogState.blob = null;
  syslogState.pendingHtml = "";
}
function syslogFlushPending() {
  if (!syslogState.pendingHtml) return;
  const out = $("syslog-out");
  out.insertAdjacentHTML("beforeend", syslogState.pendingHtml);
  syslogState.pendingHtml = "";
  // Cap on-screen size so very long captures don't blow up the DOM.
  const MAX_NODES = 2000;
  while (out.childNodes.length > MAX_NODES) out.removeChild(out.firstChild);
  if (syslogState.autoScroll) out.scrollTop = out.scrollHeight;
}
function syslogHighlight(text, needle) {
  const escaped = escapeHtml(text);
  if (!needle) return escaped;
  const re = new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "ig");
  return escaped.replace(re, (m) => `<span class="hl">${m}</span>`);
}
function syslogStatusText(extra) {
  const dur = (((Date.now() - syslogState.startedAt) / 1000) || 0).toFixed(1);
  return `${fmtBytes(syslogState.bytes)} · ${dur}s${extra ? " · " + extra : ""}`;
}

$("btn-syslog-stop").addEventListener("click", () => {
  if (syslogState.running) {
    syslogState.stopRequested = true;
    $("btn-syslog-stop").disabled = true;
    $("syslog-status").textContent = syslogStatusText("stopping…");
  }
});
$("btn-syslog-clear").addEventListener("click", () => {
  if (syslogState.running) return;
  syslogReset();
  logLine("info", "Syslog buffer cleared");
});
$("btn-syslog-save").addEventListener("click", () => {
  if (!syslogState.blob || !syslogState.blob.length) return;
  const blob = new Blob([syslogState.blob], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.download = `syslog-${stamp}.log`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  logLine("info", `syslog-${stamp}.log downloaded (${fmtBytes(syslogState.blob.length)})`);
});

$("btn-syslog").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  if (busyBtn || syslogState.running) return;
  const filter = $("syslog-filter").value.trim();
  const mirror = $("syslog-mirror").checked;
  const tail = $("syslog-tail").checked;
  const maxDur = Math.max(0, parseInt($("syslog-max-duration").value || "0", 10) || 0);
  const maxBytes = Math.max(0, parseInt($("syslog-max-bytes").value || "0", 10) || 0);

  syslogReset();
  syslogState.running = true;
  syslogState.stopRequested = false;
  syslogState.startedAt = Date.now();
  syslogState.filter = filter;
  syslogState.mirrorToLog = mirror;
  syslogState.autoScroll = tail;
  $("syslog-area").hidden = false;
  $("btn-syslog-stop").disabled = false;
  $("btn-syslog-clear").disabled = true;
  $("btn-syslog-save").disabled = true;
  setBusy(btn, "Syslog…");
  setCardState("card-syslog", "running", "Streaming");
  logLine("step", `▶ Stream syslog${filter ? ` (filter="${filter}")` : ""}${maxDur ? ` · ${maxDur}s` : ""}${maxBytes ? ` · ${fmtBytes(maxBytes)}` : ""}`);

  const onChunk = (text, totalBytes) => {
    syslogState.bytes = totalBytes;
    // Apply substring filter line-by-line. We split on `\n`; partial last line is held until
    // the next chunk by piggy-backing it onto the next call (the device emits whole lines
    // most of the time, so we can be lazy here).
    let display = text;
    if (filter) {
      display = text
        .split(/\n/)
        .filter((l) => l.toLowerCase().includes(filter.toLowerCase()))
        .join("\n");
      if (display && !display.endsWith("\n")) display += "\n";
    }
    if (display) {
      syslogState.pendingHtml += syslogHighlight(display, filter);
      const now = performance.now();
      if (now - syslogState.lastFlushAt > 100) {
        syslogState.lastFlushAt = now;
        syslogFlushPending();
      }
      if (syslogState.mirrorToLog) {
        for (const ln of display.split(/\n/)) {
          if (ln.length) logLine("info", ln);
        }
      }
    }
    $("syslog-status").textContent = syslogStatusText();
    return !syslogState.stopRequested;
  };

  try {
    const res = await lockdownSyslog(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni(),
      onChunk,
      maxBytes, maxDur * 1000
    );
    syslogFlushPending();
    if (res && res.data instanceof Uint8Array) {
      syslogState.blob = res.data;
      $("btn-syslog-save").disabled = false;
    }
    const reason = (res && res.stoppedReason) || "?";
    const sslLabel = res && res.ssl ? "TLS" : "cleartext";
    $("syslog-status").textContent = syslogStatusText(`stopped (${reason}, ${sslLabel})`);
    logLine("ok", `✓ Syslog stopped — ${reason} · ${fmtBytes(syslogState.bytes)} · ${sslLabel}`);
    clearBusy(btn, true, `Syslog ✓ (${reason})`);
    setCardState("card-syslog", "ok", `Stopped: ${reason}`);
  } catch (e) {
    syslogFlushPending();
    $("syslog-status").textContent = syslogStatusText(`error: ${e}`);
    logLine("err", `✗ Syslog: ${e}`);
    clearBusy(btn, false, "Syslog ✗");
    setCardState("card-syslog", "err", "Failed");
  } finally {
    syslogState.running = false;
    $("btn-syslog-stop").disabled = true;
    $("btn-syslog-clear").disabled = false;
  }
});

/* -----------------------------
 * Action card status pill helper. Each .action-card has a [data-state] attribute and a
 * span#card-<id>-pill that we update on idle/running/ok/err. Keeps the visual feedback
 * consistent across Lockdown queries / Screenshot / Syslog / Pcap / Crash reports.
 * ----------------------------- */
function setCardState(cardId, state, pillText) {
  const card = $(cardId);
  const pill = $(`${cardId}-pill`);
  if (!card || !pill) return;
  card.dataset.state = state;
  pill.textContent = pillText || ({
    idle: "Idle", running: "Running…", ok: "Ready", err: "Error",
  })[state] || state;
}

/* =====================================================================
 * Browser-side packet decoder for the pcap stream
 *
 * We re-parse the raw Ethernet frame the WASM layer hands us (after it
 * synthesised the fake Ethernet header for cellular `pdp_ip*` packets)
 * and surface a layered view: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP →
 * (DNS via `dns-packet`, TLS ClientHello SNI, HTTP request line).
 * Everything is pure JS so it runs without a backend.
 * ===================================================================== */
const ETHERTYPE_IPV4 = 0x0800, ETHERTYPE_IPV6 = 0x86dd, ETHERTYPE_ARP = 0x0806;
const IPPROTO_ICMP = 1, IPPROTO_TCP = 6, IPPROTO_UDP = 17, IPPROTO_ICMPV6 = 58;

function ipv4Str(b, off) {
  return `${b[off]}.${b[off + 1]}.${b[off + 2]}.${b[off + 3]}`;
}
function ipv6Str(b, off) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((b[off + i] << 8) | b[off + i + 1]).toString(16));
  }
  // Compress longest run of zero groups (RFC 5952 best-effort).
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) { curStart = i; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else {
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen >= 2) {
    const left = parts.slice(0, bestStart).join(":");
    const right = parts.slice(bestStart + bestLen).join(":");
    return `${left}::${right}`;
  }
  return parts.join(":");
}
function macStr(b, off) {
  return Array.from({ length: 6 }, (_, i) => b[off + i].toString(16).padStart(2, "0")).join(":");
}
function tcpFlags(byte) {
  const flags = [];
  if (byte & 0x01) flags.push("FIN");
  if (byte & 0x02) flags.push("SYN");
  if (byte & 0x04) flags.push("RST");
  if (byte & 0x08) flags.push("PSH");
  if (byte & 0x10) flags.push("ACK");
  if (byte & 0x20) flags.push("URG");
  if (byte & 0x40) flags.push("ECE");
  if (byte & 0x80) flags.push("CWR");
  return flags;
}
/** Parse one Ethernet frame and return a layered breakdown plus a top-level summary. */
function decodeEthernetFrame(bytes) {
  const layers = [];
  const summary = { proto: "OTHER", src: "", dst: "", info: "" };
  if (!bytes || bytes.length < 14) {
    return { layers: [], summary: { ...summary, info: "(short frame)" } };
  }
  const dst = macStr(bytes, 0), src = macStr(bytes, 6);
  const etype = (bytes[12] << 8) | bytes[13];
  layers.push({
    title: "Ethernet II",
    kv: {
      "Source MAC": src,
      "Destination MAC": dst,
      "EtherType": `0x${etype.toString(16).padStart(4, "0")} (${etypeName(etype)})`,
    },
  });

  let off = 14;
  if (etype === ETHERTYPE_IPV4) {
    return decodeIPv4(bytes, off, layers, summary);
  }
  if (etype === ETHERTYPE_IPV6) {
    return decodeIPv6(bytes, off, layers, summary);
  }
  if (etype === ETHERTYPE_ARP) {
    summary.proto = "ARP";
    summary.info = "ARP";
    layers.push({ title: "ARP", kv: { "Length": bytes.length - off } });
    return { layers, summary };
  }
  summary.proto = "OTHER";
  summary.info = `EtherType 0x${etype.toString(16).padStart(4, "0")}`;
  return { layers, summary };
}
function etypeName(t) {
  return ({
    [ETHERTYPE_IPV4]: "IPv4",
    [ETHERTYPE_IPV6]: "IPv6",
    [ETHERTYPE_ARP]: "ARP",
  })[t] || "?";
}
function decodeIPv4(bytes, off, layers, summary) {
  if (bytes.length - off < 20) {
    summary.info = "(short IPv4)";
    return { layers, summary };
  }
  const verIhl = bytes[off];
  const ihl = (verIhl & 0x0f) * 4;
  const dscp = bytes[off + 1];
  const totalLen = (bytes[off + 2] << 8) | bytes[off + 3];
  const ident = (bytes[off + 4] << 8) | bytes[off + 5];
  const flagsFrag = (bytes[off + 6] << 8) | bytes[off + 7];
  const ttl = bytes[off + 8];
  const proto = bytes[off + 9];
  const src = ipv4Str(bytes, off + 12);
  const dst = ipv4Str(bytes, off + 16);
  summary.src = src; summary.dst = dst;
  layers.push({
    title: "IPv4",
    kv: {
      "Version / IHL": `4 / ${ihl} bytes`,
      "DSCP / ECN": `0x${dscp.toString(16).padStart(2, "0")}`,
      "Total Length": `${totalLen} B`,
      "TTL": ttl,
      "Protocol": `${proto} (${ipProtoName(proto)})`,
      "Source": src,
      "Destination": dst,
      "Identification": `0x${ident.toString(16).padStart(4, "0")}`,
      "Flags / Fragment": `0x${flagsFrag.toString(16).padStart(4, "0")}`,
    },
  });
  const next = off + ihl;
  return decodeL4(bytes, next, proto, layers, summary, src, dst, /*ipv6*/ false);
}
function decodeIPv6(bytes, off, layers, summary) {
  if (bytes.length - off < 40) {
    summary.info = "(short IPv6)";
    return { layers, summary };
  }
  const verTcFl = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
  const payloadLen = (bytes[off + 4] << 8) | bytes[off + 5];
  const next = bytes[off + 6];
  const hopLimit = bytes[off + 7];
  const src = ipv6Str(bytes, off + 8);
  const dst = ipv6Str(bytes, off + 24);
  summary.src = src; summary.dst = dst;
  layers.push({
    title: "IPv6",
    kv: {
      "Version / TC / FlowLabel": `0x${verTcFl.toString(16).padStart(8, "0")}`,
      "Payload Length": `${payloadLen} B`,
      "Next Header": `${next} (${ipProtoName(next)})`,
      "Hop Limit": hopLimit,
      "Source": src,
      "Destination": dst,
    },
  });
  return decodeL4(bytes, off + 40, next, layers, summary, src, dst, /*ipv6*/ true);
}
function ipProtoName(p) {
  return ({
    [IPPROTO_ICMP]: "ICMP",
    [IPPROTO_TCP]: "TCP",
    [IPPROTO_UDP]: "UDP",
    [IPPROTO_ICMPV6]: "ICMPv6",
  })[p] || `proto=${p}`;
}
function decodeL4(bytes, off, proto, layers, summary, src, dst, isV6) {
  if (proto === IPPROTO_TCP) return decodeTCP(bytes, off, layers, summary, src, dst);
  if (proto === IPPROTO_UDP) return decodeUDP(bytes, off, layers, summary, src, dst);
  if (proto === IPPROTO_ICMP || proto === IPPROTO_ICMPV6) {
    const t = bytes[off], c = bytes[off + 1];
    layers.push({
      title: isV6 ? "ICMPv6" : "ICMP",
      kv: { "Type": t, "Code": c, "Length": bytes.length - off },
    });
    summary.proto = isV6 ? "ICMP6" : "ICMP";
    summary.info = `${summary.proto} type=${t} code=${c}`;
    return { layers, summary };
  }
  summary.proto = ipProtoName(proto);
  summary.info = `${src} → ${dst} (${ipProtoName(proto)})`;
  return { layers, summary };
}
function decodeTCP(bytes, off, layers, summary, src, dst) {
  if (bytes.length - off < 20) {
    summary.proto = "TCP"; summary.info = "(short TCP)";
    return { layers, summary };
  }
  const sport = (bytes[off] << 8) | bytes[off + 1];
  const dport = (bytes[off + 2] << 8) | bytes[off + 3];
  const seq = ((bytes[off + 4] << 24) | (bytes[off + 5] << 16) | (bytes[off + 6] << 8) | bytes[off + 7]) >>> 0;
  const ack = ((bytes[off + 8] << 24) | (bytes[off + 9] << 16) | (bytes[off + 10] << 8) | bytes[off + 11]) >>> 0;
  const dataOff = ((bytes[off + 12] >> 4) & 0x0f) * 4;
  const flags = tcpFlags(bytes[off + 13]);
  const win = (bytes[off + 14] << 8) | bytes[off + 15];
  summary.src = `${src}:${sport}`; summary.dst = `${dst}:${dport}`;
  summary.proto = "TCP";
  const payloadOff = off + dataOff;
  const payloadLen = Math.max(0, bytes.length - payloadOff);
  layers.push({
    title: "TCP",
    kv: {
      "Source Port": sport,
      "Destination Port": dport,
      "Flags": flags.length ? flags.join("|") : "(none)",
      "Sequence": seq,
      "Acknowledgement": ack,
      "Window": win,
      "Header Length": `${dataOff} B`,
      "Payload": `${payloadLen} B`,
    },
  });
  summary.info = `${flags.length ? flags.join(",") : "—"} seq=${seq} ack=${ack} win=${win} len=${payloadLen}`;
  // App-layer hints: TLS, HTTP.
  if (payloadLen > 0) {
    const payload = bytes.subarray(payloadOff, payloadOff + payloadLen);
    if (payload[0] === 0x16 /* TLS handshake */) {
      const sni = parseTlsSni(payload);
      if (sni) {
        summary.proto = "TLS";
        summary.info = `ClientHello SNI=${sni}` + (dport === 443 ? "" : ` (dport ${dport})`);
        layers.push({ title: "TLS", kv: { "Record": "Handshake (0x16)", "ClientHello SNI": sni } });
      } else if (dport === 443 || sport === 443) {
        summary.proto = "HTTPS";
        summary.info = `${flags.join(",") || "—"} TLS record (0x${payload[0].toString(16).padStart(2, "0")})`;
      }
    } else if (payload[0] === 0x17) {
      summary.proto = "TLS";
      summary.info = `Application Data (len=${payloadLen})`;
    } else {
      const httpHint = sniffHttpRequest(payload);
      if (httpHint) {
        summary.proto = "HTTP";
        summary.info = httpHint;
        layers.push({ title: "HTTP", kv: { "Request line": httpHint } });
      }
    }
  }
  return { layers, summary };
}
function decodeUDP(bytes, off, layers, summary, src, dst) {
  if (bytes.length - off < 8) {
    summary.proto = "UDP"; summary.info = "(short UDP)";
    return { layers, summary };
  }
  const sport = (bytes[off] << 8) | bytes[off + 1];
  const dport = (bytes[off + 2] << 8) | bytes[off + 3];
  const len = (bytes[off + 4] << 8) | bytes[off + 5];
  summary.src = `${src}:${sport}`; summary.dst = `${dst}:${dport}`;
  summary.proto = "UDP";
  summary.info = `len=${len}`;
  layers.push({
    title: "UDP",
    kv: { "Source Port": sport, "Destination Port": dport, "Length": `${len} B` },
  });
  const payload = bytes.subarray(off + 8);
  if (sport === 53 || dport === 53 || sport === 5353 || dport === 5353) {
    const dnsLayer = decodeDns(payload);
    if (dnsLayer) {
      summary.proto = "DNS";
      summary.info = dnsLayer.shortInfo;
      layers.push(dnsLayer.layer);
    }
  } else if (dport === 443 || sport === 443) {
    // QUIC carries TLS-1.3 ClientHello inside long-header packets; surface a hint.
    summary.proto = "QUIC?";
    summary.info = `UDP/443 len=${len} (likely QUIC)`;
  }
  return { layers, summary };
}
/** Tiny DNS dissector that uses dns-packet when available, falling back to qname-only. */
function decodeDns(payload) {
  try {
    if (dnsPacketLib && !dnsPacketLib.__fallback) {
      const decoded = dnsPacketLib.decode(payload);
      const q = (decoded.questions || []).map((qq) => `${qq.type} ${qq.name}`).join(", ");
      const a = (decoded.answers || []).map((aa) =>
        `${aa.type} ${aa.name}${aa.data ? "→" + (typeof aa.data === "string" ? aa.data : JSON.stringify(aa.data)) : ""}`
      ).join("; ");
      const id = decoded.id != null ? `0x${decoded.id.toString(16).padStart(4, "0")}` : "?";
      const opcode = decoded.opcode || "QUERY";
      const rcode = decoded.rcode || "NOERROR";
      const isResp = decoded.type === "response";
      const shortInfo = isResp
        ? `DNS resp ${rcode} ${a || q}`
        : `DNS query ${opcode} ${q}`;
      return {
        shortInfo,
        layer: {
          title: "DNS",
          kv: {
            "Transaction ID": id,
            "Type": decoded.type || "?",
            "Opcode": opcode,
            "RCode": rcode,
            "Questions": q || "(none)",
            "Answers": a || "(none)",
            "Authorities": (decoded.authorities || []).length,
            "Additionals": (decoded.additionals || []).length,
          },
        },
      };
    }
  } catch (e) {
    // Fall through to qname-only fallback.
  }
  return decodeDnsFallback(payload);
}
/** ~30-line DNS qname extractor (no answers, just first question). Used when dns-packet is unavailable. */
function decodeDnsFallback(payload) {
  if (payload.length < 12) return null;
  const id = (payload[0] << 8) | payload[1];
  const flags = (payload[2] << 8) | payload[3];
  const qd = (payload[4] << 8) | payload[5];
  let p = 12;
  const labels = [];
  let safety = 64;
  while (p < payload.length && safety--) {
    const len = payload[p];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      // Pointer — for simplicity in fallback, stop expansion here.
      labels.push("…");
      break;
    }
    if (p + 1 + len > payload.length) return null;
    labels.push(new TextDecoder("utf-8").decode(payload.subarray(p + 1, p + 1 + len)));
    p += 1 + len;
  }
  const qname = labels.join(".") || "(empty)";
  const isResp = (flags & 0x8000) !== 0;
  return {
    shortInfo: `DNS ${isResp ? "resp" : "query"} ${qname}` + (qd > 1 ? ` (+${qd - 1} more)` : ""),
    layer: {
      title: "DNS (fallback)",
      kv: {
        "Transaction ID": `0x${id.toString(16).padStart(4, "0")}`,
        "Flags": `0x${flags.toString(16).padStart(4, "0")}`,
        "Questions": qd,
        "First QName": qname,
      },
    },
  };
}
/** Pull the SNI string out of a TLS ClientHello record. Returns null if not a CH or SNI absent. */
function parseTlsSni(rec) {
  try {
    if (rec.length < 5 || rec[0] !== 0x16) return null;
    const recLen = (rec[3] << 8) | rec[4];
    if (rec.length < 5 + recLen) return null;
    const handshake = rec.subarray(5, 5 + recLen);
    if (handshake.length < 4 || handshake[0] !== 0x01 /* ClientHello */) return null;
    let p = 4 /* type+len(3) */ + 2 /* version */ + 32 /* random */;
    if (p > handshake.length) return null;
    const sidLen = handshake[p]; p += 1 + sidLen;
    if (p + 2 > handshake.length) return null;
    const csLen = (handshake[p] << 8) | handshake[p + 1]; p += 2 + csLen;
    if (p + 1 > handshake.length) return null;
    const cmLen = handshake[p]; p += 1 + cmLen;
    if (p + 2 > handshake.length) return null;
    const extLen = (handshake[p] << 8) | handshake[p + 1]; p += 2;
    const extEnd = Math.min(p + extLen, handshake.length);
    while (p + 4 <= extEnd) {
      const extType = (handshake[p] << 8) | handshake[p + 1];
      const extDataLen = (handshake[p + 2] << 8) | handshake[p + 3];
      const extData = handshake.subarray(p + 4, p + 4 + extDataLen);
      p += 4 + extDataLen;
      if (extType === 0x00 /* server_name */ && extData.length >= 5) {
        // server_name_list_length(2) | name_type(1) | host_name_length(2) | host_name(...)
        const nameType = extData[2];
        if (nameType === 0) {
          const hnLen = (extData[3] << 8) | extData[4];
          if (extData.length >= 5 + hnLen) {
            return new TextDecoder("utf-8").decode(extData.subarray(5, 5 + hnLen));
          }
        }
      }
    }
  } catch { /* swallow malformed TLS records */ }
  return null;
}
/** Detect a plain HTTP/1.x request line in the first ~64 bytes of a TCP payload. */
function sniffHttpRequest(payload) {
  const peek = payload.subarray(0, Math.min(payload.length, 256));
  let s = "";
  for (let i = 0; i < peek.length; i++) {
    const c = peek[i];
    if (c === 0x0d || c === 0x0a) break;
    if (c < 0x20 || c > 0x7e) return null;
    s += String.fromCharCode(c);
    if (s.length > 200) return null;
  }
  const m = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d/.exec(s);
  return m ? `${m[1]} ${m[2]}` : null;
}
/** Compact 16-bytes-per-line hex+ASCII dump suitable for the inspector. */
function hexDump(bytes, max = 256) {
  const slice = bytes.subarray(0, Math.min(bytes.length, max));
  const lines = [];
  for (let i = 0; i < slice.length; i += 16) {
    const row = slice.subarray(i, Math.min(slice.length, i + 16));
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const asc = Array.from(row, (b) => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".").join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48, " ")}  ${asc}`);
  }
  if (bytes.length > max) lines.push(`… (+${bytes.length - max} more bytes)`);
  return lines.join("\n");
}

/* ---------- pcap (com.apple.pcapd) --------------------------------
 *
 *   Architecture (as of the rAF rewrite)
 *   ────────────────────────────────────
 *   onPacket  ──► pcapState.allPackets[]            (lightweight record, no DOM)
 *                 pcapState.pendingPackets[]        (FIFO of un-rendered records)
 *                 ↳ schedules a single rAF to flushVisible(); returns immediately so the
 *                   WASM relay loop is never blocked by DOM work.
 *   flushVisible ─► builds <tr> elements in capped batches, appends to <tbody>, evicts
 *                   the oldest visible rows above PCAP_MAX_VISIBLE so layout cost stays
 *                   bounded no matter how long the capture runs.
 *   1Hz tick   ─► refreshes the summary chips so the user sees "alive" / "stalled"
 *                 without piling DOM work on every callback.
 *
 *   Why this matters
 *   ────────────────
 *   With the previous "render every packet inline" design, after a few thousand high-rate
 *   packets every callback paid a layout cost proportional to the table size, which
 *   eventually starved the message pump and the live pane *appeared* to stop. The relay
 *   loop is otherwise healthy (the CLI captured 3500+ pkts without hiccup in our run).
 */
/** Cap of <tr> pairs (row + detail) mounted at any time. */
const PCAP_MAX_VISIBLE   = 500;
/** Cap of un-rendered packets buffered between rAF flushes. Older are dropped from view. */
const PCAP_MAX_PENDING   = 4000;
/** Hard cap on the in-memory packet store (still doesn't affect the libpcap blob). */
const PCAP_MAX_KEPT      = 25000;
/** Max <tr>s emitted in a single rAF tick — keeps every frame snappy. */
const PCAP_RENDER_BUDGET = 80;

let pcapState = {
  running: false,
  stopRequested: false,
  packets: 0,
  blob: null,
  startedAt: 0,
  mirrorToLog: false,
  decode: true,
  protoCounts: {},
  filterProc: "",
  filterIface: "",
  allPackets: [],     // raw lightweight records (survive DOM eviction)
  pendingPackets: [], // not-yet-rendered, oldest first
  visiblePairs: [],   // {row, detail} <tr>s currently mounted, oldest first
  flushRaf: 0,        // requestAnimationFrame id (0 = idle)
  lastPacketAt: 0,    // wall-clock of last packet — drives the "stalled?" indicator
  quickFilter: "",    // user-typed substring filter (proto/flow/info/comm)
  autoTail: true,
  decodedOnly: false,
  statusTick: 0,
};
const pcapTbody = $("pcap-table").querySelector("tbody");
const pcapWrap  = $("pcap-table-wrap");

function pcapReset() {
  pcapTbody.innerHTML = "";
  $("pcap-status").textContent = "";
  $("pcap-empty").style.display = "";
  $("pcap-empty").textContent = "Waiting for the first packet…";
  $("pcap-banner").hidden = true;
  $("pcap-area").hidden = true;
  $("btn-pcap-save").disabled = true;
  $("btn-pcap-clear").disabled = true;
  pcapState.packets = 0;
  pcapState.blob = null;
  pcapState.protoCounts = {};
  pcapState.allPackets = [];
  pcapState.pendingPackets = [];
  pcapState.visiblePairs = [];
  pcapState.lastPacketAt = 0;
  if (pcapState.flushRaf) {
    cancelAnimationFrame(pcapState.flushRaf);
    pcapState.flushRaf = 0;
  }
  if (pcapState.statusTick) {
    clearInterval(pcapState.statusTick);
    pcapState.statusTick = 0;
  }
  pcapRenderSummary();
}

function pcapStatusText(extra) {
  const dur = (((Date.now() - pcapState.startedAt) / 1000) || 0).toFixed(1);
  const blobBytes = pcapState.blob ? pcapState.blob.length : 0;
  return `${pcapState.packets} pkts · ${fmtBytes(blobBytes)} · ${dur}s${extra ? " · " + extra : ""}`;
}

function escHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/** Returns true if `pkt` should appear in the live table given the current quick filter. */
function pcapPacketVisible(pkt) {
  if (pcapState.decodedOnly) {
    const p = (pkt.proto || "").toUpperCase();
    if (!/^(TCP|UDP|DNS|TLS|HTTPS|HTTP|ICMP|ICMP6|ARP|QUIC)$/.test(p)) return false;
  }
  const q = pcapState.quickFilter;
  if (!q) return true;
  const hay = `${pkt.proto} ${pkt.src} ${pkt.dst} ${pkt.info} ${pkt.comm} ${pkt.iface}`;
  return hay.toLowerCase().includes(q);
}

/** Schedule an idempotent rAF flush of the pending packet queue. */
function scheduleFlush() {
  if (pcapState.flushRaf) return;
  pcapState.flushRaf = requestAnimationFrame(flushVisible);
}

function flushVisible() {
  pcapState.flushRaf = 0;
  if (!pcapState.pendingPackets.length) return;
  // Drop excess pending so we never spend more than RENDER_BUDGET per frame even after a
  // long burst. Dropped packets are still in `allPackets[]` and the libpcap export.
  if (pcapState.pendingPackets.length > PCAP_MAX_PENDING) {
    const drop = pcapState.pendingPackets.length - PCAP_MAX_PENDING;
    pcapState.pendingPackets.splice(0, drop);
  }
  const budget = Math.min(pcapState.pendingPackets.length, PCAP_RENDER_BUDGET);
  const batch = pcapState.pendingPackets.splice(0, budget);

  const frag = document.createDocumentFragment();
  let appended = 0;
  for (const pkt of batch) {
    if (!pcapPacketVisible(pkt)) continue;
    const built = buildPacketRow(pkt);
    frag.appendChild(built.row);
    frag.appendChild(built.detail);
    pcapState.visiblePairs.push(built);
    appended++;
  }
  if (appended) {
    pcapTbody.appendChild(frag);
    $("pcap-empty").style.display = "none";
  }
  // FIFO evict oldest visible pairs in JS-array space, then a single batch DOM removal.
  if (pcapState.visiblePairs.length > PCAP_MAX_VISIBLE) {
    const drop = pcapState.visiblePairs.length - PCAP_MAX_VISIBLE;
    const evicted = pcapState.visiblePairs.splice(0, drop);
    for (const pair of evicted) {
      if (pair.row.parentNode === pcapTbody) pcapTbody.removeChild(pair.row);
      if (pair.detail.parentNode === pcapTbody) pcapTbody.removeChild(pair.detail);
    }
  }
  if (pcapState.autoTail && appended) pcapWrap.scrollTop = pcapWrap.scrollHeight;
  // Reschedule if there's still pending work.
  if (pcapState.pendingPackets.length) scheduleFlush();
}

function pcapRenderSummary() {
  const entries = Object.entries(pcapState.protoCounts).sort((a, b) => b[1] - a[1]);
  const root = $("pcap-summary");
  const dur = (((Date.now() - pcapState.startedAt) / 1000) || 0).toFixed(1);
  const sinceLast = pcapState.lastPacketAt
    ? `${((Date.now() - pcapState.lastPacketAt) / 1000).toFixed(1)}s ago`
    : "—";
  const bytes = pcapState.blob ? pcapState.blob.length : 0;
  const filt = pcapState.filterProc || pcapState.filterIface
    ? ` · filter ${pcapState.filterProc ? `proc=${escHtml(pcapState.filterProc)}` : ""}${pcapState.filterIface ? ` iface=${escHtml(pcapState.filterIface)}` : ""}`
    : "";
  const visible = pcapState.visiblePairs.length;
  const dropped = Math.max(0, pcapState.allPackets.length - visible);
  let stateClass;
  if (pcapState.running) {
    stateClass = (pcapState.lastPacketAt && (Date.now() - pcapState.lastPacketAt) > 5000)
      ? "stalled" : "running";
  } else {
    stateClass = pcapState.allPackets.length ? "ok" : "idle";
  }
  root.dataset.state = stateClass;
  root.innerHTML =
    `<span class="live-dot" aria-hidden="true"></span>` +
    `<span class="stat"><span class="lbl">pkts</span>${pcapState.packets}</span>` +
    `<span class="stat"><span class="lbl">pcap</span>${escHtml(fmtBytes(bytes))}</span>` +
    `<span class="stat"><span class="lbl">elapsed</span>${dur}s</span>` +
    `<span class="stat"><span class="lbl">last</span>${sinceLast}</span>` +
    `<span class="stat"><span class="lbl">visible</span>${visible}${dropped ? `<span class="lbl" style="margin-left:0.35rem">+${dropped} hidden</span>` : ""}</span>` +
    entries.slice(0, 8).map(([p, n]) =>
      `<span class="stat"><span class="lbl">${escHtml(p)}</span>${n}</span>`
    ).join("") +
    (filt ? `<span class="stat" style="border-color:transparent;background:transparent;color:var(--muted)">${filt}</span>` : "");
}

/** Re-apply the current quick / decoded-only filter to the kept packets — bounded by
 *  PCAP_MAX_VISIBLE so we don't blow up if someone clears the filter on a 25k-pkt capture. */
function pcapReapplyFilter() {
  pcapTbody.innerHTML = "";
  pcapState.visiblePairs = [];
  pcapState.pendingPackets = [];
  const start = Math.max(0, pcapState.allPackets.length - PCAP_MAX_VISIBLE * 4);
  pcapState.pendingPackets.push(...pcapState.allPackets.slice(start));
  $("pcap-empty").style.display = pcapState.pendingPackets.length ? "none" : "";
  scheduleFlush();
}

/**
 * Pretty-print the decoder's plain-text info string. Wraps the most "interesting" tokens —
 * hostnames (SNI / DNS qname), HTTP method + path, TCP flags, key=value pairs — in dedicated
 * highlight spans so the eye lands on them without having to expand the row.
 */
function highlightInfoHtml(info) {
  if (!info) return "";
  const e = escHtml(info);

  // HTTP request line: "GET /path", "POST /v1/foo", …
  let m = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)$/.exec(e);
  if (m) return `<span class="hl-method">${m[1]}</span><span class="hl-path">${m[2]}</span>`;

  // TLS ClientHello SNI=<host> (with optional trailer like " (dport 8443)")
  m = /^ClientHello\s+SNI=(\S+?)(\s.*)?$/.exec(e);
  if (m) {
    const trailer = m[2] ? `<span class="hl-key">${m[2]}</span>` : "";
    return `<span class="hl-tag">TLS Hello</span>SNI=<span class="hl-host">${m[1]}</span>${trailer}`;
  }
  m = /^Application Data \(len=(\d+)\)$/.exec(e);
  if (m) return `<span class="hl-tag">TLS App</span><span class="hl-key">len=</span><span class="hl-num">${m[1]}</span>`;

  // DNS query / response from dns-packet (or fallback): the question / answer name is the gold.
  m = /^DNS\s+(query|resp)\s+(.*)$/.exec(e);
  if (m) {
    const tag = m[1] === "query"
      ? `<span class="hl-tag q">DNS Q</span>`
      : `<span class="hl-tag r">DNS R</span>`;
    const rest = m[2]
      .replace(/\b(SERVFAIL|NXDOMAIN|REFUSED|FORMERR|NOTIMP)\b/g,
        '<span class="hl-rcode-bad">$1</span>')
      .replace(/\b(A|AAAA|CNAME|MX|TXT|PTR|NS|SOA|HTTPS|SRV)\s+([A-Za-z0-9_.-]+(?:\.[A-Za-z0-9_.-]+)+)/g,
        '<span class="hl-key">$1</span> <span class="hl-host">$2</span>')
      .replace(/(→)([0-9a-fA-F:.]+)/g,
        '<span class="hl-key">$1</span><span class="hl-num">$2</span>');
    return tag + rest;
  }

  // TCP: leading flag list (SYN,ACK / PSH,ACK / RST …) + seq/ack/win/len key=val pairs.
  m = /^([A-Z]{3}(?:,[A-Z]{3})*|—)\s+(.*)$/.exec(e);
  if (m && /\b(seq|ack)=/.test(m[2])) {
    const flags = m[1] === "—"
      ? `<span class="hl-flag">—</span>`
      : m[1].split(",")
        .map((f) => `<span class="hl-flag ${f}">${f}</span>`)
        .join('<span class="hl-key">,</span>');
    return flags + " " + highlightKvHtml(m[2]);
  }

  // ICMP, UDP `len=N`, generic `key=val` lists.
  return highlightKvHtml(e);
}
function highlightKvHtml(escapedStr) {
  return escapedStr.replace(
    /\b(seq|ack|win|len|type|code|opcode|rcode|sport|dport|payload|ihl|ttl|flags)=([^\s,]+)/g,
    '<span class="hl-key">$1=</span><span class="hl-num">$2</span>'
  );
}

/** Build the two <tr>s (row + detail pane) for a captured packet record. */
function buildPacketRow(pkt) {
  const evt = pkt.evt, frame = pkt.frame, decoded = pkt.decoded;
  const tr = document.createElement("tr");
  tr.className = "pcap-row";
  const tRel = ((pkt.t - pcapState.startedAt) / 1000).toFixed(2) + "s";
  const dirCls = (evt.direction === "in" || evt.direction === "out") ? evt.direction : "";
  const proto = pkt.proto || "OTHER";
  const protoCls = `proto-${/^[A-Z0-9]+$/.test(proto) ? proto : "other"}`;
  const flow = pkt.src
    ? `<span class="src">${escHtml(pkt.src)}</span><span class="arrow">→</span><span class="dst">${escHtml(pkt.dst)}</span>`
    : `<span class="src">${escHtml(evt.protocolFamily || "?")}</span>`;
  const infoHtml = decoded
    ? highlightInfoHtml(pkt.info || "")
    : "<span class=\"hl-key\">(decoder disabled)</span>";
  tr.innerHTML =
    `<td class="num col-num">${evt.index}</td>` +
    `<td class="col-t">${tRel}</td>` +
    `<td class="dir col-dir ${dirCls}">${escHtml(evt.direction || "?")}</td>` +
    `<td class="iface col-iface">${escHtml(evt.interface || "?")}</td>` +
    `<td class="col-proc">${escHtml(evt.comm || `pid=${evt.pid}`)}</td>` +
    `<td class="col-flow">${flow}</td>` +
    `<td class="col-proto"><span class="proto-tag ${protoCls}">${escHtml(proto)}</span></td>` +
    `<td class="num col-len">${evt.bytes}</td>` +
    `<td class="info col-info">${infoHtml}</td>`;

  const detail = document.createElement("tr");
  detail.className = "pcap-detail";
  const detailTd = document.createElement("td");
  detailTd.colSpan = 9;
  detail.appendChild(detailTd);

  tr.addEventListener("click", () => {
    const wasOpen = tr.classList.contains("expanded");
    // Close any other expanded row first (single-open inspector).
    for (const open of pcapTbody.querySelectorAll("tr.pcap-row.expanded")) {
      open.classList.remove("expanded");
    }
    if (!wasOpen) {
      tr.classList.add("expanded");
      if (!detailTd.firstChild) {
        detailTd.appendChild(renderPacketDetailPane(evt, frame, decoded));
      }
    }
  });

  return { row: tr, detail };
}

function renderPacketDetailPane(evt, frame, decoded) {
  const root = document.createElement("div");
  root.className = "pcap-detail-pane";

  const meta = document.createElement("div");
  meta.className = "pcap-layer";
  meta.innerHTML = `<div class="lt">Capture metadata</div>` +
    `<div class="kv">` +
      `<div class="k">Index</div><div class="v">${evt.index}</div>` +
      `<div class="k">Direction</div><div class="v">${escHtml(evt.direction || "?")}</div>` +
      `<div class="k">Interface</div><div class="v">${escHtml(evt.interface || "?")} (${escHtml(evt.interfaceType || "?")})</div>` +
      `<div class="k">Process</div><div class="v">${escHtml(evt.comm || "?")} (pid ${evt.pid})${evt.ecomm ? `, ecomm ${escHtml(evt.ecomm)}` : ""}</div>` +
      `<div class="k">Family</div><div class="v">${escHtml(evt.protocolFamily || "?")}</div>` +
      `<div class="k">Frame length</div><div class="v">${evt.bytes} B</div>` +
    `</div>`;
  root.appendChild(meta);

  const layers = (decoded && decoded.layers) || [];
  for (const l of layers) {
    const div = document.createElement("div");
    div.className = "pcap-layer";
    const kv = Object.entries(l.kv).map(
      ([k, v]) => `<div class="k">${escHtml(k)}</div><div class="v">${escHtml(String(v))}</div>`
    ).join("");
    div.innerHTML = `<div class="lt">${escHtml(l.title)}</div><div class="kv">${kv}</div>`;
    root.appendChild(div);
  }

  const hex = document.createElement("pre");
  hex.className = "pcap-hex";
  hex.textContent = hexDump(frame, 256);
  root.appendChild(hex);

  return root;
}

/** Inline banner that surfaces *why* a capture finished — explicit limit hit, user stop, or
 *  device-side close. Includes a one-click "Resume" so users don't have to scroll the form. */
function showPcapStopBanner(reason, bytes) {
  const banner = $("pcap-banner");
  const titleEl = $("pcap-banner-title");
  const msgEl   = $("pcap-banner-msg");
  const resume  = $("pcap-banner-resume");
  banner.classList.remove("warn", "danger");
  const human = ({
    "max-packets":   "Max packets reached.",
    "max-bytes":     `Max pcap bytes reached (${escHtml(fmtBytes(bytes || 0))}).`,
    "max-duration":  "Max duration reached.",
    "user-stop":     "Stopped on demand.",
    "stream-closed": "Device closed the relay.",
  })[reason] || `Stopped (${escHtml(reason)}).`;
  const showResume = (reason === "max-packets" || reason === "max-bytes" || reason === "max-duration");
  if (reason === "stream-closed") banner.classList.add("warn");
  titleEl.textContent = "Capture finished";
  msgEl.innerHTML =
    `${human} ${pcapState.packets} packets captured, ${escHtml(fmtBytes(bytes || 0))} of pcap. ` +
    (showResume
      ? `Bump the matching limit in <strong>Capture options</strong>, or click <strong>Resume</strong> to keep going with the same settings.`
      : ``);
  resume.hidden = !showResume;
  banner.hidden = false;
}
function showPcapErrorBanner(err) {
  const banner = $("pcap-banner");
  banner.classList.remove("warn");
  banner.classList.add("danger");
  $("pcap-banner-title").textContent = "Capture failed";
  $("pcap-banner-msg").textContent = err;
  $("pcap-banner-resume").hidden = false;
  banner.hidden = false;
}
$("pcap-banner-dismiss").addEventListener("click", () => { $("pcap-banner").hidden = true; });
$("pcap-banner-resume").addEventListener("click", () => {
  $("pcap-banner").hidden = true;
  $("btn-pcap").click();
});

$("btn-pcap-stop").addEventListener("click", () => {
  if (pcapState.running) {
    pcapState.stopRequested = true;
    $("btn-pcap-stop").disabled = true;
  }
});
$("btn-pcap-clear").addEventListener("click", () => {
  if (pcapState.running) return;
  pcapReset();
  setCardState("card-pcap", "idle");
});
/* Quick filter + live-tail toggles — operate purely on the rendered subset. */
$("pcap-quick-filter").addEventListener("input", (ev) => {
  pcapState.quickFilter = (ev.target.value || "").toLowerCase().trim();
  pcapReapplyFilter();
  pcapRenderSummary();
});
$("pcap-tail-btn").addEventListener("click", () => {
  pcapState.autoTail = !pcapState.autoTail;
  $("pcap-tail-btn").dataset.on = pcapState.autoTail ? "1" : "0";
  if (pcapState.autoTail) pcapWrap.scrollTop = pcapWrap.scrollHeight;
});
$("pcap-decoded-only").addEventListener("click", () => {
  pcapState.decodedOnly = !pcapState.decodedOnly;
  $("pcap-decoded-only").dataset.on = pcapState.decodedOnly ? "1" : "0";
  pcapReapplyFilter();
  pcapRenderSummary();
});
/* If the user scrolls up manually, auto-tail is paused so they can browse history calmly. */
pcapWrap.addEventListener("scroll", () => {
  const atBottom = pcapWrap.scrollTop + pcapWrap.clientHeight + 24 >= pcapWrap.scrollHeight;
  if (atBottom && !pcapState.autoTail) {
    pcapState.autoTail = true;
    $("pcap-tail-btn").dataset.on = "1";
  } else if (!atBottom && pcapState.autoTail) {
    pcapState.autoTail = false;
    $("pcap-tail-btn").dataset.on = "0";
  }
});
$("btn-pcap-save").addEventListener("click", () => {
  if (!pcapState.blob || !pcapState.blob.length) return;
  const blob = new Blob([pcapState.blob], { type: "application/vnd.tcpdump.pcap" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  a.download = `idevice-${stamp}.pcap`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  logLine("info", `${a.download} downloaded (${fmtBytes(pcapState.blob.length)})`);
});
$("btn-pcap").addEventListener("click", async (ev) => {
  const btn = ev.currentTarget;
  if (busyBtn || pcapState.running) return;
  ensureDnsPacketLib();
  const procFilter = $("pcap-filter-process").value.trim();
  const ifaceFilter = $("pcap-filter-iface").value.trim();
  const maxPkts = Math.max(0, parseInt($("pcap-max-packets").value || "0", 10) || 0);
  const maxDur = Math.max(0, parseInt($("pcap-max-duration").value || "0", 10) || 0);
  const maxBytes = Math.max(0, parseInt($("pcap-max-bytes").value || "0", 10) || 0);
  const mirror = $("pcap-mirror").checked;
  const decode = $("pcap-decode").checked;

  pcapReset();
  pcapState.running = true;
  pcapState.stopRequested = false;
  pcapState.startedAt = Date.now();
  pcapState.mirrorToLog = mirror;
  pcapState.decode = decode;
  pcapState.filterProc = procFilter;
  pcapState.filterIface = ifaceFilter;
  $("pcap-area").hidden = false;
  $("pcap-empty").textContent = "Waiting for the first packet…";
  $("btn-pcap-stop").disabled = false;
  $("btn-pcap-clear").disabled = true;
  $("btn-pcap-save").disabled = true;
  setBusy(btn, "Pcap…");
  setCardState("card-pcap", "running", "Capturing");
  // 1Hz heartbeat so the summary chips, "last packet", elapsed timer, and stalled-state
  // dot keep updating even when packet flow pauses.
  pcapState.statusTick = setInterval(() => {
    pcapRenderSummary();
    $("pcap-status").textContent = pcapStatusText();
  }, 1000);
  logLine("step",
    `▶ Capture network${procFilter ? ` (proc="${procFilter}")` : ""}${ifaceFilter ? ` (iface="${ifaceFilter}")` : ""}`
    + `${maxPkts ? ` · ${maxPkts} pkts` : ""}${maxDur ? ` · ${maxDur}s` : ""}${maxBytes ? ` · ${fmtBytes(maxBytes)}` : ""}`
    + ` · decode=${decode ? "on" : "off"}`);

  // The WASM layer hands us the **raw Ethernet frame** directly via `evt.frame` (same bytes
  // that end up in the final libpcap file). We do as little as possible per packet so the
  // WASM relay loop never blocks: store a lightweight record, schedule a rAF, return.
  const onPacket = (evt) => {
    try {
      pcapState.packets = evt.index;
      pcapState.lastPacketAt = Date.now();
      const frame = evt.frame instanceof Uint8Array ? evt.frame : null;
      let decoded = null, proto = "OTHER", src = "", dst = "", info = "";
      if (decode && frame && frame.length) {
        try {
          decoded = decodeEthernetFrame(frame);
          proto = decoded.summary.proto || "OTHER";
          src = decoded.summary.src; dst = decoded.summary.dst;
          info = decoded.summary.info;
        } catch (e) {
          proto = "ERR";
          info = `decode error: ${e}`;
          decoded = { layers: [], summary: { proto, src: "", dst: "", info } };
        }
      } else {
        info = evt.protocolFamily || "";
      }
      pcapState.protoCounts[proto] = (pcapState.protoCounts[proto] || 0) + 1;
      const pkt = { evt, frame, decoded, proto, src, dst, info,
        comm: evt.comm || "", iface: evt.interface || "", t: pcapState.lastPacketAt };
      pcapState.allPackets.push(pkt);
      if (pcapState.allPackets.length > PCAP_MAX_KEPT) {
        // Drop oldest in-memory packets to bound page memory. Doesn't affect the libpcap blob.
        pcapState.allPackets.splice(0, pcapState.allPackets.length - PCAP_MAX_KEPT);
      }
      pcapState.pendingPackets.push(pkt);
      scheduleFlush();
      if (pcapState.mirrorToLog) {
        const flow = src ? `${src} → ${dst}` : (evt.protocolFamily || "");
        logLine("info",
          `[pcap] #${evt.index} ${evt.direction || "?"} ${evt.interface || "?"} ${flow} `
          + `${proto} ${info} (${evt.bytes} B)`);
      }
    } catch (e) {
      // Swallow per-packet exceptions so a single bad row doesn't kill the relay loop —
      // the user can still see whatever's already been captured.
      console.warn("[pcap] onPacket exception:", e);
    }
    return !pcapState.stopRequested;
  };

  try {
    const res = await lockdownPcap(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni(),
      onPacket,
      procFilter, ifaceFilter,
      maxPkts, maxBytes, maxDur * 1000
    );
    if (res && res.data instanceof Uint8Array) {
      pcapState.blob = res.data;
      $("btn-pcap-save").disabled = false;
    }
    // Drain any leftover pending DOM work so the user sees the final tally immediately.
    while (pcapState.pendingPackets.length) flushVisible();
    pcapRenderSummary();
    const reason = (res && res.stoppedReason) || "?";
    const sslLabel = res && res.ssl ? "TLS" : "cleartext";
    $("pcap-status").textContent = pcapStatusText(`stopped (${reason}, ${sslLabel})`);
    logLine("ok", `✓ Pcap stopped — ${reason} · ${pcapState.packets} pkts · ${fmtBytes(res ? res.bytes : 0)} · ${sslLabel}`);
    clearBusy(btn, true, `Pcap ✓ (${reason})`);
    setCardState("card-pcap", "ok", `Stopped: ${reason}`);
    showPcapStopBanner(reason, res ? res.bytes : 0);
  } catch (e) {
    while (pcapState.pendingPackets.length) flushVisible();
    pcapRenderSummary();
    $("pcap-status").textContent = pcapStatusText(`error: ${e}`);
    logLine("err", `✗ Pcap: ${e}`);
    clearBusy(btn, false, "Pcap ✗");
    setCardState("card-pcap", "err", "Failed");
    showPcapErrorBanner(String(e));
  } finally {
    pcapState.running = false;
    if (pcapState.statusTick) {
      clearInterval(pcapState.statusTick);
      pcapState.statusTick = 0;
    }
    $("btn-pcap-stop").disabled = true;
    $("btn-pcap-clear").disabled = false;
    pcapRenderSummary();
  }
});

$("btn-crash").addEventListener("click", (ev) =>
  runBusyCard(ev.currentTarget, "card-crash", "Crash reports", async () => {
    const filter = $("crash-filter").value.trim();
    const keep = $("crash-keep").checked;
    const arr = await lockdownCrashReports(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni(),
      keep, filter, false
    );
    const items = Array.from(arr, (o) => ({ name: o.name, data: o.data }));
    renderFiles(items);
    const total = items.reduce((a, f) => a + f.data.length, 0);
    logLine("ok", `Copied ${items.length} file(s) · ${fmtBytes(total)} · filter="${filter}" keep=${keep}`);
    setCardState("card-crash", "ok", `${items.length} file(s) · ${fmtBytes(total)}`);
  })
);

$("btn-sysdiagnose-list").addEventListener("click", (ev) =>
  runBusyCard(ev.currentTarget, "card-sysdiagnose", "Sysdiagnose list", async () => {
    const res = await lockdownSysdiagnoseList(
      dev, pairMode(), hostId(), systemBuid(),
      plistXmlText ?? "", verbose(),
      tlsClientAuth(), tlsSni()
    );
    const items = Array.from(res.entries || [], (o) => ({
      path: o.path,
      name: o.name,
      sizeBytes: o.sizeBytes | 0,
    }));
    const debugText = res.debug || "";
    if (debugText) {
      logLine("step", "Sysdiagnose AFC listing:");
      logBlock(debugText);
    }
    renderSysdiagnoseList(items, debugText);
    const total = items.reduce((a, e) => a + e.sizeBytes, 0);
    if (items.length) {
      logLine("ok", `Found ${items.length} sysdiagnose archive(s) · ${fmtBytes(total)} on device`);
      setCardState("card-sysdiagnose", "ok", `${items.length} archive(s)`);
    } else {
      logLine("warn", "No finished sysdiagnose archives matched — see AFC list debug in the log / below the table.");
      setCardState("card-sysdiagnose", "idle", "None matched");
    }
  })
);

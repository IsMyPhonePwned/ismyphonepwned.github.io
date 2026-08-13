/**
 * droid2web — APK, DEX, AXML, ARSC inspector
 * Loads WASM, parses files, displays bytecode + source (DEX) and manifest/XML (APK/AXML/ARSC)
 */

import initWasm, { parse_file, parse_dex, parse_apk, parse_axml, parse_arsc, parse_arsc_resource_map, parse_arsc_resource_tables, get_apk_file_content, get_dex_method, decompile_dex_class, run_dex_emulator, run_dex_emulator_with_history, scan_vulns, scan_semgrep, scan_semgrep_xml, get_semgrep_builtin_rules, parse_semgrep_rules, taint_solve } from './pkg/droid2web.js';
import { createHexEditor } from './hex-editor.js';
import { APP_VERSION } from './version.js';

const LOG = '[droid2web]';
const APP_VERSION_LABEL = `v${APP_VERSION}`;
const PARSE_WORKER_TIMEOUT_MS = 120000;
/** Single-method decompile on huge DEXes (Facebook-scale) can take several minutes. */
const DECOMPILE_WORKER_TIMEOUT_MS = 300000;
/** Auto “all methods” decompile above this count freezes UX on large APKs — require explicit load. */
const ALL_METHODS_AUTO_LIMIT = 24;
/** Per-DEX security worker budget. Large APKs (Facebook) keep partial findings on timeout. */
const SECURITY_WORKER_TIMEOUT_MS = 90000;
/** Max DEX files to run vuln/Semgrep/MT on (prefer classes.dex, classes2…). */
const SECURITY_MAX_DEX_FILES = 4;
/** Skip individual DEX blobs larger than this for security scans (still openable in UI). */
const SECURITY_MAX_DEX_BYTES = 14 * 1024 * 1024;
const WASM_INIT_TIMEOUT_MS = 60000;

/** Lazy-created workers: parse/index/decompile stay responsive while security scans run. */
let parseWorker = null;
let parseWorkerReady = false;
let securityWorker = null;
let securityWorkerReady = false;
let wasmWorkerReqId = 0;
/** @type {Map<number, { reject: (err: Error) => void, cleanup: () => void }>} */
const pendingParseWorkerJobs = new Map();
/** In-flight / completed main-thread WASM init (for get_apk_file_content etc.). */
let wasmReady = false;
let wasmInitPromise = null;

/** Security-only ops — routed to a dedicated worker so indexing/browse aren't blocked. */
const SECURITY_WORKER_OPS = new Set([
  'scan_semgrep',
  'scan_semgrep_xml',
  'scan_vulns',
  'taint_solve',
  'get_semgrep_builtin_rules',
]);

function createNamedWorker(label) {
  const url = new URL('./parse-worker.js', import.meta.url);
  const worker = new Worker(url, { type: 'module' });
  worker.addEventListener('message', (e) => {
    if (e.data && e.data.type === 'ready') {
      if (label === 'parse') parseWorkerReady = true;
      else securityWorkerReady = true;
      debug(`[${label}Worker] ready`);
    }
  });
  worker.addEventListener('error', (err) => {
    warn(`[${label}Worker] error`, err);
    if (label === 'parse') parseWorkerReady = false;
    else securityWorkerReady = false;
  });
  return worker;
}

function getParseWorker() {
  if (parseWorker) return parseWorker;
  parseWorker = createNamedWorker('parse');
  return parseWorker;
}

function getSecurityWorker() {
  if (securityWorker) return securityWorker;
  securityWorker = createNamedWorker('security');
  return securityWorker;
}

function getWorkerForOp(op) {
  return SECURITY_WORKER_OPS.has(op) ? getSecurityWorker() : getParseWorker();
}

/** Decode worker result: transferable UTF-8 JSON buffer, JSON string, or structured object. */
function decodeWorkerRaw(raw, encoding) {
  if (encoding === 'utf8-json' || raw instanceof ArrayBuffer || ArrayBuffer.isView?.(raw)) {
    const u8 = raw instanceof Uint8Array
      ? raw
      : raw instanceof ArrayBuffer
        ? new Uint8Array(raw)
        : ArrayBuffer.isView(raw)
          ? new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)
          : null;
    if (u8) {
      const text = (typeof TextDecoder !== 'undefined')
        ? new TextDecoder('utf-8').decode(u8)
        : String.fromCharCode.apply(null, u8);
      return JSON.parse(text);
    }
  }
  if (typeof raw === 'string') return JSON.parse(raw);
  return raw;
}

/** Ensure main-thread WASM is loaded (timeout so a hung fetch cannot block forever). */
function ensureMainWasm() {
  if (wasmReady) return Promise.resolve();
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    debug('[wasm] main-thread init starting…');
    const t0 = performance.now();
    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('WASM init timed out after ' + (WASM_INIT_TIMEOUT_MS / 1000) + 's (check network / droid2web_bg.wasm)')), WASM_INIT_TIMEOUT_MS);
    });
    await Promise.race([initWasm(), timeout]);
    wasmReady = true;
    debug('[wasm] main-thread init done in', Math.round(performance.now() - t0) + 'ms');
  })().catch((err) => {
    wasmInitPromise = null;
    wasmReady = false;
    throw err;
  });
  return wasmInitPromise;
}

/**
 * Run a WASM op in the worker. Keeps the UI thread free during long Semgrep/vuln/MT scans.
 * Security ops use a dedicated worker so class indexing / browse stay unblocked.
 * @param {string} op
 * @param {object} payload
 * @param {{ timeoutMs?: number, transfer?: Transferable[] }} [opts]
 */
function runInParseWorker(op, payload = {}, opts = {}) {
  return new Promise((resolve, reject) => {
    const worker = getWorkerForOp(op);
    const id = ++wasmWorkerReqId;
    const timeoutMs = opts.timeoutMs ?? SECURITY_WORKER_TIMEOUT_MS;
    let settled = false;

    const cleanup = () => {
      clearTimeout(timeoutId);
      worker.removeEventListener('message', handler);
      pendingParseWorkerJobs.delete(id);
    };

    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn(value);
    };

    const timeoutId = setTimeout(() => {
      settle(reject, new Error(`${op} timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    const handler = (e) => {
      const d = e.data;
      if (!d || d.type === 'ready') return;
      if (d.id != null && d.id !== id) return;
      // Legacy parse_file responses have no id — accept when this is the only pending parse
      if (d.id == null && op !== 'parse_file') return;
      if (d.type === 'progress') {
        if (typeof opts.onProgress === 'function') {
          try { opts.onProgress(d); } catch (_) {}
        }
        return;
      }
      if (d.type === 'result') {
        try {
          settle(resolve, decodeWorkerRaw(d.raw, d.encoding));
        } catch (err) {
          settle(reject, err instanceof Error ? err : new Error(String(err)));
        }
      } else if (d.type === 'error') settle(reject, new Error(d.error || 'Worker error'));
    };
    worker.addEventListener('message', handler);
    pendingParseWorkerJobs.set(id, {
      reject: (err) => settle(reject, err),
      cleanup,
    });

    const msg = { ...payload, op, id };
    const transfer = opts.transfer || [];
    worker.postMessage(msg, transfer);
  });
}

/** Abort security worker jobs (Stop). Leaves parse/index worker running. */
function abortAllParseWorkerJobs(reason = 'Aborted') {
  const err = reason instanceof Error ? reason : new SecurityScanAbortError(String(reason));
  for (const [, job] of pendingParseWorkerJobs) {
    try { job.reject(err); } catch (_) {}
  }
  pendingParseWorkerJobs.clear();
  // Only kill the security worker so indexing / decompile can continue.
  if (securityWorker) {
    try { securityWorker.terminate(); } catch (_) {}
    securityWorker = null;
    securityWorkerReady = false;
  }
}

/** Run parse_file in worker; returns Promise<object> ({ok,data,error}) after transferable decode. */
function parseFileInWorker(bytes, filename) {
  const copy = bytes.slice();
  return runInParseWorker(
    'parse_file',
    { bytes: copy.buffer, filename },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Permission string-site scan in worker (keeps UI clickable on large multidex APKs). */
function findPermissionUsagesInWorker(bytes, permissions) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  const perms = Array.isArray(permissions) ? permissions.map(String) : [];
  return runInParseWorker(
    'find_permission_usages',
    { bytes: copy.buffer, permissions: perms },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Find const-string sites for one string pool index (worker). */
function findStringUsagesInWorker(bytes, stringIndex) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'find_string_usages',
    { bytes: copy.buffer, stringIndex: Number(stringIndex) >>> 0 },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Find invoke sites that call a method (worker). Indices match get_dex_method. */
function findMethodCallersInWorker(bytes, classIdx, methodIdx) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'find_method_callers',
    {
      bytes: copy.buffer,
      classIdx: Number(classIdx) >>> 0,
      methodIdx: Number(methodIdx) >>> 0,
    },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Methods invoked from a method (worker). */
function findMethodCalleesInWorker(bytes, classIdx, methodIdx) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'find_method_callees',
    {
      bytes: copy.buffer,
      classIdx: Number(classIdx) >>> 0,
      methodIdx: Number(methodIdx) >>> 0,
    },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Field get/put sites (worker). */
function findFieldXrefsInWorker(bytes, fieldIdx) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'find_field_xrefs',
    {
      bytes: copy.buffer,
      fieldIdx: Number(fieldIdx) >>> 0,
    },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/**
 * Options for worker decompile: JSON-cloneable, without multi-MB sibling DEXes.
 * (Cross-DEX inlining is best-effort; keeping the UI responsive matters more on large APKs.)
 */
function getDexMethodOptionsForWorker() {
  const opts = getDexMethodOptions();
  const out = { ...opts };
  delete out.extraDexes;
  if (out.resourceMap && typeof out.resourceMap === 'object') {
    const n = Object.keys(out.resourceMap).length;
    if (n > 8000) delete out.resourceMap;
  }
  return out;
}

/** Decompile one method off the main thread (keeps UI responsive on large DEXes). */
function getDexMethodInWorker(bytes, classIdx, methodIdx) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'get_dex_method',
    {
      bytes: copy.buffer,
      classIdx: Number(classIdx) >>> 0,
      methodIdx: Number(methodIdx) >>> 0,
      options: getDexMethodOptionsForWorker(),
    },
    { timeoutMs: DECOMPILE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Compact DEX class index in worker (names + method counts only — keeps UI responsive). */
function indexDexClassesInWorker(bytes) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'index_dex_classes',
    { bytes: copy.buffer },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Load string pool on demand after browse parse omitted it. */
function getDexStringsInWorker(bytes) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'get_dex_strings',
    { bytes: copy.buffer },
    { timeoutMs: PARSE_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}

/** Semgrep DEX scan in worker (does not freeze the UI). */
function scanSemgrepInWorker(bytes, rulesYaml, onProgress) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'scan_semgrep',
    { bytes: copy.buffer, rulesYaml: rulesYaml || null },
    { timeoutMs: SECURITY_WORKER_TIMEOUT_MS, transfer: [copy.buffer], onProgress }
  );
}

/** Semgrep XML scan in worker. */
function scanSemgrepXmlInWorker(xml, pathLabel, rulesYaml) {
  return runInParseWorker(
    'scan_semgrep_xml',
    { xml: String(xml || ''), pathLabel: String(pathLabel || 'xml'), rulesYaml: rulesYaml || null },
    { timeoutMs: SECURITY_WORKER_TIMEOUT_MS }
  );
}

/** Vulnerability detectors in worker. */
function scanVulnsInWorker(bytes, onProgress) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'scan_vulns',
    { bytes: copy.buffer },
    { timeoutMs: SECURITY_WORKER_TIMEOUT_MS, transfer: [copy.buffer], onProgress }
  );
}

/** MT taint solve in worker. */
function taintSolveInWorker(bytes) {
  const copy = bytes instanceof Uint8Array ? bytes.slice() : new Uint8Array(bytes).slice();
  return runInParseWorker(
    'taint_solve',
    { bytes: copy.buffer },
    { timeoutMs: SECURITY_WORKER_TIMEOUT_MS, transfer: [copy.buffer] }
  );
}
function debug(...args) { console.log(LOG, ...args); }
function warn(...args) { console.warn(LOG, ...args); }
function error(...args) { console.error(LOG, ...args); }

/** Returns a function that logs elapsed ms when called with a label (for timing steps). */
function timer() {
  const t0 = typeof performance !== 'undefined' ? performance.now() : Date.now();
  return (label) => {
    const elapsed = typeof performance !== 'undefined' ? (performance.now() - t0) : (Date.now() - t0);
    recordPerf(label, elapsed);
    return elapsed;
  };
}

/** Debug console (collapsed dock under Emulator) — perf timings + diagnostics. */
const DEBUG_LOG_MAX = 400;
const DEBUG_OPEN_KEY = 'droid2web-debug-open';
const debugLogLines = [];
let debugConsoleFlushTimer = 0;
let perfSessionT0 = 0;

function nowMs() {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function formatDebugTs(d = new Date()) {
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/** Append a line to the Debug dock console (also mirrors to browser console). */
function debugConsoleLog(level, message, ...extra) {
  const text = [message, ...extra.map((x) => {
    if (x == null) return '';
    if (typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean') return String(x);
    try { return JSON.stringify(x); } catch (_) { return String(x); }
  }).filter(Boolean)].join(' ');
  const line = {
    level: level || 'info',
    text,
    at: Date.now(),
  };
  debugLogLines.push(line);
  if (debugLogLines.length > DEBUG_LOG_MAX) {
    debugLogLines.splice(0, debugLogLines.length - DEBUG_LOG_MAX);
  }
  if (level === 'warn') warn(text);
  else if (level === 'error') error(text);
  else debug(text);
  scheduleDebugConsoleFlush();
  updateDebugConsoleMeta();
}

function recordPerf(name, ms, detail = '') {
  const msR = Math.round(Math.max(0, Number(ms) || 0));
  const detailBit = detail ? ` · ${detail}` : '';
  const slow = msR >= 250 ? (msR >= 1000 ? 'VERY_SLOW' : 'SLOW') : '';
  const tag = slow ? `[perf:${slow}]` : '[perf]';
  debugConsoleLog('perf', `${tag} ${msR}ms  ${name}${detailBit}`);
  return msR;
}

function clearDebugConsole() {
  debugLogLines.length = 0;
  perfSessionT0 = nowMs();
  const el = document.getElementById('debug-console');
  if (el) el.textContent = '';
  updateDebugConsoleMeta();
}

function startPerfSession(label = 'session') {
  clearDebugConsole();
  debugConsoleLog('info', `[session] ${label}`);
}

function measureSync(name, fn, detail = '') {
  const t0 = nowMs();
  try {
    return fn();
  } finally {
    recordPerf(name, nowMs() - t0, detail);
  }
}

async function measureAsync(name, fn, detail = '') {
  const t0 = nowMs();
  try {
    return await fn();
  } finally {
    recordPerf(name, nowMs() - t0, detail);
  }
}

function scheduleDebugConsoleFlush() {
  if (debugConsoleFlushTimer) return;
  debugConsoleFlushTimer = setTimeout(() => {
    debugConsoleFlushTimer = 0;
    flushDebugConsole();
  }, 60);
}

function flushDebugConsole() {
  const el = document.getElementById('debug-console');
  if (!el) return;
  const start = Math.max(0, debugLogLines.length - 200);
  let html = '';
  for (let i = start; i < debugLogLines.length; i++) {
    const line = debugLogLines[i];
    const cls = line.level === 'error' || line.level === 'warn' || line.level === 'perf'
      ? `debug-line debug-line-${line.level}`
      : 'debug-line';
    const slow = /\[perf:(VERY_)?SLOW\]/.test(line.text);
    html += `<div class="${cls}${slow ? ' is-slow' : ''}"><span class="debug-ts">${escapeHtml(formatDebugTs(new Date(line.at)))}</span> ${escapeHtml(line.text)}</div>`;
  }
  el.innerHTML = html || '<div class="muted debug-line">No debug output yet.</div>';
  const pane = document.getElementById('debug-console-area');
  if (pane?.dataset.collapsed !== 'true') {
    el.scrollTop = el.scrollHeight;
  }
}

function updateDebugConsoleMeta() {
  const meta = document.getElementById('debug-console-meta');
  if (!meta) return;
  if (!debugLogLines.length) {
    meta.textContent = '';
    return;
  }
  const last = debugLogLines[debugLogLines.length - 1];
  const short = String(last.text || '').replace(/^\[perf(?::[^\]]+)?\]\s*/, '');
  meta.textContent = `(${debugLogLines.length}) ${short.length > 48 ? short.slice(0, 45) + '…' : short}`;
}

function wireDebugConsoleUi() {
  const pane = document.getElementById('debug-console-area');
  const btn = document.getElementById('debug-collapse-btn');
  if (!pane || !btn) return;
  // Always start collapsed; remember only explicit open preference when expanding later.
  setDockCollapsed(pane, true, DEBUG_OPEN_KEY);
  btn.addEventListener('click', () => {
    const next = pane.dataset.collapsed !== 'true';
    setDockCollapsed(pane, next, DEBUG_OPEN_KEY);
    if (!next) {
      flushDebugConsole();
      const el = document.getElementById('debug-console');
      if (el) el.scrollTop = el.scrollHeight;
    }
  });
  document.getElementById('debug-clear-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    clearDebugConsole();
    flushDebugConsole();
  });
  document.getElementById('debug-copy-btn')?.addEventListener('click', async (e) => {
    e.stopPropagation();
    const text = debugLogLines.map((l) => `${formatDebugTs(new Date(l.at))}  ${l.text}`).join('\n');
    try {
      await navigator.clipboard.writeText(text || '(empty)');
    } catch (_) {}
  });
  flushDebugConsole();
}

debug(`main.js loaded (${APP_VERSION_LABEL})`);
{
  const verEl = document.getElementById('app-version');
  if (verEl) {
    verEl.textContent = APP_VERSION_LABEL;
    verEl.title = `droid2web ${APP_VERSION_LABEL}`;
  }
  try { document.title = `droid2web ${APP_VERSION_LABEL} — APK, DEX, AXML, ARSC Inspector`; } catch (_) {}
}
// Warm main-thread WASM in the background so the first APK/DEX open is not blocked on fetch.
ensureMainWasm()
  .then(() => {
    preloadSemgrepBuiltinRules();
    // Warm the worker WASM so the first Semgrep scan does not stall on init.
    try { getParseWorker(); } catch (_) {}
  })
  .catch((e) => warn('[wasm] background preload failed', e));

// Theme switcher — elfbrowser-aligned tokens + Nyan Cat flyby
const THEME_STORAGE_KEY = 'droid2web-theme';
const THEME_VALID = ['default', 'dark', 'light', 'unicorn', 'rainbow', 'nyan'];
const THEME_NAMES = {
  default: 'Default',
  dark: 'Dark',
  light: 'Light',
  unicorn: '🦄 Unicorn',
  rainbow: '🌈 Rainbow',
  nyan: '🐱 Nyan Cat',
};

/** Map legacy saved keys to current theme ids. */
function normalizeThemeId(id) {
  const m = {
    ida: 'default',
    'nyan-cat': 'nyan',
    ocean: 'default',
    forest: 'dark',
    sunset: 'dark',
    matrix: 'dark',
    dracula: 'dark',
    dp701: 'default',
    'vs-dark': 'default',
  };
  return m[id] || id;
}

function playNyanCatRun() {
  const container = document.getElementById('nyan-cat-container');
  if (!container) return;
  const run = container.querySelector('.nyan-cat-run');
  if (!run) return;
  run.style.animation = 'none';
  void run.offsetHeight;
  container.classList.add('nyan-cat-visible');
  container.setAttribute('aria-hidden', 'false');
  run.style.animation = '';
  clearTimeout(playNyanCatRun._hideTimer);
  playNyanCatRun._hideTimer = setTimeout(() => {
    container.classList.remove('nyan-cat-visible');
    container.setAttribute('aria-hidden', 'true');
  }, 4800);
}

function refreshThemeDependentViews() {
  try {
    const ctx = typeof getCodeViewContext === 'function' ? getCodeViewContext() : null;
    if (ctx && typeof codeViewMethodIdx !== 'undefined' && codeViewMethodIdx != null) {
      const method = ctx.classes?.[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
      if (method && typeof renderCfgGraph === 'function') renderCfgGraph(method);
    }
  } catch (_) {}
}

function getCurrentThemeId() {
  return document.documentElement.getAttribute('data-theme') || 'default';
}

function setTheme(id, options) {
  const opts = options || {};
  const theme = normalizeThemeId(id || 'default');
  const valid = THEME_VALID.includes(theme) ? theme : 'default';
  document.documentElement.setAttribute('data-theme', valid);
  try { localStorage.setItem(THEME_STORAGE_KEY, valid); } catch (_) {}
  document.querySelectorAll('.theme-option, .settings-theme-option').forEach((opt) => {
    opt.classList.toggle('active', opt.dataset.theme === valid);
  });
  const themeLabel = document.getElementById('theme-label');
  if (themeLabel) themeLabel.textContent = THEME_NAMES[valid] || 'Theme';
  if (valid === 'nyan' && opts.playNyan !== false) playNyanCatRun();
  if (!opts.skipRefresh) {
    // Defer so CSS variables are committed before CFG reads them.
    requestAnimationFrame(() => refreshThemeDependentViews());
  }
  if (typeof syncSettingsThemeUi === 'function' && !opts.skipSettingsSync) {
    syncSettingsThemeUi();
  }
}

(function initTheme() {
  const themeBtn = document.getElementById('theme-btn');
  const themeDropdown = document.getElementById('theme-dropdown');
  const themeOptions = document.querySelectorAll('.theme-option');

  let saved = null;
  try { saved = localStorage.getItem(THEME_STORAGE_KEY); } catch (_) {}
  // Prefer shared elfbrowser theme if droid2web has none yet
  if (!saved) {
    try {
      const binb = localStorage.getItem('binb-theme');
      if (THEME_VALID.includes(binb) || binb === 'ida') saved = binb;
    } catch (_) {}
  }
  const normalized = saved ? normalizeThemeId(saved) : 'default';
  setTheme(THEME_VALID.includes(normalized) ? normalized : 'default', {
    playNyan: false,
    skipRefresh: true,
    skipSettingsSync: true,
  });

  if (themeBtn && themeDropdown) {
    themeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = themeDropdown.classList.toggle('open');
      themeBtn.setAttribute('aria-expanded', open);
      themeDropdown.setAttribute('aria-hidden', !open);
    });
    themeDropdown.addEventListener('click', (e) => e.stopPropagation());
    themeOptions.forEach((opt) => {
      opt.addEventListener('click', () => {
        setTheme(opt.dataset.theme);
        themeDropdown.classList.remove('open');
        themeBtn.setAttribute('aria-expanded', 'false');
        themeDropdown.setAttribute('aria-hidden', 'true');
      });
    });
    document.addEventListener('click', () => {
      themeDropdown.classList.remove('open');
      themeBtn.setAttribute('aria-expanded', 'false');
      themeDropdown.setAttribute('aria-hidden', 'true');
    });
  }
})();

/* ===== UI Settings (theme + CSS token overrides) ===== */
const UI_SETTINGS_KEY = 'droid2web-ui-settings';
const UI_TOKEN_GROUPS = {
  layout: [
    { key: '--ui-font-size', label: 'UI font size', type: 'range', min: 11, max: 18, step: 1, unit: 'px', def: 14 },
    { key: '--code-font-size', label: 'Source font size', type: 'range', min: 0.7, max: 1.15, step: 0.01, unit: 'rem', def: 0.82 },
    { key: '--bytecode-font-size', label: 'Bytecode font size', type: 'range', min: 0.65, max: 1.1, step: 0.01, unit: 'rem', def: 0.8 },
    { key: '--radius', label: 'Corner radius', type: 'range', min: 0, max: 16, step: 1, unit: 'px', def: null },
  ],
  ui: [
    { key: '--bg', label: 'Background' },
    { key: '--surface', label: 'Surface' },
    { key: '--surface-2', label: 'Surface 2' },
    { key: '--border', label: 'Border' },
    { key: '--text', label: 'Text' },
    { key: '--text-muted', label: 'Muted text' },
    { key: '--accent', label: 'Accent' },
    { key: '--accent-hover', label: 'Accent hover' },
    { key: '--green', label: 'Green' },
    { key: '--red', label: 'Red' },
    { key: '--yellow', label: 'Yellow' },
    { key: '--orange', label: 'Orange' },
    { key: '--purple', label: 'Purple' },
  ],
  syn: [
    { key: '--syn-insn', label: 'Instruction' },
    { key: '--syn-reg', label: 'Register' },
    { key: '--syn-num', label: 'Number' },
    { key: '--syn-str', label: 'String' },
    { key: '--syn-char', label: 'Char' },
    { key: '--syn-cmt', label: 'Comment' },
    { key: '--syn-keyword', label: 'Keyword' },
    { key: '--syn-name', label: 'Name / function' },
    { key: '--syn-data', label: 'Data' },
    { key: '--syn-api-android', label: 'API android.*' },
    { key: '--syn-api-androidx', label: 'API androidx.*' },
    { key: '--syn-api-java', label: 'API java/javax.*' },
    { key: '--syn-api-r', label: 'R.id / resources' },
    { key: '--syn-xref', label: 'Xref' },
    { key: '--syn-punct', label: 'Punctuation' },
    { key: '--syn-error', label: 'Error' },
  ],
  cfg: [
    { key: '--cfg-edge-yes', label: 'True / yes' },
    { key: '--cfg-edge-no', label: 'False / no' },
    { key: '--cfg-edge-flow', label: 'Fallthrough' },
    { key: '--cfg-edge-back', label: 'Back edge' },
  ],
};

let uiSettings = { overrides: {} };

function loadUiSettings() {
  try {
    const raw = localStorage.getItem(UI_SETTINGS_KEY);
    if (!raw) return { overrides: {} };
    const parsed = JSON.parse(raw);
    const overrides = (parsed && typeof parsed.overrides === 'object' && parsed.overrides)
      ? parsed.overrides
      : {};
    const clean = {};
    for (const [k, v] of Object.entries(overrides)) {
      if (typeof k === 'string' && k.startsWith('--') && typeof v === 'string' && v.trim()) {
        clean[k] = v.trim();
      }
    }
    return { overrides: clean };
  } catch (_) {
    return { overrides: {} };
  }
}

function saveUiSettings() {
  try {
    localStorage.setItem(UI_SETTINGS_KEY, JSON.stringify({ overrides: uiSettings.overrides || {} }));
  } catch (_) {}
}

function allUiTokenKeys() {
  const keys = [];
  for (const group of Object.values(UI_TOKEN_GROUPS)) {
    for (const t of group) keys.push(t.key);
  }
  return keys;
}

function applyUiTokenOverrides() {
  const root = document.documentElement;
  const overrides = uiSettings.overrides || {};
  for (const key of allUiTokenKeys()) {
    if (Object.prototype.hasOwnProperty.call(overrides, key)) {
      root.style.setProperty(key, overrides[key]);
    } else {
      root.style.removeProperty(key);
    }
  }
}

function cssColorToHex(input) {
  if (!input) return '#000000';
  const s = String(input).trim();
  if (/^#[0-9a-fA-F]{6}$/.test(s)) return s.toLowerCase();
  if (/^#[0-9a-fA-F]{3}$/.test(s)) {
    return `#${s[1]}${s[1]}${s[2]}${s[2]}${s[3]}${s[3]}`.toLowerCase();
  }
  const m = s.match(/^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)/i);
  if (m) {
    const hex = (n) => Math.max(0, Math.min(255, Math.round(Number(n)))).toString(16).padStart(2, '0');
    return `#${hex(m[1])}${hex(m[2])}${hex(m[3])}`;
  }
  try {
    const probe = document.createElement('div');
    probe.style.color = s;
    document.body.appendChild(probe);
    const computed = getComputedStyle(probe).color;
    document.body.removeChild(probe);
    return cssColorToHex(computed);
  } catch (_) {
    return '#000000';
  }
}

function readCssToken(key) {
  return getComputedStyle(document.documentElement).getPropertyValue(key).trim();
}

function parseTokenNumber(raw, unit) {
  if (!raw) return null;
  const m = String(raw).trim().match(/^([\d.]+)/);
  if (!m) return null;
  let n = Number(m[1]);
  if (!Number.isFinite(n)) return null;
  if (unit === 'rem' && /px$/i.test(raw)) {
    const base = parseFloat(getComputedStyle(document.documentElement).fontSize) || 14;
    n = n / base;
  }
  return n;
}

function formatTokenValue(n, unit, step) {
  if (unit === 'px') return `${Math.round(n)}px`;
  const digits = String(step).includes('.') ? String(step).split('.')[1].length : 0;
  return `${Number(n).toFixed(digits)}${unit}`;
}

function setUiTokenOverride(key, value) {
  if (!uiSettings.overrides) uiSettings.overrides = {};
  if (!value) {
    delete uiSettings.overrides[key];
  } else {
    uiSettings.overrides[key] = value;
  }
  applyUiTokenOverrides();
  saveUiSettings();
}

function clearUiTokenOverrides() {
  uiSettings.overrides = {};
  applyUiTokenOverrides();
  saveUiSettings();
  requestAnimationFrame(() => {
    refreshSettingsControls();
    refreshThemeDependentViews();
  });
}

function syncSettingsThemeUi() {
  const theme = getCurrentThemeId();
  document.querySelectorAll('.settings-theme-option').forEach((opt) => {
    opt.classList.toggle('active', opt.dataset.theme === theme);
  });
}

function buildSettingsColorItem(token) {
  const item = document.createElement('div');
  item.className = 'settings-color-item';
  item.dataset.token = token.key;

  const swatch = document.createElement('input');
  swatch.type = 'color';
  swatch.className = 'settings-color-swatch';
  swatch.title = token.key;
  swatch.setAttribute('aria-label', token.label);

  const meta = document.createElement('div');
  meta.className = 'settings-color-meta';
  const nameEl = document.createElement('span');
  nameEl.className = 'settings-color-name';
  nameEl.textContent = token.label;
  const tokenEl = document.createElement('span');
  tokenEl.className = 'settings-color-token';
  tokenEl.textContent = token.key;
  meta.appendChild(nameEl);
  meta.appendChild(tokenEl);

  const reset = document.createElement('button');
  reset.type = 'button';
  reset.className = 'settings-color-reset';
  reset.textContent = '↺';
  reset.title = 'Reset to theme default';

  const sync = () => {
    const overridden = Object.prototype.hasOwnProperty.call(uiSettings.overrides || {}, token.key);
    item.classList.toggle('is-overridden', overridden);
    reset.disabled = !overridden;
    swatch.value = cssColorToHex(readCssToken(token.key));
  };

  swatch.addEventListener('input', () => {
    setUiTokenOverride(token.key, swatch.value);
    item.classList.add('is-overridden');
    reset.disabled = false;
    requestAnimationFrame(() => refreshThemeDependentViews());
  });
  reset.addEventListener('click', () => {
    setUiTokenOverride(token.key, null);
    sync();
    requestAnimationFrame(() => refreshThemeDependentViews());
  });

  item.appendChild(swatch);
  item.appendChild(meta);
  item.appendChild(reset);
  item._sync = sync;
  return item;
}

function buildSettingsLayoutRow(token) {
  const row = document.createElement('div');
  row.className = 'settings-row';
  row.dataset.token = token.key;

  const label = document.createElement('label');
  label.className = 'settings-row-label';
  label.textContent = token.label;

  const input = document.createElement('input');
  input.type = 'range';
  input.min = String(token.min);
  input.max = String(token.max);
  input.step = String(token.step);

  const valueEl = document.createElement('span');
  valueEl.className = 'settings-row-value';

  const sync = () => {
    const overridden = Object.prototype.hasOwnProperty.call(uiSettings.overrides || {}, token.key);
    row.classList.toggle('is-overridden', overridden);
    let n = parseTokenNumber(overridden ? uiSettings.overrides[token.key] : readCssToken(token.key), token.unit);
    if (n == null && token.def != null) n = token.def;
    if (n == null) n = token.min;
    n = Math.max(token.min, Math.min(token.max, n));
    input.value = String(n);
    valueEl.textContent = formatTokenValue(n, token.unit, token.step);
  };

  input.addEventListener('input', () => {
    const n = Number(input.value);
    const formatted = formatTokenValue(n, token.unit, token.step);
    valueEl.textContent = formatted;
    setUiTokenOverride(token.key, formatted);
    row.classList.add('is-overridden');
  });

  row.appendChild(label);
  row.appendChild(input);
  row.appendChild(valueEl);
  row._sync = sync;
  return row;
}

function refreshSettingsControls() {
  document.querySelectorAll('#settings-modal [data-token]').forEach((el) => {
    if (typeof el._sync === 'function') el._sync();
  });
  syncSettingsThemeUi();
}

function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (!modal) return;
  refreshSettingsControls();
  modal.hidden = false;
  modal.removeAttribute('inert');
  modal.setAttribute('aria-hidden', 'false');
  document.getElementById('settings-close')?.focus();
}

function closeSettingsModal() {
  const modal = document.getElementById('settings-modal');
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute('inert', '');
  modal.setAttribute('aria-hidden', 'true');
  document.getElementById('settings-btn')?.focus();
}

(function initUiSettings() {
  uiSettings = loadUiSettings();
  applyUiTokenOverrides();

  const layoutHost = document.getElementById('settings-layout-rows');
  const uiHost = document.getElementById('settings-ui-colors');
  const synHost = document.getElementById('settings-syn-colors');
  const cfgHost = document.getElementById('settings-cfg-colors');
  if (layoutHost) {
    UI_TOKEN_GROUPS.layout.forEach((t) => layoutHost.appendChild(buildSettingsLayoutRow(t)));
  }
  if (uiHost) UI_TOKEN_GROUPS.ui.forEach((t) => uiHost.appendChild(buildSettingsColorItem(t)));
  if (synHost) UI_TOKEN_GROUPS.syn.forEach((t) => synHost.appendChild(buildSettingsColorItem(t)));
  if (cfgHost) UI_TOKEN_GROUPS.cfg.forEach((t) => cfgHost.appendChild(buildSettingsColorItem(t)));

  document.getElementById('settings-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    openSettingsModal();
  });
  document.getElementById('settings-close')?.addEventListener('click', closeSettingsModal);
  document.getElementById('settings-done')?.addEventListener('click', closeSettingsModal);
  document.getElementById('settings-modal-backdrop')?.addEventListener('click', closeSettingsModal);
  document.getElementById('settings-reset')?.addEventListener('click', () => {
    clearUiTokenOverrides();
  });
  document.getElementById('settings-theme-grid')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.settings-theme-option');
    if (!btn) return;
    setTheme(btn.dataset.theme);
    // Re-sync color pickers to the new theme defaults for non-overridden tokens.
    requestAnimationFrame(() => refreshSettingsControls());
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const helpModal = document.getElementById('help-modal');
    if (helpModal && !helpModal.hidden) {
      e.preventDefault();
      closeHelpModal();
      return;
    }
    const modal = document.getElementById('settings-modal');
    if (modal && !modal.hidden) {
      e.preventDefault();
      closeSettingsModal();
    }
  });
  syncSettingsThemeUi();
})();

function openHelpModal() {
  const modal = document.getElementById('help-modal');
  if (!modal) return;
  modal.hidden = false;
  modal.removeAttribute('inert');
  modal.setAttribute('aria-hidden', 'false');
  document.getElementById('help-close')?.focus();
}

function closeHelpModal() {
  const modal = document.getElementById('help-modal');
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute('inert', '');
  modal.setAttribute('aria-hidden', 'true');
  document.getElementById('help-btn')?.focus();
}

(function initHelpModal() {
  document.getElementById('help-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    openHelpModal();
  });
  document.getElementById('help-close')?.addEventListener('click', closeHelpModal);
  document.getElementById('help-done')?.addEventListener('click', closeHelpModal);
  document.getElementById('help-modal-backdrop')?.addEventListener('click', closeHelpModal);
})();

// State
let currentData = null;
let currentType = null;  // 'dex' | 'apk' | 'axml' | 'arsc'
let currentApkBytes = null;  // For extracting files from APK
/** Cached resources.arsc id → R.type.name map for the current APK (plain object). */
let apkResourceMap = null;
/** Cached resources.arsc id → resolved string value (labels, etc.). */
let apkResourceValues = null;
let apkResourceMapPromise = null;
/** Bytes of the last loaded primary file (APK/DEX/AXML/ARSC) for the Raw hex editor. */
let currentFileBytes = null;
/** Raw bytes of current standalone DEX file (for lazy get_dex_method). */
let currentDexBytes = null;
/**
 * Standalone DEX session (one or many):
 * [{ name, bytes, data, classCount, methodCount }]
 * Empty when viewing APK / AXML / ARSC.
 */
let loadedDexFiles = [];
let activeDexIndex = 0;
let currentFilename = '';
let searchQuery = '';  // Search filter (classes, methods, strings, etc.)
let searchDebounceId = null;
/** Precomputed lowercased searchable strings for current DEX; invalidated on file change. */
let dexSearchIndex = null;
/** When false (default), hide android.* / androidx.* from class trees and selectors. */
const SHOW_ANDROID_CLASSES_KEY = 'droid2web-show-android-classes';
let showAndroidFrameworkClasses = (() => {
  try { return localStorage.getItem(SHOW_ANDROID_CLASSES_KEY) === '1'; } catch (_) { return false; }
})();

/** When viewing an APK: the currently selected extracted file (DEX/PNG/ARSC/AXML). Does not replace currentData. */
let apkExtractedFile = null;  // null | { name, kind: 'dex'|'axml'|'arsc'|'png'|'binary', data?, bytes? }
/** Left panel mode for APK: class browser (default) or raw file tree. */
let apkLeftMode = 'classes';
/**
 * APK DEX filter for the left class browser.
 * '' = All DEXes (unified packages from apkClassToDex);
 * otherwise a DEX path (e.g. classes2.dex) — packages from that file only.
 */
let apkDexFilter = '';
/** When apkExtractedFile.kind === 'dex': selected class and method indices for bytecode/source view. */
let apkExtractedDexSelection = { classIdx: 0, methodIdx: 0 };
/** When currentType === 'dex' (standalone): selected class and method for bytecode/source/emulator. */
let currentDexSelection = { classIdx: 0, methodIdx: 0 };
/** Code view: which class/method to show. methodIdx null = "All methods" for that class. */
let codeViewClassIdx = 0;
let codeViewMethodIdx = null;  // null = show all methods for codeViewClassIdx
/** Code tab toolbar: selected package name; Class dropdown shows only classes from this package. */
let codeViewPackage = '';
/** DEX left panel: selected package name (empty = none). Only classes of this package are shown. */
let selectedDexPackage = '';
/** Strings tab: full list + filtered view state. */
let currentStringsArray = [];
/** @type {number[]} indices into currentStringsArray after filter/sort */
let stringsFilteredIdx = [];
let stringsSelectedIdx = null; // index into currentStringsArray
/** Cache: stringIndex -> usages info for the current DEX bytes fingerprint. */
let stringsUsageCache = new Map();
let stringsUsageCacheKey = '';
let stringsUsageRequestId = 0;
let stringsTypeFilter = 'all';
let stringsRenderTimer = null;
const STRINGS_ROW_H = 28;
const STRINGS_OVERSCAN = 12;
/** Last emulator run in bytecode view: { history, stepIndex } or null. Cleared when method changes. */
let lastEmulatorRun = null;

/** In-memory renames for decompiler: right-click on class/method/field/variable. Sent to get_dex_method. */
let dexRenames = {
  package: {},
  class: {},
  method: {},
  field: {},
  variable: {},
};

const RENAMES_STORAGE_KEY = 'droid2web-renames-v1';
const RENAMES_STORAGE_MAX_CHARS = 1_500_000;

function emptyDexRenames() {
  return { package: {}, class: {}, method: {}, field: {}, variable: {} };
}

function normalizeDexRenames(raw) {
  const out = emptyDexRenames();
  if (!raw || typeof raw !== 'object') return out;
  const fixKey = (k) => String(k).includes('->') && !String(k).includes('#')
    ? String(k).replace('->', '#')
    : String(k);
  for (const k of ['package', 'class', 'method', 'field']) {
    if (raw[k] && typeof raw[k] === 'object') {
      for (const [from, to] of Object.entries(raw[k])) {
        if (typeof from === 'string' && typeof to === 'string' && from && to) {
          out[k][k === 'method' || k === 'field' ? fixKey(from) : from] = to;
        }
      }
    }
  }
  if (raw.variable && typeof raw.variable === 'object') {
    for (const [methodKey, vars] of Object.entries(raw.variable)) {
      if (!vars || typeof vars !== 'object') continue;
      const map = {};
      for (const [from, to] of Object.entries(vars)) {
        if (typeof from === 'string' && typeof to === 'string' && from && to) map[from] = to;
      }
      if (Object.keys(map).length) out.variable[fixKey(methodKey)] = map;
    }
  }
  return out;
}

function dexRenamesHasAny(r = dexRenames) {
  return Object.keys(r.package || {}).length > 0
    || Object.keys(r.class || {}).length > 0
    || Object.keys(r.method || {}).length > 0
    || Object.keys(r.field || {}).length > 0
    || Object.keys(r.variable || {}).length > 0;
}

function renamesStorageFingerprint() {
  try {
    return (typeof securityFileFingerprint === 'function' && securityFileFingerprint()) || '';
  } catch (_) {
    return '';
  }
}

function readRenamesStore() {
  try {
    const raw = localStorage.getItem(RENAMES_STORAGE_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeRenamesStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > RENAMES_STORAGE_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > RENAMES_STORAGE_MAX_CHARS && keys.length > 1) {
        delete store.entries[keys.shift().k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(RENAMES_STORAGE_KEY, json);
    return true;
  } catch (e) {
    warn('renames cache write failed', e);
    return false;
  }
}

/** Load renames for the current file fingerprint into `dexRenames`. */
function loadDexRenamesFromStorage() {
  dexRenames = emptyDexRenames();
  const key = renamesStorageFingerprint();
  if (!key) return;
  try {
    const entry = readRenamesStore().entries[key];
    if (entry?.renames) dexRenames = normalizeDexRenames(entry.renames);
  } catch (_) {
    dexRenames = emptyDexRenames();
  }
}

/** Persist current `dexRenames` for this file (or remove entry if empty). */
function saveDexRenamesToStorage() {
  const key = renamesStorageFingerprint();
  if (!key) return;
  const store = readRenamesStore();
  if (!dexRenamesHasAny()) {
    delete store.entries[key];
  } else {
    store.entries[key] = { savedAt: Date.now(), renames: dexRenames };
  }
  writeRenamesStore(store);
}

/* ── Annotations (notes + tags) for classes / methods ─────────────────────── */
const ANNOTATIONS_STORAGE_KEY = 'droid2web-notes-v1';
const ANNOTATIONS_STORAGE_MAX_CHARS = 1_500_000;

/** @type {{ class: Record<string, { note?: string, tags?: string[] }>, method: Record<string, { note?: string, tags?: string[] }> }} */
let dexAnnotations = { class: {}, method: {} };

function emptyDexAnnotations() {
  return { class: {}, method: {} };
}

function normalizeAnnotationEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const note = typeof raw.note === 'string' ? raw.note.trim() : '';
  const tags = Array.isArray(raw.tags)
    ? [...new Set(raw.tags.map((t) => String(t).trim()).filter(Boolean))]
    : [];
  if (!note && !tags.length) return null;
  return { note, tags };
}

function normalizeDexAnnotations(raw) {
  const out = emptyDexAnnotations();
  if (!raw || typeof raw !== 'object') return out;
  for (const kind of ['class', 'method']) {
    if (!raw[kind] || typeof raw[kind] !== 'object') continue;
    for (const [key, val] of Object.entries(raw[kind])) {
      if (typeof key !== 'string' || !key) continue;
      const entry = normalizeAnnotationEntry(val);
      if (entry) out[kind][key] = entry;
    }
  }
  return out;
}

function dexAnnotationsHasAny(a = dexAnnotations) {
  return Object.keys(a.class || {}).length > 0 || Object.keys(a.method || {}).length > 0;
}

function annotationsStorageFingerprint() {
  const primary = renamesStorageFingerprint();
  if (primary) return primary;
  // Fallback so notes still persist when the security fingerprint is empty
  const name = currentFilename || 'unknown';
  const size = currentApkBytes?.length || currentDexBytes?.length || currentFileBytes?.length || 0;
  if (!size && currentType !== 'dex' && currentType !== 'apk') return '';
  return `anno-fallback|${currentType || 'file'}|${name}|${size}`;
}

function readAnnotationsStore() {
  try {
    const raw = localStorage.getItem(ANNOTATIONS_STORAGE_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeAnnotationsStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > ANNOTATIONS_STORAGE_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > ANNOTATIONS_STORAGE_MAX_CHARS && keys.length > 1) {
        delete store.entries[keys.shift().k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(ANNOTATIONS_STORAGE_KEY, json);
    return true;
  } catch (e) {
    warn('annotations cache write failed', e);
    return false;
  }
}

function loadDexAnnotationsFromStorage() {
  dexAnnotations = emptyDexAnnotations();
  const key = annotationsStorageFingerprint();
  if (!key) return;
  try {
    const entry = readAnnotationsStore().entries[key];
    if (entry?.annotations) dexAnnotations = normalizeDexAnnotations(entry.annotations);
  } catch (_) {
    dexAnnotations = emptyDexAnnotations();
  }
}

function saveDexAnnotationsToStorage() {
  const key = annotationsStorageFingerprint();
  if (!key) {
    warn('annotations not saved: no file fingerprint');
    return false;
  }
  const store = readAnnotationsStore();
  if (!dexAnnotationsHasAny()) {
    delete store.entries[key];
  } else {
    store.entries[key] = { savedAt: Date.now(), annotations: dexAnnotations };
  }
  return writeAnnotationsStore(store);
}

function getAnnotation(kind, key) {
  if (!key || (kind !== 'class' && kind !== 'method')) return null;
  return dexAnnotations[kind]?.[key] || null;
}

function setAnnotation(kind, key, { note, tags } = {}) {
  if (!key || (kind !== 'class' && kind !== 'method')) return false;
  const entry = normalizeAnnotationEntry({
    note: note != null ? note : (dexAnnotations[kind][key]?.note || ''),
    tags: tags != null ? tags : (dexAnnotations[kind][key]?.tags || []),
  });
  if (!entry) {
    delete dexAnnotations[kind][key];
  } else {
    dexAnnotations[kind][key] = entry;
  }
  return saveDexAnnotationsToStorage();
}

function clearAnnotation(kind, key) {
  if (!key || !dexAnnotations[kind]) return false;
  delete dexAnnotations[kind][key];
  return saveDexAnnotationsToStorage();
}

function methodAnnotationKey(className, methodName) {
  return `${className}#${methodName}`;
}

/* ── Bookmarks (jadx-like: pin class/method, jump later) ──────────────────── */
const BOOKMARKS_STORAGE_KEY = 'droid2web-bookmarks-v1';
const BOOKMARKS_STORAGE_MAX_CHARS = 1_500_000;

/** @type {{ items: Array<{ id: string, kind: string, key: string, label: string, note?: string, className?: string, methodName?: string, line?: number, offset?: number, createdAt: number }> }} */
let dexBookmarks = { items: [] };

function emptyDexBookmarks() {
  return { items: [] };
}

function bookmarksStorageFingerprint() {
  try {
    const fp = annotationsStorageFingerprint();
    if (fp) return fp;
  } catch (_) { /* ignore */ }
  const name = currentFilename || 'unknown';
  const size = currentApkBytes?.length || currentDexBytes?.length || currentFileBytes?.length || 0;
  return `bm-fallback|${currentType || 'file'}|${name}|${size || '0'}`;
}

function readBookmarksStore() {
  try {
    const raw = localStorage.getItem(BOOKMARKS_STORAGE_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeBookmarksStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > BOOKMARKS_STORAGE_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > BOOKMARKS_STORAGE_MAX_CHARS && keys.length > 1) {
        delete store.entries[keys.shift().k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(BOOKMARKS_STORAGE_KEY, json);
    return true;
  } catch (e) {
    warn('bookmarks cache write failed', e);
    return false;
  }
}

function normalizeBookmark(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const kind = String(raw.kind || '').trim();
  const key = String(raw.key || '').trim();
  if (!kind || !key) return null;
  return {
    id: String(raw.id || `${kind}:${key}`),
    kind,
    key,
    label: String(raw.label || key).trim() || key,
    note: typeof raw.note === 'string' ? raw.note.trim() : '',
    className: typeof raw.className === 'string' ? raw.className : '',
    methodName: typeof raw.methodName === 'string' ? raw.methodName : '',
    line: Number.isFinite(Number(raw.line)) ? Number(raw.line) : undefined,
    offset: Number.isFinite(Number(raw.offset)) ? Number(raw.offset) : undefined,
    createdAt: Number(raw.createdAt) || Date.now(),
  };
}

function normalizeDexBookmarks(raw) {
  const out = emptyDexBookmarks();
  const list = Array.isArray(raw?.items) ? raw.items : (Array.isArray(raw) ? raw : []);
  for (const item of list) {
    const b = normalizeBookmark(item);
    if (b) out.items.push(b);
  }
  return out;
}

function loadDexBookmarksFromStorage() {
  dexBookmarks = emptyDexBookmarks();
  const key = bookmarksStorageFingerprint();
  if (!key) return;
  try {
    const entry = readBookmarksStore().entries[key];
    if (entry?.bookmarks) dexBookmarks = normalizeDexBookmarks(entry.bookmarks);
  } catch (_) {
    dexBookmarks = emptyDexBookmarks();
  }
}

function saveDexBookmarksToStorage() {
  const key = bookmarksStorageFingerprint();
  if (!key) {
    warn('bookmarks not saved: no file fingerprint');
    return false;
  }
  const store = readBookmarksStore();
  if (!dexBookmarks.items.length) delete store.entries[key];
  else store.entries[key] = { savedAt: Date.now(), bookmarks: dexBookmarks };
  return writeBookmarksStore(store);
}

function findBookmark(kind, key) {
  return dexBookmarks.items.find((b) => b.kind === kind && b.key === key) || null;
}

function treeBookmarkStarHtml(kind, classIdx, methodIdx = null, key = '') {
  const on = !!(key && findBookmark(kind, key));
  const methodAttr = methodIdx != null && !Number.isNaN(methodIdx)
    ? ` data-method="${methodIdx}"`
    : '';
  return `<button type="button" class="tree-bookmark-star${on ? ' is-on' : ''}" data-bm-kind="${escapeAttr(kind)}" data-class="${classIdx}"${methodAttr} title="${on ? 'Remove bookmark' : 'Add bookmark'}" aria-label="${on ? 'Remove bookmark' : 'Add bookmark'}" aria-pressed="${on ? 'true' : 'false'}">${on ? '★' : '☆'}</button>`;
}

function syncAnnoBookmarkStarButton() {
  const btn = document.getElementById('anno-bookmark-star');
  if (!btn) return;
  const target = currentAnnotationTarget();
  if (!target) {
    btn.hidden = true;
    return;
  }
  btn.hidden = false;
  const on = !!findBookmark(target.kind, target.key);
  btn.classList.toggle('is-on', on);
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  btn.textContent = on ? '★' : '☆';
  btn.title = on ? 'Remove bookmark' : 'Bookmark this ' + target.kind;
  btn.setAttribute('aria-label', btn.title);
}

function syncListBookmarksFilterButton() {
  const btn = document.getElementById('list-bookmarks-btn');
  if (!btn) return;
  const parsed = parseListSearchQuery(searchQuery);
  const on = !!parsed.bookmarks;
  btn.classList.toggle('is-on', on);
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  const n = dexBookmarks.items.length;
  btn.textContent = n ? `★${n}` : '★';
  btn.title = on
    ? 'Clear bookmark filter (showing bookmarked only)'
    : (n ? `Show ${n} bookmark${n === 1 ? '' : 's'}` : 'Show bookmarked classes and methods');
}

function toggleBookmark({ kind, key, label, className, methodName, line, offset, note } = {}) {
  if (!kind || !key) {
    warn('toggleBookmark missing kind/key', kind, key);
    return false;
  }
  const existing = findBookmark(kind, key);
  if (existing) {
    dexBookmarks.items = dexBookmarks.items.filter((b) => !(b.kind === kind && b.key === key));
  } else {
    const entry = normalizeBookmark({
      id: `${kind}:${key}:${Date.now()}`,
      kind,
      key,
      label: label || key,
      note: note || '',
      className: className || (kind === 'class' ? key : String(key).split('#')[0] || ''),
      methodName: methodName || (kind === 'method' ? (String(key).split('#')[1] || '') : ''),
      line,
      offset,
      createdAt: Date.now(),
    });
    if (!entry) return false;
    dexBookmarks.items.unshift(entry);
  }
  const ok = saveDexBookmarksToStorage();
  refreshBookmarksUi();
  try {
    if (typeof setAnnotationStatus === 'function') {
      setAnnotationStatus(
        existing ? 'Bookmark removed' : (ok ? 'Bookmarked' : 'Bookmarked (not persisted)'),
        !existing
      );
    }
  } catch (_) { /* ignore */ }
  // If bookmark filter is active, refresh the tree so items appear/disappear.
  try {
    if (parseListSearchQuery(searchQuery).bookmarks) {
      if (currentType === 'dex' && Array.isArray(currentData?.classes)) {
        renderClassTreeFromPackageMap(currentData.classes, buildDexPackageMap(currentData.classes), { isApk: false });
      } else if (currentType === 'apk' && apkLeftMode === 'classes' && typeof renderApkClassTree === 'function') {
        renderApkClassTree();
      }
    }
  } catch (_) { /* ignore */ }
  return true;
}

function removeBookmark(id) {
  const before = dexBookmarks.items.length;
  dexBookmarks.items = dexBookmarks.items.filter((b) => b.id !== id);
  if (dexBookmarks.items.length === before) return false;
  const ok = saveDexBookmarksToStorage();
  refreshBookmarksUi();
  return ok;
}

function bookmarkContextMenuItems(kind, key, meta = {}) {
  const has = !!findBookmark(kind, key);
  return [{
    label: has ? 'Remove bookmark' : 'Add bookmark',
    onChoose: () => {
      toggleBookmark({
        kind,
        key,
        label: meta.label || key,
        className: meta.className || '',
        methodName: meta.methodName || '',
        line: meta.line,
        offset: meta.offset,
      });
    },
  }];
}

function jumpToBookmark(b) {
  if (!b) return;
  const className = b.className
    || (b.kind === 'class' ? b.key : String(b.key).split('#')[0])
    || '';
  const methodName = b.methodName
    || (b.kind === 'method' ? (String(b.key).split('#')[1] || '') : '')
    || '';
  if (!className) return;

  // Fast path: resolve inside the currently loaded DEX classes.
  try {
    const ctx = getCodeViewContext();
    const classes = ctx?.classes;
    if (Array.isArray(classes) && classes.length) {
      const classIdx = classes.findIndex((c) => (c?.name || '') === className);
      if (classIdx >= 0) {
        let methodIdx = null;
        if (methodName) {
          const methods = classes[classIdx].methods || [];
          const mi = methods.findIndex((m) => (m?.name || '') === methodName);
          methodIdx = mi >= 0 ? mi : null;
        }
        if (typeof selectCodeViewMethod === 'function') {
          selectCodeViewMethod(classIdx, methodIdx, { expandCfg: methodIdx != null });
        } else {
          codeViewClassIdx = classIdx;
          codeViewMethodIdx = methodIdx;
          updateCodeView();
        }
        return;
      }
    }
  } catch (_) { /* fall through */ }

  navigateToSecurityFinding(className, methodName || '', '', {
    offset: Number.isFinite(b.offset) ? b.offset : undefined,
    hint: b.note || '',
  });
}

function renderBookmarksListHtml() {
  if (!dexBookmarks.items.length) {
    return `<div class="anno-bookmark-empty muted">No bookmarks yet — click ★ on a class/method</div>`;
  }
  return `<ul class="anno-bookmark-list">${dexBookmarks.items.map((b) => {
    const kind = escapeHtml(b.kind);
    const label = escapeHtml(b.label || b.key);
    return `<li class="anno-bookmark-item" data-bookmark-id="${escapeAttr(b.id)}">
      <button type="button" class="anno-bookmark-jump" title="Jump to bookmark"><span class="anno-bookmark-star" aria-hidden="true">★</span> ${label}</button>
      <span class="anno-bookmark-kind muted">${kind}</span>
      <button type="button" class="anno-bookmark-remove" title="Remove bookmark" aria-label="Remove">×</button>
    </li>`;
  }).join('')}</ul>`;
}

function refreshBookmarksUi() {
  const list = document.getElementById('anno-bookmarks-list');
  const count = document.getElementById('anno-bookmarks-count');
  if (count) count.textContent = dexBookmarks.items.length ? String(dexBookmarks.items.length) : '';
  if (list) list.innerHTML = renderBookmarksListHtml();
  syncAnnoBookmarkStarButton();
  syncListBookmarksFilterButton();
  syncAnnoPanelCollapsedChrome(document.getElementById('annotation-panel'));
  try {
    const ctx = getCodeViewContext();
    const classes = ctx?.classes;
    document.querySelectorAll('.tree-bookmark-star').forEach((btn) => {
      const kind = btn.getAttribute('data-bm-kind');
      const classIdx = parseInt(btn.getAttribute('data-class'), 10);
      if (!kind || Number.isNaN(classIdx) || !classes?.[classIdx]) return;
      const className = classes[classIdx].name || '';
      let key = className;
      if (kind === 'method') {
        const methodIdx = parseInt(btn.getAttribute('data-method'), 10);
        const methodName = classes[classIdx].methods?.[methodIdx]?.name || '';
        key = methodAnnotationKey(className, methodName);
      }
      const on = !!findBookmark(kind, key);
      btn.classList.toggle('is-on', on);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.textContent = on ? '★' : '☆';
      btn.title = on ? 'Remove bookmark' : 'Add bookmark';
      btn.setAttribute('aria-label', btn.title);
      const row = btn.closest('.tree-item');
      if (row) row.classList.toggle('is-bookmarked', on);
    });
  } catch (_) { /* ignore */ }
}

function bindBookmarksUi() {
  const list = document.getElementById('anno-bookmarks-list');
  if (!list || list.dataset.bound === '1') return;
  list.dataset.bound = '1';
  list.addEventListener('click', (e) => {
    const row = e.target.closest('.anno-bookmark-item');
    if (!row) return;
    const id = row.getAttribute('data-bookmark-id');
    if (e.target.closest('.anno-bookmark-remove')) {
      removeBookmark(id);
      return;
    }
    if (e.target.closest('.anno-bookmark-jump')) {
      const b = dexBookmarks.items.find((x) => x.id === id);
      jumpToBookmark(b);
    }
  });
}

/* ── Per-line comments on decompiled source (EOL notes) ───────────────────── */
const SOURCE_COMMENTS_KEY = 'droid2web-source-comments-v1';
const SOURCE_COMMENTS_MAX_CHARS = 1_500_000;

function sourceCommentsFileFingerprint() {
  try {
    return annotationsStorageFingerprint() || securityFileFingerprint() || '';
  } catch (_) {
    return '';
  }
}

function readSourceCommentsStore() {
  try {
    const raw = localStorage.getItem(SOURCE_COMMENTS_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeSourceCommentsStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > SOURCE_COMMENTS_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > SOURCE_COMMENTS_MAX_CHARS && keys.length > 1) {
        delete store.entries[keys.shift().k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(SOURCE_COMMENTS_KEY, json);
    return true;
  } catch (e) {
    warn('source comments write failed', e);
    return false;
  }
}

function resolveSourceCommentMethodKey(methodRef) {
  if (!methodRef || methodRef.classIdx == null || methodRef.methodIdx == null) return '';
  const ctx = getCodeViewContext();
  const cls = ctx?.classes?.[methodRef.classIdx];
  const m = cls?.methods?.[methodRef.methodIdx];
  if (!cls?.name || !m) return '';
  const methodName = (typeof getDexMethodRawName === 'function' ? getDexMethodRawName(m) : '') || m.name || '';
  if (!methodName) return '';
  return cfgMethodStorageKey(cls.name, methodName, m.descriptor || m.sig || '', cfgCurrentDexLabel());
}

function getSourceLineCommentsMap(methodKey) {
  const fp = sourceCommentsFileFingerprint();
  if (!fp || !methodKey) return {};
  try {
    const lines = readSourceCommentsStore().entries[fp]?.methods?.[methodKey]?.lines;
    return (lines && typeof lines === 'object') ? lines : {};
  } catch (_) {
    return {};
  }
}

function getSourceLineComment(methodKey, lineIdx) {
  const text = getSourceLineCommentsMap(methodKey)[String(lineIdx)];
  return typeof text === 'string' ? text : '';
}

function setSourceLineComment(methodKey, lineIdx, text) {
  const fp = sourceCommentsFileFingerprint();
  if (!fp || !methodKey || lineIdx == null || Number.isNaN(Number(lineIdx))) return false;
  const store = readSourceCommentsStore();
  const entry = store.entries[fp] && typeof store.entries[fp] === 'object'
    ? store.entries[fp]
    : { methods: {} };
  const methods = entry.methods && typeof entry.methods === 'object' ? { ...entry.methods } : {};
  const prev = methods[methodKey]?.lines && typeof methods[methodKey].lines === 'object'
    ? { ...methods[methodKey].lines }
    : {};
  const note = String(text || '').trim().slice(0, 2000);
  if (note) prev[String(lineIdx)] = note;
  else delete prev[String(lineIdx)];
  if (!Object.keys(prev).length) delete methods[methodKey];
  else methods[methodKey] = { lines: prev, updatedAt: Date.now() };
  if (!Object.keys(methods).length) delete store.entries[fp];
  else store.entries[fp] = { savedAt: Date.now(), methods };
  return writeSourceCommentsStore(store);
}

function srcLineCommentChrome(methodKey, lineIdx) {
  if (!methodKey) return '';
  const text = getSourceLineComment(methodKey, lineIdx);
  if (text) {
    return `<span class="src-line-comment" data-src-comment data-method-key="${escapeAttr(methodKey)}" data-line="${lineIdx}" title="Edit line comment"><span class="src-line-comment-mark">//</span> ${escapeHtml(text)}</span>`;
  }
  return `<button type="button" class="src-line-comment-add" data-src-comment-add data-method-key="${escapeAttr(methodKey)}" data-line="${lineIdx}" title="Add line comment">+</button>`;
}

function editSourceLineComment(methodKey, lineIdx) {
  if (!methodKey || lineIdx == null || Number.isNaN(Number(lineIdx))) {
    alert('Comments need a loaded method. Open a method in the Code view first.');
    return;
  }
  if (!sourceCommentsFileFingerprint()) {
    alert('Comments need a loaded APK/DEX so they can be saved to localStorage.');
    return;
  }
  const cur = getSourceLineComment(methodKey, lineIdx);
  const next = window.prompt(`Comment for line ${Number(lineIdx) + 1} (empty to clear):`, cur);
  if (next == null) return;
  if (!setSourceLineComment(methodKey, lineIdx, next)) {
    alert('Could not save the comment to localStorage (quota or private mode?).');
    return;
  }
  renderSourceWithSearch();
}

/** Resolve method key + line index for a source click/contextmenu target. */
function resolveSourceCommentTarget(event) {
  const lineEl = event?.target?.closest?.('.src-line[data-line]');
  if (!lineEl || !sourceCode?.contains(lineEl)) return null;
  const lineIdx = Number(lineEl.getAttribute('data-line'));
  if (Number.isNaN(lineIdx)) return null;
  const resolved = typeof resolveMethodFromEvent === 'function' ? resolveMethodFromEvent(event) : null;
  const methodRef = resolved?.methodIdx != null
    ? { classIdx: resolved.classIdx, methodIdx: resolved.methodIdx }
    : (currentSourceMethodMeta
      ? { classIdx: currentSourceMethodMeta.classIdx, methodIdx: currentSourceMethodMeta.methodIdx }
      : (codeViewMethodIdx != null ? { classIdx: codeViewClassIdx, methodIdx: codeViewMethodIdx } : null));
  const methodKey = resolveSourceCommentMethodKey(methodRef);
  if (!methodKey) return null;
  return { methodKey, lineIdx, methodRef };
}

function buildSourceLineCommentMenuItems(event) {
  const hit = resolveSourceCommentTarget(event);
  if (!hit) return [];
  const { methodKey, lineIdx } = hit;
  const cur = getSourceLineComment(methodKey, lineIdx);
  const items = [{
    label: cur ? `Edit comment on line ${lineIdx + 1}…` : `Add comment on line ${lineIdx + 1}…`,
    onChoose: () => editSourceLineComment(methodKey, lineIdx),
  }];
  if (cur) {
    items.push({
      label: `Clear comment on line ${lineIdx + 1}`,
      onChoose: () => {
        if (!setSourceLineComment(methodKey, lineIdx, '')) {
          alert('Could not update localStorage.');
          return;
        }
        renderSourceWithSearch();
      },
    });
  }
  return items;
}

function mergeSourceCommentsJson(localRaw, importedRaw) {
  let local = { entries: {} };
  let imported = { entries: {} };
  try {
    const p = JSON.parse(localRaw || '{}');
    if (p?.entries && typeof p.entries === 'object') local = p;
  } catch (_) {}
  try {
    const p = JSON.parse(importedRaw || '{}');
    if (p?.entries && typeof p.entries === 'object') imported = p;
  } catch (_) {}
  const out = { entries: { ...(local.entries || {}) } };
  for (const [fp, entry] of Object.entries(imported.entries || {})) {
    if (!entry || typeof entry !== 'object') continue;
    const existing = out.entries[fp];
    if (!existing) {
      out.entries[fp] = entry;
      continue;
    }
    const methods = { ...(existing.methods || {}) };
    for (const [mk, meth] of Object.entries(entry.methods || {})) {
      if (!meth || typeof meth !== 'object') continue;
      const prev = methods[mk];
      if (!prev) {
        methods[mk] = meth;
        continue;
      }
      methods[mk] = {
        ...prev,
        ...meth,
        lines: { ...(prev.lines || {}), ...(meth.lines || {}) },
        updatedAt: Math.max(Number(prev.updatedAt) || 0, Number(meth.updatedAt) || 0),
      };
    }
    out.entries[fp] = {
      ...existing,
      ...entry,
      methods,
      savedAt: Math.max(Number(existing.savedAt) || 0, Number(entry.savedAt) || 0),
    };
  }
  return JSON.stringify(out);
}

/** Read pending note/tags from the panel so we never wipe unsaved textarea content. */
function annotationPanelDraft({ includePendingTag = false } = {}) {
  const panel = document.getElementById('annotation-panel');
  if (!panel || panel.hidden) return null;
  const kind = panel.dataset.kind;
  const key = panel.dataset.key;
  if (!kind || !key) return null;
  const noteEl = panel.querySelector('.anno-note');
  const tagInput = panel.querySelector('.anno-tag-input');
  const stored = getAnnotation(kind, key);
  const tags = [...(stored?.tags || [])];
  if (includePendingTag) {
    const pendingTag = tagInput?.value?.trim();
    if (pendingTag && !tags.some((t) => t.toLowerCase() === pendingTag.toLowerCase())) {
      tags.push(pendingTag);
    }
  }
  return {
    kind,
    key,
    note: noteEl ? noteEl.value : (stored?.note || ''),
    tags,
    hadPendingTag: !!(includePendingTag && tagInput?.value?.trim()),
  };
}

function setAnnotationStatus(msg, ok = true) {
  const el = document.getElementById('anno-status');
  if (!el) return;
  el.textContent = msg || '';
  el.classList.toggle('is-error', !ok && !!msg);
  el.classList.toggle('is-ok', ok && !!msg);
  if (msg && ok) {
    clearTimeout(setAnnotationStatus._t);
    setAnnotationStatus._t = setTimeout(() => {
      if (el.textContent === msg) {
        el.textContent = '';
        el.classList.remove('is-ok', 'is-error');
      }
    }, 1800);
  }
}

function persistAnnotationPanel({ quiet = false, includePendingTag = false } = {}) {
  const draft = annotationPanelDraft({ includePendingTag });
  if (!draft) return false;
  const ok = setAnnotation(draft.kind, draft.key, { note: draft.note, tags: draft.tags });
  if (draft.hadPendingTag) {
    const tagInput = document.querySelector('#annotation-panel .anno-tag-input');
    if (tagInput) tagInput.value = '';
  }
  if (!quiet) setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
  return ok;
}

function treeAnnotationBadgeHtml(kind, key) {
  const a = getAnnotation(kind, key);
  if (!a) return '';
  const tipParts = [];
  if (a.tags?.length) tipParts.push('Tags: ' + a.tags.join(', '));
  if (a.note) tipParts.push(a.note.length > 120 ? a.note.slice(0, 117) + '…' : a.note);
  const title = escapeAttr(tipParts.join(' — '));
  let html = `<span class="tree-anno" title="${title}">`;
  if (a.note) html += '<span class="tree-anno-dot note" aria-label="Has note"></span>';
  if (a.tags?.length) {
    html += `<span class="tree-anno-dot tag" aria-label="${a.tags.length} tag(s)"></span>`;
    if (a.tags.length > 1) html += `<span class="tree-anno-count">${a.tags.length}</span>`;
  }
  html += '</span>';
  return html;
}

function annotationContextMenuItems(kind, key, displayLabel) {
  const items = [
    {
      label: 'Edit note…',
      onChoose: () => promptEditAnnotationNote(kind, key, displayLabel),
    },
    {
      label: 'Edit tags…',
      onChoose: () => promptEditAnnotationTags(kind, key, displayLabel),
    },
  ];
  if (getAnnotation(kind, key)) {
    items.push({
      label: 'Clear note & tags',
      onChoose: () => {
        clearAnnotation(kind, key);
        refreshAnnotationUi();
      },
    });
  }
  const className = kind === 'class' ? key : key.split('#')[0];
  const methodName = kind === 'method' ? (key.split('#')[1] || '') : '';
  items.push(...bookmarkContextMenuItems(kind, key, {
    label: displayLabel || key,
    className,
    methodName,
  }));
  if (kind === 'method') {
    items.push({
      label: 'Find usages (xrefs)',
      onChoose: () => {
        const ctx = getCodeViewContext();
        const classes = ctx?.classes;
        if (!classes) return;
        let classIdx = -1;
        let methodIdx = -1;
        for (let ci = 0; ci < classes.length; ci++) {
          if (classes[ci]?.name !== className) continue;
          classIdx = ci;
          const methods = classes[ci].methods || [];
          for (let mi = 0; mi < methods.length; mi++) {
            if ((methods[mi]?.name || '') === methodName) {
              methodIdx = mi;
              break;
            }
          }
          break;
        }
        if (classIdx < 0 || methodIdx < 0) {
          navigateToSecurityFinding(className, methodName, '', { hint: 'xrefs' });
          return;
        }
        selectCodeViewMethod(classIdx, methodIdx, { expandCfg: false });
        requestAnimationFrame(() => loadAndShowMethodCallers(classIdx, methodIdx));
      },
    });
  }
  return items;
}

function promptEditAnnotationNote(kind, key, displayLabel) {
  const cur = getAnnotation(kind, key)?.note || '';
  const next = window.prompt(`Note for ${displayLabel || key}:`, cur);
  if (next === null) return;
  const tags = getAnnotation(kind, key)?.tags || [];
  const ok = setAnnotation(kind, key, { note: next, tags });
  setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
  refreshAnnotationUi();
}

function promptEditAnnotationTags(kind, key, displayLabel) {
  const cur = (getAnnotation(kind, key)?.tags || []).join(', ');
  const next = window.prompt(`Tags for ${displayLabel || key} (comma-separated):`, cur);
  if (next === null) return;
  const tags = next.split(/[,;\n]/).map((t) => t.trim()).filter(Boolean);
  const note = getAnnotation(kind, key)?.note || '';
  const ok = setAnnotation(kind, key, { tags, note });
  setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
  refreshAnnotationUi();
}

function currentAnnotationTarget() {
  const ctx = getCodeViewContext();
  if (!ctx?.classes?.length) return null;
  const classIdx = codeViewClassIdx;
  const cls = ctx.classes[classIdx];
  if (!cls?.name) return null;
  if (codeViewMethodIdx != null && cls.methods?.[codeViewMethodIdx]) {
    const methodName = cls.methods[codeViewMethodIdx].name || '';
    return {
      kind: 'method',
      key: methodAnnotationKey(cls.name, methodName),
      label: getDisplayClassName(cls.name).split('.').pop() + '.' + getDisplayMethodName(cls.name, methodName),
      className: cls.name,
      methodName,
    };
  }
  return {
    kind: 'class',
    key: cls.name,
    label: getDisplayClassName(cls.name),
    className: cls.name,
  };
}

function refreshTreeAnnotationBadges() {
  try {
    document.querySelectorAll('.tree-item.class[data-class], .tree-item.method[data-class]').forEach((el) => {
      const classIdx = parseInt(el.dataset.class, 10);
      if (Number.isNaN(classIdx)) return;
      const ctx = getCodeViewContext();
      const classes = ctx?.classes;
      if (!classes?.[classIdx]) return;
      const className = classes[classIdx].name || '';
      let badge = '';
      if (el.classList.contains('method')) {
        const methodIdx = parseInt(el.dataset.method, 10);
        const methodName = classes[classIdx].methods?.[methodIdx]?.name || '';
        badge = treeAnnotationBadgeHtml('method', methodAnnotationKey(className, methodName));
      } else {
        badge = treeAnnotationBadgeHtml('class', className);
      }
      let slot = el.querySelector('.tree-anno');
      if (!badge) {
        slot?.remove();
        return;
      }
      if (slot) slot.outerHTML = badge;
      else el.insertAdjacentHTML('beforeend', badge);
    });
  } catch (_) {}
}

function refreshAnnotationUi() {
  updateAnnotationPanel();
  refreshTreeAnnotationBadges();
  bindBookmarksUi();
  refreshBookmarksUi();
}

function collectAllAnnotationTags() {
  const set = new Set();
  for (const kind of ['class', 'method']) {
    const map = dexAnnotations?.[kind];
    if (!map || typeof map !== 'object') continue;
    for (const a of Object.values(map)) {
      for (const t of (a.tags || [])) {
        const s = String(t || '').trim();
        if (s) set.add(s);
      }
    }
  }
  return [...set].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
}

function setAnnoSectionCollapsed(section, collapsed) {
  if (!section) return;
  const want = !!collapsed;
  section.dataset.collapsed = want ? 'true' : 'false';
  const toggle = section.querySelector('.anno-section-toggle');
  if (toggle) {
    toggle.setAttribute('aria-expanded', want ? 'false' : 'true');
    toggle.title = want ? 'Show section' : 'Hide section';
  }
}

/** Prefer keeping the Tags/Notes/Bookmarks body open across method switches (session). */
let annoBodyPreferOpen = false;

function expandAnnoSectionsWithContent(panel, anno) {
  if (!panel) return;
  const tags = Array.isArray(anno?.tags) ? anno.tags : [];
  const hasNote = !!(anno?.note && String(anno.note).trim());
  const hasBm = dexBookmarks.items.length > 0;
  const tagsSec = panel.querySelector('.anno-tags-section');
  const noteSec = panel.querySelector('.anno-note-section');
  const bmSec = panel.querySelector('.anno-bookmarks-section');
  if (tagsSec) setAnnoSectionCollapsed(tagsSec, tags.length === 0);
  if (noteSec) setAnnoSectionCollapsed(noteSec, !hasNote);
  if (bmSec) setAnnoSectionCollapsed(bmSec, !hasBm);
  // If everything empty, leave Tags open so the user can add one
  if (!tags.length && !hasNote && !hasBm && tagsSec) {
    setAnnoSectionCollapsed(tagsSec, false);
  }
}

function collapseAnnoSectionsByDefault(panel, { forceBodyClosed = false } = {}) {
  if (!panel) return;
  panel.querySelectorAll('.anno-section').forEach((sec) => setAnnoSectionCollapsed(sec, true));
  panel.classList.remove('anno-note-expanded');
  const expandBtn = panel.querySelector('#anno-note-expand');
  if (expandBtn) {
    expandBtn.setAttribute('aria-expanded', 'false');
    expandBtn.textContent = 'Expand';
    expandBtn.title = 'Expand note editor';
  }
  if (forceBodyClosed || !annoBodyPreferOpen) {
    setAnnoBodyCollapsed(panel, true);
  } else {
    setAnnoBodyCollapsed(panel, false);
  }
}

function setAnnoBodyCollapsed(panel, collapsed) {
  if (!panel) return;
  const body = panel.querySelector('.anno-body') || document.getElementById('anno-body');
  const want = !!collapsed;
  panel.classList.toggle('anno-sections-collapsed', want);
  if (body) body.hidden = want;
  const saveBtn = panel.querySelector('#anno-save-btn');
  const clearBtn = panel.querySelector('#anno-clear-btn');
  if (saveBtn) saveBtn.hidden = want;
  if (clearBtn) clearBtn.hidden = want;
  syncAnnoPanelCollapsedChrome(panel);
}

function setAllAnnoSectionsCollapsed(panel, collapsed) {
  if (!panel) return;
  // Global toggle shows/hides the whole Tags/Notes/Bookmarks block.
  if (collapsed) {
    panel.querySelectorAll('.anno-section').forEach((sec) => setAnnoSectionCollapsed(sec, true));
    panel.classList.remove('anno-note-expanded');
    const expandBtn = panel.querySelector('#anno-note-expand');
    if (expandBtn) {
      expandBtn.setAttribute('aria-expanded', 'false');
      expandBtn.textContent = 'Expand';
      expandBtn.title = 'Expand note editor';
    }
  }
  setAnnoBodyCollapsed(panel, collapsed);
}

function renderAnnoHeaderMeta(panel, anno) {
  if (!panel) return;
  const meta = panel.querySelector('#anno-header-meta') || document.getElementById('anno-header-meta');
  const tagsEl = panel.querySelector('#anno-header-tags') || document.getElementById('anno-header-tags');
  const noteEl = panel.querySelector('#anno-header-note') || document.getElementById('anno-header-note');
  if (!meta || !tagsEl || !noteEl) return;
  const tags = Array.isArray(anno?.tags) ? anno.tags : [];
  const noteText = (anno?.note && String(anno.note).trim()) || '';
  tagsEl.innerHTML = tags.map((t) =>
    `<button type="button" class="anno-header-tag" data-tag="${escapeAttr(t)}" title="Filter tree by tag:${escapeAttr(t)}">${escapeHtml(t)}</button>`
  ).join('');
  if (noteText) {
    const firstLine = noteText.split(/\r?\n/).find((l) => l.trim()) || noteText;
    noteEl.hidden = false;
    noteEl.textContent = firstLine.length > 96 ? firstLine.slice(0, 95) + '…' : firstLine;
    noteEl.title = noteText;
  } else {
    noteEl.hidden = true;
    noteEl.textContent = '';
    noteEl.title = '';
  }
  meta.hidden = tags.length === 0 && !noteText;
}

function syncAnnoPanelCollapsedChrome(panel) {
  if (!panel) return;
  const body = panel.querySelector('.anno-body') || document.getElementById('anno-body');
  const bodyCollapsed = body ? !!body.hidden : panel.classList.contains('anno-sections-collapsed');
  panel.classList.toggle('anno-sections-collapsed', bodyCollapsed);
  const globalBtn = panel.querySelector('#anno-sections-toggle');
  if (globalBtn) {
    const nBm = dexBookmarks.items.length;
    const target = currentAnnotationTarget();
    const anno = target ? getAnnotation(target.kind, target.key) : null;
    const nTags = anno?.tags?.length || 0;
    const hasNote = !!(anno?.note && String(anno.note).trim());
    const bits = [];
    if (nTags) bits.push(`${nTags} tag${nTags === 1 ? '' : 's'}`);
    if (hasNote) bits.push('note');
    if (nBm) bits.push(`★${nBm}`);
    const summary = bits.length ? bits.join(' · ') : 'Notes';
    globalBtn.setAttribute('aria-expanded', bodyCollapsed ? 'false' : 'true');
    globalBtn.textContent = bodyCollapsed ? summary : 'Hide';
    globalBtn.title = bodyCollapsed
      ? 'Show tags, notes & bookmarks'
      : 'Hide tags, notes & bookmarks';
    globalBtn.setAttribute('aria-label', globalBtn.title);
    globalBtn.classList.toggle('has-anno', nTags > 0 || hasNote);
  }
}

function updateAnnotationPanel() {
  const panel = document.getElementById('annotation-panel');
  if (!panel) return;
  const target = currentAnnotationTarget();
  if (!target || (currentType !== 'dex' && currentType !== 'apk')) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  const anno = getAnnotation(target.kind, target.key) || { note: '', tags: [] };
  const tags = Array.isArray(anno.tags) ? anno.tags : [];
  const scopeEl = panel.querySelector('.anno-scope');
  const tagsEl = panel.querySelector('.anno-tags');
  const noteEl = panel.querySelector('.anno-note');
  const tagsCountEl = document.getElementById('anno-tags-count');
  const tagsPreviewEl = document.getElementById('anno-tags-preview');
  const notePreviewEl = document.getElementById('anno-note-preview');
  const tagEmptyEl = document.getElementById('anno-tag-empty');
  const suggestToggle = document.getElementById('anno-suggest-toggle');
  const noteCharsEl = document.getElementById('anno-note-chars');

  // On method/class switch: collapse section editors, but keep the Notes body
  // open if the user left it open (so tags/notes don't "disappear").
  const targetSig = `${target.kind}:${target.key}`;
  if (panel.dataset.targetSig !== targetSig) {
    panel.dataset.targetSig = targetSig;
    collapseAnnoSectionsByDefault(panel);
    if (annoBodyPreferOpen) {
      expandAnnoSectionsWithContent(panel, anno);
    }
  } else if (!panel.dataset.annoBodyInit) {
    panel.dataset.annoBodyInit = '1';
    setAnnoBodyCollapsed(panel, !annoBodyPreferOpen);
  }

  if (scopeEl) {
    scopeEl.textContent = target.kind === 'method' ? 'Method' : 'Class';
    scopeEl.title = target.label;
  }
  const labelEl = panel.querySelector('.anno-label');
  if (labelEl) {
    labelEl.textContent = target.label;
    labelEl.title = target.key;
  }

  renderAnnoHeaderMeta(panel, anno);

  if (tagsCountEl) {
    tagsCountEl.textContent = tags.length
      ? `${tags.length} assigned`
      : 'none';
  }
  if (tagsPreviewEl) {
    tagsPreviewEl.textContent = tags.length ? tags.slice(0, 4).join(', ') + (tags.length > 4 ? '…' : '') : '';
    tagsPreviewEl.title = tags.length ? tags.join(', ') : '';
  }
  if (tagEmptyEl) tagEmptyEl.hidden = tags.length > 0;

  if (tagsEl) {
    tagsEl.innerHTML = tags.map((t) =>
      `<span class="anno-tag" data-tag="${escapeAttr(t)}" title="Click to filter tree by tag:${escapeAttr(t)}">` +
      `<span class="anno-tag-text">${escapeHtml(t)}</span>` +
      `<button type="button" class="anno-tag-remove" title="Remove tag" aria-label="Remove ${escapeAttr(t)}">&times;</button></span>`
    ).join('') +
      `<input type="text" class="anno-tag-input" placeholder="Add tag… (Enter)" maxlength="40" list="anno-tag-datalist" aria-label="Add tag">`;
  }

  // Datalist + optional “All tags” picker from tags used elsewhere in this file
  const allTags = collectAllAnnotationTags();
  let datalist = document.getElementById('anno-tag-datalist');
  if (!datalist) {
    datalist = document.createElement('datalist');
    datalist.id = 'anno-tag-datalist';
    panel.appendChild(datalist);
  }
  datalist.innerHTML = allTags.map((t) => `<option value="${escapeAttr(t)}"></option>`).join('');
  const assignedLower = new Set(tags.map((t) => t.toLowerCase()));
  const otherTags = allTags.filter((t) => !assignedLower.has(t.toLowerCase()));
  if (suggestToggle) {
    suggestToggle.hidden = otherTags.length === 0;
    suggestToggle.textContent = panel.classList.contains('anno-suggestions-open')
      ? 'Hide tags'
      : `All tags (${otherTags.length})`;
  }
  const suggestEl = document.getElementById('anno-tag-suggestions');
  if (suggestEl) {
    if (panel.classList.contains('anno-suggestions-open') && otherTags.length) {
      suggestEl.hidden = false;
      suggestEl.innerHTML =
        `<div class="anno-suggest-hint muted">Tags used elsewhere — click to assign</div>` +
        otherTags.map((t) =>
          `<button type="button" class="anno-suggest-tag" data-suggest-tag="${escapeAttr(t)}">${escapeHtml(t)}</button>`
        ).join('');
    } else {
      suggestEl.hidden = true;
      suggestEl.innerHTML = '';
    }
  }

  if (noteEl && document.activeElement !== noteEl) {
    noteEl.value = anno.note || '';
  }
  const noteText = (document.activeElement === noteEl ? noteEl.value : (anno.note || '')).trim();
  if (noteCharsEl) {
    const len = noteText.length;
    noteCharsEl.textContent = len ? `${len} char${len === 1 ? '' : 's'}` : 'empty';
  }
  if (notePreviewEl) {
    const firstLine = noteText.split(/\r?\n/).find((l) => l.trim()) || '';
    notePreviewEl.textContent = firstLine
      ? (firstLine.length > 56 ? firstLine.slice(0, 55) + '…' : firstLine)
      : '';
    notePreviewEl.title = noteText || '';
  }

  panel.dataset.kind = target.kind;
  panel.dataset.key = target.key;
  syncAnnoPanelCollapsedChrome(panel);
  syncAnnoBookmarkStarButton();
}

function wireAnnotationPanel() {
  const panel = document.getElementById('annotation-panel');
  if (!panel || panel.dataset.wired === '1') return;
  panel.dataset.wired = '1';

  let noteTimer = null;
  const flushNote = (opts) => {
    clearTimeout(noteTimer);
    noteTimer = null;
    persistAnnotationPanel(opts);
    refreshTreeAnnotationBadges();
  };

  panel.addEventListener('click', (e) => {
    const headerTag = e.target.closest('.anno-header-tag[data-tag]');
    if (headerTag) {
      const tag = headerTag.getAttribute('data-tag');
      if (tag && searchInput) {
        searchInput.value = `tag:${tag}`;
        applySearch();
        syncListBookmarksFilterButton();
      }
      return;
    }
    const globalToggle = e.target.closest('#anno-sections-toggle');
    if (globalToggle) {
      const body = panel.querySelector('.anno-body');
      const currentlyHidden = body ? !!body.hidden : panel.classList.contains('anno-sections-collapsed');
      const opening = currentlyHidden;
      annoBodyPreferOpen = opening;
      setAnnoBodyCollapsed(panel, !opening);
      if (opening) {
        const target = currentAnnotationTarget();
        const anno = target ? getAnnotation(target.kind, target.key) : null;
        expandAnnoSectionsWithContent(panel, anno);
      }
      return;
    }
    const starBtn = e.target.closest('#anno-bookmark-star');
    if (starBtn) {
      const target = currentAnnotationTarget();
      if (!target) return;
      toggleBookmark({
        kind: target.kind,
        key: target.key,
        label: target.label,
        className: target.className || (target.kind === 'class' ? target.key : ''),
        methodName: target.methodName || '',
      });
      return;
    }
    const sectionToggle = e.target.closest('.anno-section-toggle');
    if (sectionToggle) {
      const section = sectionToggle.closest('.anno-section');
      if (!section) return;
      const next = section.dataset.collapsed !== 'true';
      setAnnoSectionCollapsed(section, next);
      if (next) {
        panel.classList.remove('anno-note-expanded');
        const expandBtn = panel.querySelector('#anno-note-expand');
        if (expandBtn) {
          expandBtn.setAttribute('aria-expanded', 'false');
          expandBtn.textContent = 'Expand';
        }
      } else if (section.classList.contains('anno-note-section')) {
        requestAnimationFrame(() => panel.querySelector('.anno-note')?.focus());
      } else if (section.classList.contains('anno-tags-section')) {
        requestAnimationFrame(() => panel.querySelector('.anno-tag-input')?.focus());
      }
      syncAnnoPanelCollapsedChrome(panel);
      return;
    }
    const suggestToggle = e.target.closest('#anno-suggest-toggle');
    if (suggestToggle) {
      panel.classList.toggle('anno-suggestions-open');
      refreshAnnotationUi();
      return;
    }
    const suggestTag = e.target.closest('[data-suggest-tag]');
    if (suggestTag) {
      const tag = suggestTag.getAttribute('data-suggest-tag') || '';
      const kind = panel.dataset.kind;
      const key = panel.dataset.key;
      if (!tag || !kind || !key) return;
      const noteEl = panel.querySelector('.anno-note');
      const cur = getAnnotation(kind, key);
      const tags = [...(cur?.tags || [])];
      if (!tags.some((t) => t.toLowerCase() === tag.toLowerCase())) tags.push(tag);
      const note = noteEl ? noteEl.value : (cur?.note || '');
      const ok = setAnnotation(kind, key, { note, tags });
      setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
      refreshAnnotationUi();
      return;
    }
    const expandBtn = e.target.closest('#anno-note-expand');
    if (expandBtn) {
      const noteSection = panel.querySelector('.anno-note-section');
      if (noteSection?.dataset.collapsed === 'true') {
        setAnnoSectionCollapsed(noteSection, false);
        syncAnnoPanelCollapsedChrome(panel);
      }
      const expanded = panel.classList.toggle('anno-note-expanded');
      expandBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      expandBtn.textContent = expanded ? 'Collapse' : 'Expand';
      expandBtn.title = expanded ? 'Collapse note editor' : 'Expand note editor';
      panel.querySelector('.anno-note')?.focus();
      return;
    }
    const btn = e.target.closest('.anno-tag-remove');
    if (btn) {
      const tag = btn.closest('.anno-tag')?.dataset?.tag;
      const kind = panel.dataset.kind;
      const key = panel.dataset.key;
      if (!tag || !kind || !key) return;
      // Keep unsaved note from textarea
      const noteEl = panel.querySelector('.anno-note');
      const cur = getAnnotation(kind, key);
      const tags = (cur?.tags || []).filter((t) => t !== tag);
      const note = noteEl ? noteEl.value : (cur?.note || '');
      const ok = setAnnotation(kind, key, { tags, note });
      setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
      refreshAnnotationUi();
      return;
    }
    // Click a tag chip (not the ×) → search methods with that tag
    const chip = e.target.closest('.anno-tag');
    if (chip && !e.target.closest('.anno-tag-remove')) {
      const tag = chip.dataset?.tag;
      if (!tag || !searchInput) return;
      searchInput.value = `tag:${tag}`;
      applySearch();
    }
  });

  const commitTagFromInput = (input) => {
    if (!input) return;
    const kind = panel.dataset.kind;
    const key = panel.dataset.key;
    const tag = input.value.trim();
    if (!tag || !kind || !key) return;
    const noteEl = panel.querySelector('.anno-note');
    const cur = getAnnotation(kind, key);
    const tags = [...(cur?.tags || [])];
    if (!tags.some((t) => t.toLowerCase() === tag.toLowerCase())) tags.push(tag);
    const note = noteEl ? noteEl.value : (cur?.note || '');
    const ok = setAnnotation(kind, key, { note, tags });
    setAnnotationStatus(ok ? 'Saved' : 'Save failed', ok);
    input.value = '';
    refreshAnnotationUi();
    panel.querySelector('.anno-tag-input')?.focus();
  };

  panel.addEventListener('keydown', (e) => {
    const input = e.target.closest('.anno-tag-input');
    if (!input) return;
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      // Strip trailing comma if user typed it
      if (e.key === ',') input.value = input.value.replace(/,+$/, '');
      commitTagFromInput(input);
    }
  });

  panel.addEventListener('focusout', (e) => {
    const input = e.target.closest?.('.anno-tag-input');
    if (!input) return;
    // Defer so click on remove still works
    setTimeout(() => {
      if (panel.contains(document.activeElement) && document.activeElement?.classList?.contains('anno-tag-input')) return;
      if (input.value.trim()) commitTagFromInput(input);
    }, 0);
  });

  const noteEl = panel.querySelector('.anno-note');
  if (noteEl) {
    const syncChars = () => {
      const el = document.getElementById('anno-note-chars');
      if (!el) return;
      const len = noteEl.value.length;
      el.textContent = len ? `${len} char${len === 1 ? '' : 's'}` : '';
    };
    noteEl.addEventListener('input', () => {
      syncChars();
      clearTimeout(noteTimer);
      noteTimer = setTimeout(() => flushNote({ quiet: true, includePendingTag: false }), 350);
    });
    noteEl.addEventListener('blur', () => flushNote({ quiet: false, includePendingTag: false }));
  }

  panel.querySelector('#anno-save-btn')?.addEventListener('click', () => {
    flushNote({ quiet: false, includePendingTag: true });
    refreshAnnotationUi();
  });

  panel.querySelector('#anno-clear-btn')?.addEventListener('click', () => {
    const kind = panel.dataset.kind;
    const key = panel.dataset.key;
    if (!kind || !key) return;
    if (!getAnnotation(kind, key) && !panel.querySelector('.anno-note')?.value?.trim()) return;
    if (!window.confirm('Clear note and tags for this item?')) return;
    clearTimeout(noteTimer);
    const noteEl2 = panel.querySelector('.anno-note');
    if (noteEl2) noteEl2.value = '';
    const ok = clearAnnotation(kind, key);
    setAnnotationStatus(ok ? 'Cleared' : 'Clear failed', ok);
    refreshAnnotationUi();
  });
}

/** Decompiler options (dex-decompiler): mode / SSA, bytecode comments, debug names, deobf. */
let decompileOptions = {
  mode: 'restructure',
  showBytecode: false,
  useDebugNames: true,
  deobf: false,
};

function loadDecompileOptionsFromStorage() {
  try {
    const raw = localStorage.getItem('droid2web-decompile-options');
    if (!raw) return;
    const o = JSON.parse(raw);
    if (o && typeof o === 'object') {
      if (o.mode === 'simple' || o.mode === 'fallback' || o.mode === 'restructure') decompileOptions.mode = o.mode;
      if (typeof o.showBytecode === 'boolean') decompileOptions.showBytecode = o.showBytecode;
      if (typeof o.useDebugNames === 'boolean') decompileOptions.useDebugNames = o.useDebugNames;
      if (typeof o.deobf === 'boolean') decompileOptions.deobf = o.deobf;
    }
  } catch (_) {}
}

function saveDecompileOptionsToStorage() {
  try { localStorage.setItem('droid2web-decompile-options', JSON.stringify(decompileOptions)); } catch (_) {}
}

function syncDecompileOptionsUI() {
  const modeEl = document.getElementById('decompile-mode');
  const showBc = document.getElementById('decompile-show-bytecode');
  const dbg = document.getElementById('decompile-debug-names');
  const deobf = document.getElementById('decompile-deobf');
  if (modeEl) modeEl.value = decompileOptions.mode;
  if (showBc) showBc.checked = !!decompileOptions.showBytecode;
  if (dbg) dbg.checked = !!decompileOptions.useDebugNames;
  if (deobf) deobf.checked = !!decompileOptions.deobf;
}

/** Options object for get_dex_method (renames + decompiler settings). */
function getDexMethodOptions() {
  const hasAny = dexRenamesHasAny();
  const opts = {
    mode: decompileOptions.mode || 'restructure',
    showBytecode: !!decompileOptions.showBytecode,
    useDebugNames: decompileOptions.useDebugNames !== false,
    deobf: !!decompileOptions.deobf,
  };
  if (hasAny) {
    opts.renames = {
      package: dexRenames.package,
      class: dexRenames.class,
      method: dexRenames.method,
      field: dexRenames.field,
      variable: dexRenames.variable,
    };
  }
  if (apkResourceMap && typeof apkResourceMap === 'object') {
    const keys = Object.keys(apkResourceMap);
    if (keys.length) opts.resourceMap = apkResourceMap;
  }
  const extras = collectExtraDexBytesForDecompile();
  if (extras.length) opts.extraDexes = extras;
  return opts;
}

/** Sibling DEX buffers for cross-DEX anonymous/inner inlining (capped). */
function collectExtraDexBytesForDecompile() {
  const extras = [];
  const current = currentDexBytes;
  const maxExtras = 4;
  const maxEach = 24 * 1024 * 1024;
  for (const d of loadedDexFiles || []) {
    if (!d?.bytes?.length) continue;
    if (current && d.bytes === current) continue;
    if (current && d.bytes.length === current.length && d.bytes === current) continue;
    if (d.bytes.length > maxEach) continue;
    extras.push(d.bytes);
    if (extras.length >= maxExtras) break;
  }
  return extras;
}

function getDexRenamesObject() {
  return getDexMethodOptions();
}

/** Load / cache ARSC resource id map for the current APK (best-effort). */
function ensureApkResourceMap() {
  if (apkResourceMap && typeof apkResourceMap === 'object') {
    return Promise.resolve(apkResourceMap);
  }
  if (apkResourceMapPromise) return apkResourceMapPromise;
  if (currentType !== 'apk' || !currentApkBytes?.length) {
    apkResourceMap = {};
    apkResourceValues = {};
    return Promise.resolve(apkResourceMap);
  }
  apkResourceMapPromise = (async () => {
    try {
      const arscBytes = get_apk_file_content(currentApkBytes, 'resources.arsc');
      if (!arscBytes || !arscBytes.length) {
        apkResourceMap = {};
        apkResourceValues = {};
        return apkResourceMap;
      }
      const raw = typeof parse_arsc_resource_tables === 'function'
        ? parse_arsc_resource_tables(arscBytes)
        : null;
      const result = raw && typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
      if (result?.ok && result.data && typeof result.data === 'object') {
        let data = result.data;
        if (typeof normalizeWasmResult === 'function') data = normalizeWasmResult(data) || data;
        const names = data.names || data;
        const values = data.values || {};
        const toObj = (src) => {
          if (src instanceof Map) {
            const obj = {};
            for (const [k, v] of src) obj[String(k)] = String(v);
            return obj;
          }
          return src && typeof src === 'object' ? src : {};
        };
        apkResourceMap = toObj(names);
        apkResourceValues = toObj(values);
      } else {
        // Fallback: names-only map (older wasm)
        const rawMap = parse_arsc_resource_map(arscBytes);
        const mapResult = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(rawMap) : rawMap;
        if (mapResult?.ok && mapResult.data && typeof mapResult.data === 'object') {
          let data = mapResult.data;
          if (typeof normalizeWasmResult === 'function') data = normalizeWasmResult(data) || data;
          apkResourceMap = data instanceof Map
            ? Object.fromEntries([...data].map(([k, v]) => [String(k), String(v)]))
            : data;
        } else {
          apkResourceMap = {};
        }
        apkResourceValues = {};
      }
    } catch (_) {
      apkResourceMap = {};
      apkResourceValues = {};
    }
    return apkResourceMap;
  })();
  return apkResourceMapPromise;
}

function clearApkResourceMap() {
  apkResourceMap = null;
  apkResourceValues = null;
  apkResourceMapPromise = null;
  clearInfoResourceThumbUrls();
}

/** Blob URLs for Info-panel resource thumbnails (icons, etc.). */
let infoResourceThumbUrls = [];
function clearInfoResourceThumbUrls() {
  for (const u of infoResourceThumbUrls) {
    try { URL.revokeObjectURL(u); } catch (_) {}
  }
  infoResourceThumbUrls = [];
}

loadDecompileOptionsFromStorage();

(function wireDecompileOptionsUI() {
  const modeEl = document.getElementById('decompile-mode');
  const showBc = document.getElementById('decompile-show-bytecode');
  const dbg = document.getElementById('decompile-debug-names');
  const deobf = document.getElementById('decompile-deobf');
  syncDecompileOptionsUI();
  function onChange() {
    if (modeEl) decompileOptions.mode = modeEl.value || 'restructure';
    if (showBc) decompileOptions.showBytecode = !!showBc.checked;
    if (dbg) decompileOptions.useDebugNames = !!dbg.checked;
    if (deobf) decompileOptions.deobf = !!deobf.checked;
    saveDecompileOptionsToStorage();
    invalidateCurrentMethodAndRefresh();
  }
  modeEl?.addEventListener('change', onChange);
  showBc?.addEventListener('change', onChange);
  dbg?.addEventListener('change', onChange);
  deobf?.addEventListener('change', onChange);
})();

/** DEX method name for rename / storage keys (`<init>`, not the display ctor name). */
function getDexMethodRawName(method) {
  if (!method) return '';
  const raw = (method.dexName || method.dex_name || '').trim();
  if (raw) return raw;
  return method.name || '';
}

function methodRenameKey(className, methodOrName) {
  if (!className) return '';
  if (methodOrName && typeof methodOrName === 'object') {
    const raw = getDexMethodRawName(methodOrName);
    return raw ? `${className}#${raw}` : '';
  }
  const name = (methodOrName || '').trim();
  return name ? `${className}#${name}` : '';
}

/** Display name for class (renamed if set). */
function getDisplayClassName(className) {
  return (className && dexRenames.class[className]) || className || '';
}

/** Display name for method (renamed if set). Key is original className#dexMethodName. */
function getDisplayMethodName(className, methodName) {
  if (!className || !methodName) return methodName || '';
  const direct = dexRenames.method[className + '#' + methodName];
  if (direct) return direct;
  // After fetch, constructors are shown as the simple class name but rename keys use <init>.
  if (methodName !== '<init>') {
    const simple = className.split('.').pop();
    if (methodName === simple) {
      const ctor = dexRenames.method[className + '#<init>'];
      if (ctor) return ctor;
    }
  }
  return methodName;
}

/** Display name for field (renamed if set). Key is original className#fieldName. */
function getDisplayFieldName(className, fieldName) {
  if (!className || !fieldName) return fieldName || '';
  return dexRenames.field[className + '#' + fieldName] || fieldName || '';
}

/** Shorten Java type for tree/meta (`java.lang.String` → `String`). */
function shortJavaType(typ) {
  const t = String(typ || '').trim();
  if (!t) return '';
  let dims = '';
  let base = t;
  while (base.endsWith('[]')) {
    dims += '[]';
    base = base.slice(0, -2);
  }
  const simple = base.includes('.') ? base.split('.').pop() : base;
  return (simple || base) + dims;
}

/** Java field declaration line (modifiers + type + name [= init]). */
function formatFieldDeclaration(f, className) {
  if (!f) return '';
  const cn = className || f.class_name || f.className || '';
  const name = getDisplayFieldName(cn, f.name || '') || (f.name || '?');
  const typ = f.type || f.typ || '?';
  const mods = String(f.modifiers || '').trim();
  const init = f.initial_value ?? f.initialValue;
  const head = `${mods ? mods + ' ' : ''}${typ} ${name}`;
  return init != null && String(init) !== '' ? `${head} = ${init};` : `${head};`;
}

/** Source pane text for all fields of a class. */
function formatClassFieldsSource(classIdx) {
  const ctx = getCodeViewContext();
  const cl = ctx?.classes?.[classIdx];
  const fields = Array.isArray(cl?.fields) ? cl.fields : [];
  if (!fields.length) return '';
  return fields
    .filter((f) => {
      const n = f?.name || '';
      return n !== 'this$0' && !n.startsWith('val$');
    })
    .map((f) => formatFieldDeclaration(f, cl?.name || ''))
    .join('\n');
}

function isValidJavaSimpleName(name) {
  return typeof name === 'string' && /^[A-Za-z_][\w]*$/.test(name.trim());
}

function isValidJavaClassName(name) {
  return typeof name === 'string' && /^[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*$/.test(name.trim());
}

/** Apply method rename to decompiled Java source so the displayed name matches the bytecode. */
function applyMethodRenameToDecompilation(decompilation, originalName, displayName) {
  if (!decompilation || typeof decompilation !== 'string') return decompilation || '';
  if (!originalName || originalName === displayName) return decompilation;
  const escaped = String(originalName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return decompilation.replace(new RegExp('\\b' + escaped + '\\s*\\(', 'g'), displayName + '(');
}

/** Update left-tree labels after a rename without a full re-render. */
function refreshTreeRenameLabels() {
  const ctx = getCodeViewContext();
  const classes = ctx?.classes || (currentType === 'dex' ? currentData?.classes : null);
  if (!classes || !treeContent) return;
  treeContent.querySelectorAll('.tree-item.class').forEach((el) => {
    const idx = parseInt(el.dataset.class, 10);
    if (Number.isNaN(idx)) return;
    const full = classes[idx]?.name || '';
    const short = (getDisplayClassName(full).split('.').filter(Boolean).pop()) || '?';
    const arrow = el.querySelector('.arrow');
    const label = el.querySelector('.tree-item-label');
    const count = el.querySelector('.tree-count');
    const star = el.querySelector('.tree-bookmark-star');
    const anno = el.querySelector('.tree-anno');
    if (label) label.textContent = short;
    else {
      const kids = [];
      if (arrow) kids.push(arrow);
      const lab = document.createElement('span');
      lab.className = 'tree-item-label';
      lab.textContent = short;
      kids.push(lab);
      if (count) {
        kids.push(document.createTextNode(' '));
        kids.push(count);
      }
      if (star) kids.push(star);
      if (anno) kids.push(anno);
      el.replaceChildren(...kids);
    }
  });
  treeContent.querySelectorAll('.tree-item.method').forEach((el) => {
    const ci = parseInt(el.dataset.class, 10);
    const mi = parseInt(el.dataset.method, 10);
    if (Number.isNaN(ci) || Number.isNaN(mi)) return;
    const cn = classes[ci]?.name || '';
    const mn = classes[ci]?.methods?.[mi]?.name || '';
    const label = el.querySelector('.tree-item-label');
    if (label) label.textContent = getDisplayMethodName(cn, mn);
    else el.textContent = getDisplayMethodName(cn, mn);
  });
  refreshTreeAnnotationBadges();
  refreshBookmarksUi();
}

/** Invalidate decompilation cache, refresh code + tree. Call saveDexRenamesToStorage separately or via commitDexRenamesChange. */
function invalidateCurrentMethodAndRefresh(opts = {}) {
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  if (classes) {
    const clearMethod = (m) => {
      if (!m) return;
      m.decompilation = '';
      m.bytecode = [];
    };
    if (opts.allClasses) {
      classes.forEach((c) => (c.methods || []).forEach(clearMethod));
    } else {
      const classIdx = codeViewClassIdx;
      if (codeViewMethodIdx !== null && !opts.wholeClass) {
        clearMethod(classes[classIdx]?.methods?.[codeViewMethodIdx]);
      } else {
        (classes[classIdx]?.methods || []).forEach(clearMethod);
      }
    }
  }
  updateCodeView();
  refreshTreeRenameLabels();
}

function commitDexRenamesChange(opts = {}) {
  saveDexRenamesToStorage();
  invalidateCurrentMethodAndRefresh(opts);
}

function promptRename(kind, currentValue) {
  const label = kind === 'class' ? 'New class name (full, e.g. com.example.Main):'
    : kind === 'method' ? 'New method name:'
    : kind === 'field' ? 'New field name:'
    : 'New variable name:';
  const next = prompt(label, currentValue || '');
  if (next == null) return null;
  const trimmed = next.trim();
  if (!trimmed) return null;
  if (kind === 'class') {
    if (!isValidJavaClassName(trimmed)) {
      alert('Invalid class name. Use a dotted Java identifier (e.g. com.example.Main).');
      return null;
    }
  } else if (!isValidJavaSimpleName(trimmed)) {
    alert('Invalid name. Use a Java identifier (letters, digits, _, starting with a letter or _).');
    return null;
  }
  return trimmed;
}

/** One-off context menu for "Rename class/method/variable". Items: [{ label, onChoose }]. */
let renameContextMenu = null;
function getRenameContextMenu() {
  if (renameContextMenu) return renameContextMenu;
  renameContextMenu = document.createElement('div');
  renameContextMenu.className = 'context-menu';
  renameContextMenu.setAttribute('role', 'menu');
  renameContextMenu.style.display = 'none';
  document.body.appendChild(renameContextMenu);
  const hide = () => { renameContextMenu.style.display = 'none'; };
  document.addEventListener('click', hide, true);
  document.addEventListener('scroll', hide, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); }, true);
  return renameContextMenu;
}

function showRenameContextMenu(clientX, clientY, label, onChoose) {
  showRenameContextMenuMultiple(clientX, clientY, [{ label, onChoose }]);
}

function showRenameContextMenuMultiple(clientX, clientY, items) {
  const menu = getRenameContextMenu();
  menu.innerHTML = '';
  items.forEach(({ label, onChoose }) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'context-menu-item';
    item.setAttribute('role', 'menuitem');
    item.textContent = label;
    item.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      menu.style.display = 'none';
      onChoose();
    };
    menu.appendChild(item);
  });
  menu.style.left = clientX + 'px';
  menu.style.top = clientY + 'px';
  menu.style.display = 'block';
  requestAnimationFrame(() => {
    const r = menu.getBoundingClientRect();
    if (r.right > window.innerWidth) menu.style.left = (window.innerWidth - r.width) + 'px';
    if (r.bottom > window.innerHeight) menu.style.top = (window.innerHeight - r.height) + 'px';
  });
}

/** Get word at coordinates in element (for variable rename in source). Prefer `.src-ident` when present. */
function getWordAtPoint(element, x, y) {
  const hit = document.elementFromPoint?.(x, y);
  if (hit && element.contains(hit)) {
    const ident = hit.closest?.('.src-ident');
    if (ident && element.contains(ident)) {
      const fromData = (ident.getAttribute('data-ident') || ident.textContent || '').trim();
      if (fromData && /^[A-Za-z_$][\w$]*$/.test(fromData)) return fromData;
    }
  }
  let range = null;
  if (document.caretRangeFromPoint) {
    range = document.caretRangeFromPoint(x, y);
  } else if (document.caretPositionFromPoint) {
    const pos = document.caretPositionFromPoint(x, y);
    if (pos) {
      range = document.createRange();
      range.setStart(pos.offsetNode, pos.offset);
      range.collapse(true);
    }
  }
  if (!range || !element.contains(range.startContainer)) return '';
  const text = element.innerText || element.textContent || '';
  let offset = 0;
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let n = walker.nextNode();
  while (n) {
    if (n === range.startContainer) { offset += range.startOffset; break; }
    offset += n.textContent.length;
    n = walker.nextNode();
  }
  const isIdentChar = (c) => c && /[A-Za-z0-9_$]/.test(c);
  let i = offset;
  while (i > 0 && isIdentChar(text[i - 1])) i--;
  let j = offset;
  while (j < text.length && isIdentChar(text[j])) j++;
  const word = text.slice(i, j).trim();
  if (!word || !/^[A-Za-z_$]/.test(word)) return '';
  return word;
}

/** Resolve variable rename map entry for a displayed or original name. */
function resolveVariableRenameEntry(methodKey, word) {
  const map = dexRenames.variable[methodKey];
  if (!map || !word) return { orig: word, current: null };
  if (Object.prototype.hasOwnProperty.call(map, word)) {
    return { orig: word, current: map[word] };
  }
  for (const [k, v] of Object.entries(map)) {
    if (v === word) return { orig: k, current: v };
  }
  return { orig: word, current: null };
}

function setVariableRename(methodKey, word, newName) {
  if (!methodKey || !word || !newName) return;
  if (!dexRenames.variable[methodKey]) dexRenames.variable[methodKey] = {};
  const map = dexRenames.variable[methodKey];
  const { orig } = resolveVariableRenameEntry(methodKey, word);
  // Drop a mistaken entry keyed by the display name if we remapped via original.
  if (orig !== word && Object.prototype.hasOwnProperty.call(map, word) && map[word] !== newName) {
    delete map[word];
  }
  map[orig] = newName;
}

function clearVariableRename(methodKey, word) {
  const map = dexRenames.variable[methodKey];
  if (!map || !word) return;
  const { orig } = resolveVariableRenameEntry(methodKey, word);
  delete map[orig];
  if (Object.prototype.hasOwnProperty.call(map, word)) delete map[word];
  if (!Object.keys(map).length) delete dexRenames.variable[methodKey];
}

/** Currently highlighted identifier in the source pane (hover-to-find-usages). */
let sourceIdentHighlight = null;
/** Scope element that currently has hover-ident classes applied. */
let sourceIdentHoverScope = null;
/** Sticky (click-pinned) identifier; survives mouseleave until cleared. */
let sourceIdentPinned = null;

function clearSourceIdentHighlights(root = sourceCode) {
  if (!root) return;
  root.querySelectorAll('.src-ident.is-hl, .src-ident.is-hl-primary').forEach((el) => {
    el.classList.remove('is-hl', 'is-hl-primary');
  });
  root.querySelectorAll('[data-hl-ident]').forEach((el) => {
    delete el.dataset.hlIdent;
  });
  // Legacy mark cleanup (from older click-highlight)
  root.querySelectorAll('mark.src-ident-hit').forEach((m) => {
    const parent = m.parentNode;
    if (!parent) return;
    while (m.firstChild) parent.insertBefore(m.firstChild, m);
    parent.removeChild(m);
    parent.normalize();
  });
  if (sourceIdentHoverScope && (root === sourceCode || root.contains(sourceIdentHoverScope))) {
    sourceIdentHoverScope = null;
  }
}

/**
 * Wrap Java identifiers in `.src-ident` spans once per render so hover can
 * highlight every usage without rebuilding the DOM on each mousemove.
 */
function wrapSourceIdents(root) {
  if (!root || root.dataset.identsWrapped === '1') return;
  const skipSel = [
    '.src-comment', '.src-string', '.token.comment', '.token.string', '.token.char',
    '.src-line-no', '.src-fold-btn', '.src-ident', '.src-api', '.src-keyword', '.src-number',
    'mark.source-search-hit',
  ].join(', ');
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || !/[A-Za-z_$]/.test(node.nodeValue)) return NodeFilter.FILTER_REJECT;
      if (node.parentElement?.closest(skipSel)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);

  const re = /[A-Za-z_$][A-Za-z0-9_$]*/g;
  for (const textNode of textNodes) {
    const text = textNode.nodeValue;
    re.lastIndex = 0;
    if (!re.test(text)) continue;
    re.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
      const name = m[0];
      if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
      if (typeof JAVA_KEYWORDS !== 'undefined' && JAVA_KEYWORDS.has(name)) {
        frag.appendChild(document.createTextNode(name));
      } else {
        const span = document.createElement('span');
        span.className = 'src-ident';
        span.dataset.ident = name;
        span.textContent = name;
        frag.appendChild(span);
      }
      last = m.index + name.length;
    }
    if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
    textNode.parentNode?.replaceChild(frag, textNode);
  }
  root.dataset.identsWrapped = '1';
}

function setSourceIdentHover(ident, scope, primaryEl = null) {
  if (!scope) return;
  // Pinned selection wins over transient hover of a different name
  if (sourceIdentPinned && ident && ident !== sourceIdentPinned) {
    return;
  }
  if (sourceIdentPinned && !ident) {
    return;
  }
  if (sourceIdentHoverScope && sourceIdentHoverScope !== scope) {
    clearSourceIdentHighlights(sourceIdentHoverScope);
  }
  if (sourceIdentHoverScope === scope && sourceIdentHighlight === ident) {
    // Just update primary
    scope.querySelectorAll('.src-ident.is-hl-primary').forEach((el) => el.classList.remove('is-hl-primary'));
    primaryEl?.classList.add('is-hl-primary');
    return;
  }
  clearSourceIdentHighlights(scope);
  sourceIdentHoverScope = scope;
  sourceIdentHighlight = ident || null;
  if (!ident) return;
  scope.dataset.hlIdent = ident;
  let sel;
  try {
    sel = `.src-ident[data-ident="${CSS.escape(ident)}"]`;
  } catch (_) {
    sel = `.src-ident[data-ident="${ident.replace(/"/g, '\\"')}"]`;
  }
  scope.querySelectorAll(sel).forEach((el) => el.classList.add('is-hl'));
  primaryEl?.classList.add('is-hl-primary');
}

function pinSourceIdent(ident, scope, primaryEl = null) {
  if (!scope || !ident) return;
  if (sourceIdentPinned === ident && sourceIdentHoverScope === scope) {
    // Toggle off
    sourceIdentPinned = null;
    clearSourceIdentHighlights(scope);
    sourceIdentHighlight = null;
    sourceIdentHoverScope = null;
    return;
  }
  sourceIdentPinned = ident;
  setSourceIdentHover(ident, scope, primaryEl);
}

function clearPinnedSourceIdent() {
  sourceIdentPinned = null;
  if (sourceCode) clearSourceIdentHighlights(sourceCode);
  sourceIdentHighlight = null;
  sourceIdentHoverScope = null;
}

function restoreSourceIdentHighlight() {
  if (!sourceCode) return;
  // Re-wrap after each render; innerHTML replace leaves dataset on #source-code,
  // so always clear the flag or new content never gets `.src-ident` spans.
  sourceIdentHighlight = null;
  sourceIdentHoverScope = null;
  sourceIdentPinned = null;
  delete sourceCode.dataset.identsWrapped;
  wrapSourceIdents(sourceCode);
}

/** Raw source string for the Code tab source pane (for search + re-highlight). */
let currentSourceRaw = '';
/** When showing "All methods", array of { classIdx, methodIdx, name, raw } for each method block (used to render wrapped blocks and resolve method from click). */
let currentSourceBlocks = null;
/** Single-method source chrome: { classIdx, methodIdx, name }. */
let currentSourceMethodMeta = null;
/** Source pane search term and current match index for prev/next. */
let sourceSearchQuery = '';
let sourceSearchMatchIndex = 0;
let sourceSearchMatches = [];
/** Cached APK AndroidManifest.xml text so we can restore it when viewing non-AXML files. */
let apkManifestXml = null;
/** Last blob URL for APK-extracted image; revoked when switching file so we don't revoke before img loads. */
let lastApkImageBlobUrl = null;
/** Open file tabs in APK: each entry is { id, name, kind, data?, bytes? }. Each has its own tab with name + close. */
let apkOpenFileTabs = [];
let apkFileTabCounter = 0;
/** Blob URLs per file tab id (for revoke on close). */
let apkFileTabBlobUrls = {};
/** Cached parsed APK files by name so we don't re-parse when reselecting. Cleared when APK changes. */
let apkFileCache = {};
/** Raw bytes for the currently extracted file (avoids repeated get_apk_file_content for Raw tab). */
let apkExtractedFileRawBytes = null;
/** Map full class name -> { file: dexFileName, classIdx } for manifest class links. Built when APK is loaded. */
let apkClassToDex = {};
/**
 * Package → unique class entries (same objects as apkClassToDex values).
 * Built incrementally during indexing so the UI never walks Object.values(apkClassToDex)
 * (Facebook: ~180k classes + aliases ≈ 300k+ map keys → multi-second freezes).
 */
let apkClassesByPackage = Object.create(null);
/** Cached package→count for the unfiltered All-DEXes dropdown (invalidated on index/filter toggle). */
let apkPackageCountsCache = null;
let apkClassIndexPromise = null;
/** permission → [{ class_name, method_name, offset, dex_file, string_index }] */
let apkPermissionUsageIndex = null;
let apkPermissionUsagePromise = null;
let apkPermissionUsageStatus = ''; // '', 'loading', 'ready', 'error'
/** APK-wide DEX class/method totals (from buildApkClassIndex). */
let apkDexStats = { dexFiles: 0, classes: 0, methods: 0, ready: false, totalDex: 0, current: 0, currentName: '' };

/**
 * Background UI activity shown in the bottom status bar so long work never looks "stuck".
 * Map id → { text, detail? }
 */
const uiActivityTasks = new Map();
let statusBarUpdateTimer = 0;
let statusBarUpdateForced = false;

function scheduleStatusBarUpdate(force = false) {
  if (force) statusBarUpdateForced = true;
  if (statusBarUpdateTimer) return;
  statusBarUpdateTimer = setTimeout(() => {
    statusBarUpdateTimer = 0;
    const forceNow = statusBarUpdateForced;
    statusBarUpdateForced = false;
    updateStatusBar(forceNow);
  }, force ? 0 : 120);
}

function setUiActivity(id, text, detail = '') {
  if (!id) return;
  const key = String(id);
  const prev = uiActivityTasks.get(key);
  const t = nowMs();
  // Record when the step label changes (ignore detail-only progress spam).
  if (prev && prev._t0 != null && prev.text !== text) {
    recordPerf(`ui:${prev.text}`, t - prev._t0, prev.detail || '');
  }
  uiActivityTasks.set(key, {
    text: String(text || ''),
    detail: detail ? String(detail) : '',
    at: Date.now(),
    _t0: prev && prev.text === text ? prev._t0 : t,
  });
  scheduleStatusBarUpdate();
}

function clearUiActivity(id) {
  if (!id) return;
  const key = String(id);
  const prev = uiActivityTasks.get(key);
  if (prev && prev._t0 != null) {
    recordPerf(`ui:${prev.text}`, nowMs() - prev._t0, prev.detail || '');
  }
  if (uiActivityTasks.delete(key)) scheduleStatusBarUpdate(true);
}

function clearAllUiActivity() {
  if (uiActivityTasks.size) {
    uiActivityTasks.clear();
    scheduleStatusBarUpdate(true);
  }
  setWorkNotice(null);
}

/**
 * Left-panel notice for heavy in-browser work.
 * Explains brief freezes so large APK loads don't look "stuck".
 * @param {string|null} title  null/'' clears
 * @param {string} [body]
 * @param {{ tone?: 'info'|'warn'|'ok', sticky?: boolean, autoHideMs?: number }} [opts]
 */
let workNoticeHideTimer = 0;
function setWorkNotice(title, body = '', opts = {}) {
  const el = document.getElementById('work-notice');
  if (!el) return;
  if (workNoticeHideTimer) {
    clearTimeout(workNoticeHideTimer);
    workNoticeHideTimer = 0;
  }
  if (!title) {
    el.hidden = true;
    el.innerHTML = '';
    el.classList.remove('is-warn', 'is-ok');
    return;
  }
  const tone = opts.tone || 'info';
  el.classList.toggle('is-warn', tone === 'warn');
  el.classList.toggle('is-ok', tone === 'ok');
  const dismiss = opts.sticky
    ? ''
    : '<button type="button" class="work-notice-dismiss" title="Dismiss" aria-label="Dismiss">×</button>';
  el.innerHTML = `${dismiss}<span class="work-notice-title">${escapeHtml(title)}</span>`
    + (body ? `<span class="work-notice-body">${escapeHtml(body)}</span>` : '');
  el.hidden = false;
  const btn = el.querySelector('.work-notice-dismiss');
  if (btn) {
    btn.onclick = () => setWorkNotice(null);
  }
  const hideMs = opts.autoHideMs != null ? opts.autoHideMs : (opts.sticky ? 0 : 10000);
  if (hideMs > 0) {
    workNoticeHideTimer = setTimeout(() => setWorkNotice(null), hideMs);
  }
}

/** True when this APK is large enough that indexing can hitch the UI. */
function isLargeApkWorkload() {
  const n = Number(apkDexStats?.classes) || 0;
  const dex = Number(apkDexStats?.totalDex) || listApkDexNames().length || 0;
  return n >= 40000 || dex >= 8;
}

function shortDexLabel(name) {
  const n = String(name || '');
  if (!n) return 'DEX';
  const slash = n.lastIndexOf('/');
  return slash >= 0 ? n.slice(slash + 1) : n;
}

// DOM
const fileInput = document.getElementById('file-input');
const btnUpload = document.getElementById('btn-upload');
const fileName = document.getElementById('file-name');
const statusbarInner = document.getElementById('statusbar-inner');
const leftPanelTitle = document.getElementById('left-panel-title');
const treePlaceholder = document.getElementById('tree-placeholder');
const treeContent = document.getElementById('tree-content');
const listSearchWrap = document.getElementById('list-search-wrap');

/** One-time delegated click handler for tree ★ bookmarks (survives re-renders). */
function wireTreeBookmarkStars() {
  if (!treeContent || treeContent.dataset.bmWired === '1') return;
  treeContent.dataset.bmWired = '1';
  treeContent.addEventListener('click', (e) => {
    const btn = e.target.closest('.tree-bookmark-star');
    if (!btn || !treeContent.contains(btn)) return;
    e.preventDefault();
    e.stopPropagation();
    const kind = btn.getAttribute('data-bm-kind');
    const classIdx = parseInt(btn.getAttribute('data-class'), 10);
    if (!kind || Number.isNaN(classIdx)) return;
    const ctx = getCodeViewContext();
    const classes = ctx?.classes || (currentType === 'dex' ? currentData?.classes : null);
    if (!classes?.[classIdx]) return;
    const className = classes[classIdx].name || '';
    let methodName = '';
    let key = className;
    let label = getDisplayClassName(className);
    if (kind === 'method') {
      const methodIdx = parseInt(btn.getAttribute('data-method'), 10);
      methodName = classes[classIdx].methods?.[methodIdx]?.name || '';
      key = methodAnnotationKey(className, methodName);
      label = (getDisplayClassName(className).split('.').pop() || className) + '.' + getDisplayMethodName(className, methodName);
    }
    toggleBookmark({ kind, key, label, className, methodName });
  });
}
const dexFileWrap = document.getElementById('dex-file-wrap');
const dexFileSelect = document.getElementById('dex-file-select');
const dexPackageWrap = document.getElementById('dex-package-wrap');
const dexPackageSelect = document.getElementById('dex-package-select');
const bytecodeListing = document.getElementById('bytecode-listing');
const cfgGraphContainer = document.getElementById('cfg-graph-container');
const cfgHtmlLayer = document.getElementById('cfg-html-layer');
const cfgGraphWrap = document.getElementById('cfg-graph-wrap');

/* Single wheel path for the whole CFG viewport (empty canvas + HTML blocks). */
if (cfgGraphWrap) {
  cfgGraphWrap.addEventListener('wheel', (e) => {
    if (!cfgNetwork) return;
    const body = e.target.closest?.('.cfg-block-body');
    if (body && body.scrollHeight > body.clientHeight + 1) {
      const atTop = body.scrollTop <= 0;
      const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 1;
      // Only keep the event for real in-body scrolling
      if (!((e.deltaY < 0 && atTop) || (e.deltaY > 0 && atBottom))) {
        return;
      }
    }
    e.preventDefault();
    e.stopPropagation();
    zoomCfgGraph(cfgWheelZoomFactor(e), e);
  }, { capture: true, passive: false });

  /* Middle-button (wheel click) long-press → pan/navigate the CFG. */
  const CFG_MIDDLE_LONG_MS = 180;
  let cfgMiddlePan = null;

  function endCfgMiddlePan() {
    if (!cfgMiddlePan) return;
    if (cfgMiddlePan.timer) clearTimeout(cfgMiddlePan.timer);
    cfgGraphWrap.classList.remove('cfg-panning');
    cfgMiddlePan = null;
  }

  function activateCfgMiddlePan() {
    if (!cfgMiddlePan || cfgMiddlePan.active || !cfgNetwork) return;
    cfgMiddlePan.active = true;
    cfgGraphWrap.classList.add('cfg-panning');
  }

  cfgGraphWrap.addEventListener('mousedown', (e) => {
    if (e.button !== 1 || !cfgNetwork) return;
    // Prevent browser autoscroll / middle-click paste
    e.preventDefault();
    e.stopPropagation();
    let view;
    let scale;
    try {
      view = cfgNetwork.getViewPosition();
      scale = cfgNetwork.getScale();
    } catch (_) {
      return;
    }
    if (!view || !Number.isFinite(scale) || scale <= 0) return;
    endCfgMiddlePan();
    cfgMiddlePan = {
      startX: e.clientX,
      startY: e.clientY,
      viewX: view.x,
      viewY: view.y,
      scale,
      active: false,
      timer: setTimeout(activateCfgMiddlePan, CFG_MIDDLE_LONG_MS),
    };
  }, { capture: true });

  cfgGraphWrap.addEventListener('auxclick', (e) => {
    if (e.button === 1) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, { capture: true });

  window.addEventListener('mousemove', (e) => {
    if (!cfgMiddlePan || !cfgNetwork) return;
    const dx = e.clientX - cfgMiddlePan.startX;
    const dy = e.clientY - cfgMiddlePan.startY;
    // Start pan early if the user drags before the long-press timer fires
    if (!cfgMiddlePan.active) {
      if (Math.hypot(dx, dy) < 5) return;
      if (cfgMiddlePan.timer) {
        clearTimeout(cfgMiddlePan.timer);
        cfgMiddlePan.timer = null;
      }
      activateCfgMiddlePan();
    }
    e.preventDefault();
    const scale = cfgMiddlePan.scale || 1;
    try {
      cfgNetwork.moveTo({
        position: {
          x: cfgMiddlePan.viewX - dx / scale,
          y: cfgMiddlePan.viewY - dy / scale,
        },
        scale,
        animation: false,
      });
      syncCfgHtmlOverlay();
    } catch (_) {}
  }, { passive: false });

  window.addEventListener('mouseup', (e) => {
    if (e.button === 1) endCfgMiddlePan();
  });
  window.addEventListener('blur', endCfgMiddlePan);
}
const cfgGraphEmpty = document.getElementById('cfg-graph-empty');
const cfgMeta = document.getElementById('cfg-meta');
const cfgLegend = document.getElementById('cfg-legend');
const bytecodeColHeader = document.getElementById('bytecode-col-header');
/** vis-network instance for per-method CFG (destroyed on method change). */
let cfgNetwork = null;
let cfgNetworkDrawHandler = null;
/** Custom orthogonal edge draw state (canvas polylines with sharp 90° corners). */
let cfgOrthoEdgeState = null;
let cfgCompactLabels = false;
/** When false, CFG insn lines omit address + hex columns (mnemonic/operands only). */
let cfgShowAddr = true;
let cfgHighlightBlockId = null;

/* ── Per-method CFG layout / triage (positions, read, notes, color) ───────────── */
const CFG_STATE_KEY = 'droid2web-cfg-state-v1';
const CFG_STATE_MAX_CHARS = 1_500_000;
/** Named highlight colors for CFG blocks (persisted as id). */
const CFG_BLOCK_COLOR_PRESETS = [
  { id: 'red', hex: '#d85050', label: 'Red' },
  { id: 'orange', hex: '#dda95b', label: 'Orange' },
  { id: 'yellow', hex: '#dcdcaa', label: 'Yellow' },
  { id: 'green', hex: '#b8d7a3', label: 'Green' },
  { id: 'cyan', hex: '#4ec9b0', label: 'Cyan' },
  { id: 'blue', hex: '#569cd6', label: 'Blue' },
  { id: 'purple', hex: '#c563bd', label: 'Purple' },
  { id: 'pink', hex: '#ce9178', label: 'Pink' },
];
const CFG_BLOCK_COLOR_IDS = new Set(CFG_BLOCK_COLOR_PRESETS.map((c) => c.id));
/** In-memory map for the current method: startOffset → { x?, y?, read?, note?, color? } */
let cfgMethodBlockState = {};
/** Active HTML-overlay block drag (canvas coords). */
let cfgBlockDragSession = null;
/** Open color-picker popover element (if any). */
let cfgColorPopover = null;

function cfgStateFileFingerprint() {
  try {
    return annotationsStorageFingerprint() || securityFileFingerprint() || '';
  } catch (_) {
    return '';
  }
}

function cfgCurrentDexLabel() {
  if (currentType === 'apk' && apkExtractedFile?.name) return apkExtractedFile.name;
  if (loadedDexFiles?.length && activeDexIndex != null && loadedDexFiles[activeDexIndex]?.name) {
    return loadedDexFiles[activeDexIndex].name;
  }
  return currentFilename || '';
}

function cfgMethodStorageKey(className, methodName, descriptor = '', dexName = '') {
  const dex = dexName || cfgCurrentDexLabel();
  const desc = descriptor || '';
  return `${dex}|${className || ''}#${methodName || ''}|${desc}`;
}

function cfgCurrentMethodStorageKey() {
  const ctx = getCodeViewContext();
  if (!ctx || codeViewMethodIdx == null) return '';
  const cls = ctx.classes[codeViewClassIdx];
  const m = cls?.methods?.[codeViewMethodIdx];
  if (!cls?.name || !m?.name) return '';
  return cfgMethodStorageKey(cls.name, m.name, m.descriptor || m.sig || '', cfgCurrentDexLabel());
}

function readCfgStateStore() {
  try {
    const raw = localStorage.getItem(CFG_STATE_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeCfgStateStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > CFG_STATE_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > CFG_STATE_MAX_CHARS && keys.length > 1) {
        delete store.entries[keys.shift().k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(CFG_STATE_KEY, json);
    return true;
  } catch (e) {
    warn('cfg state write failed', e);
    return false;
  }
}

function normalizeCfgBlockColor(raw) {
  const id = String(raw || '').trim().toLowerCase();
  return CFG_BLOCK_COLOR_IDS.has(id) ? id : '';
}

function cfgBlockColorHex(colorId) {
  const id = normalizeCfgBlockColor(colorId);
  return CFG_BLOCK_COLOR_PRESETS.find((c) => c.id === id)?.hex || '';
}

function normalizeCfgBlockState(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {};
  if (Number.isFinite(raw.x) && Number.isFinite(raw.y)) {
    out.x = Math.round(raw.x);
    out.y = Math.round(raw.y);
  }
  if (raw.read) out.read = true;
  const note = typeof raw.note === 'string' ? raw.note.trim() : '';
  if (note) out.note = note.slice(0, 2000);
  const color = normalizeCfgBlockColor(raw.color);
  if (color) out.color = color;
  if (!Object.keys(out).length) return null;
  return out;
}

function loadCfgMethodBlockState() {
  cfgMethodBlockState = {};
  const fp = cfgStateFileFingerprint();
  const methodKey = cfgCurrentMethodStorageKey();
  if (!fp || !methodKey) return;
  try {
    const entry = readCfgStateStore().entries[fp];
    const method = entry?.methods?.[methodKey];
    const blocks = method?.blocks;
    if (!blocks || typeof blocks !== 'object') return;
    for (const [off, raw] of Object.entries(blocks)) {
      const st = normalizeCfgBlockState(raw);
      if (st) cfgMethodBlockState[String(off)] = st;
    }
  } catch (_) {
    cfgMethodBlockState = {};
  }
}

function persistCfgMethodBlockState() {
  const fp = cfgStateFileFingerprint();
  const methodKey = cfgCurrentMethodStorageKey();
  if (!fp || !methodKey) return false;
  const store = readCfgStateStore();
  const entry = store.entries[fp] && typeof store.entries[fp] === 'object'
    ? store.entries[fp]
    : { methods: {} };
  const methods = entry.methods && typeof entry.methods === 'object' ? { ...entry.methods } : {};
  const blocks = {};
  for (const [off, raw] of Object.entries(cfgMethodBlockState)) {
    const st = normalizeCfgBlockState(raw);
    if (st) blocks[off] = st;
  }
  if (!Object.keys(blocks).length) {
    delete methods[methodKey];
  } else {
    methods[methodKey] = { blocks, updatedAt: Date.now() };
  }
  if (!Object.keys(methods).length) {
    delete store.entries[fp];
  } else {
    store.entries[fp] = { savedAt: Date.now(), methods };
  }
  return writeCfgStateStore(store);
}

function getCfgBlockState(startOffset) {
  return cfgMethodBlockState[String(startOffset >>> 0)] || {};
}

function updateCfgBlockState(startOffset, patch) {
  const key = String(startOffset >>> 0);
  const cur = { ...(cfgMethodBlockState[key] || {}) };
  if (patch.x !== undefined) {
    if (patch.x == null || patch.y == null) {
      delete cur.x;
      delete cur.y;
    } else {
      cur.x = Math.round(patch.x);
      cur.y = Math.round(patch.y);
    }
  }
  if (patch.read !== undefined) {
    if (patch.read) cur.read = true;
    else delete cur.read;
  }
  if (patch.note !== undefined) {
    const note = String(patch.note || '').trim().slice(0, 2000);
    if (note) cur.note = note;
    else delete cur.note;
  }
  if (patch.color !== undefined) {
    const color = normalizeCfgBlockColor(patch.color);
    if (color) cur.color = color;
    else delete cur.color;
  }
  const normalized = normalizeCfgBlockState(cur);
  if (normalized) cfgMethodBlockState[key] = normalized;
  else delete cfgMethodBlockState[key];
  persistCfgMethodBlockState();
  return cfgMethodBlockState[key] || {};
}

function cfgMethodHasCustomLayout() {
  return Object.values(cfgMethodBlockState).some((b) => Number.isFinite(b?.x) && Number.isFinite(b?.y));
}

function clearCfgMethodLayout() {
  for (const key of Object.keys(cfgMethodBlockState)) {
    const b = cfgMethodBlockState[key];
    if (!b) continue;
    delete b.x;
    delete b.y;
    const next = normalizeCfgBlockState(b);
    if (next) cfgMethodBlockState[key] = next;
    else delete cfgMethodBlockState[key];
  }
  persistCfgMethodBlockState();
}

function applySavedCfgBlockPositions(nodes) {
  if (!cfgNetwork || !nodes?.length) return 0;
  const saved = [];
  for (const n of nodes) {
    const st = getCfgBlockState(n.startOffset);
    if (!Number.isFinite(st.x) || !Number.isFinite(st.y)) continue;
    saved.push({ n, x: st.x, y: st.y });
  }
  if (!saved.length) return 0;
  // Drop corrupt/collapsed saves (e.g. from a prior layout bug) so auto layout wins.
  if (saved.length >= 2) {
    const xs = saved.map((s) => s.x);
    const ys = saved.map((s) => s.y);
    const span = (Math.max(...xs) - Math.min(...xs)) + (Math.max(...ys) - Math.min(...ys));
    if (span < 48) {
      clearCfgMethodLayout();
      return 0;
    }
  }
  let applied = 0;
  for (const s of saved) {
    try {
      cfgNetwork.moveNode(s.n.id, s.x, s.y);
      applied++;
    } catch (_) {}
  }
  return applied;
}

function persistCfgNodePositions(nodeIds, nodesById) {
  if (!cfgNetwork || !nodeIds?.length) return;
  let positions;
  try { positions = cfgNetwork.getPositions(nodeIds); } catch (_) { return; }
  for (const id of nodeIds) {
    const node = nodesById?.get?.(Number(id)) || nodesById?.get?.(id);
    const pos = positions[id];
    if (!node || !pos) continue;
    updateCfgBlockState(node.startOffset, { x: pos.x, y: pos.y });
  }
}

function mergeCfgStateJson(localRaw, importedRaw) {
  let local = { entries: {} };
  let imported = { entries: {} };
  try {
    const p = JSON.parse(localRaw || '{}');
    if (p?.entries && typeof p.entries === 'object') local = p;
  } catch (_) {}
  try {
    const p = JSON.parse(importedRaw || '{}');
    if (p?.entries && typeof p.entries === 'object') imported = p;
  } catch (_) {}
  const out = { entries: { ...(local.entries || {}) } };
  for (const [fp, entry] of Object.entries(imported.entries || {})) {
    if (!entry || typeof entry !== 'object') continue;
    const existing = out.entries[fp];
    if (!existing) {
      out.entries[fp] = entry;
      continue;
    }
    const methods = { ...(existing.methods || {}) };
    for (const [mk, meth] of Object.entries(entry.methods || {})) {
      if (!meth || typeof meth !== 'object') continue;
      const prev = methods[mk];
      if (!prev) {
        methods[mk] = meth;
        continue;
      }
      const blocks = { ...(prev.blocks || {}) };
      for (const [off, blk] of Object.entries(meth.blocks || {})) {
        const merged = normalizeCfgBlockState({ ...(blocks[off] || {}), ...(blk || {}) });
        if (merged) blocks[off] = merged;
        else delete blocks[off];
      }
      methods[mk] = {
        ...prev,
        ...meth,
        blocks,
        updatedAt: Math.max(Number(prev.updatedAt) || 0, Number(meth.updatedAt) || 0),
      };
    }
    out.entries[fp] = {
      ...existing,
      ...entry,
      methods,
      savedAt: Math.max(Number(existing.savedAt) || 0, Number(entry.savedAt) || 0),
    };
  }
  return JSON.stringify(out);
}

function getMethodCfgData(method) {
  if (!method) return { nodes: [], edges: [], bytecode: [] };
  const nodesRaw = method.cfgNodes || method.cfg_nodes || [];
  const edgesRaw = method.cfgEdges || method.cfg_edges || [];
  const bytecode = Array.isArray(method.bytecode) ? method.bytecode : [];
  return {
    nodes: nodesRaw.map((n) => ({
      id: n.id,
      startOffset: n.startOffset ?? n.start_offset ?? 0,
      endOffset: n.endOffset ?? n.end_offset ?? 0,
      label: n.label || '',
    })),
    edges: edgesRaw.map((e) => ({
      fromId: e.fromId ?? e.from_id,
      toId: e.toId ?? e.to_id,
    })),
    bytecode,
  };
}

function formatCfgOffset(off) {
  const n = Number(off) >>> 0;
  return '0x' + n.toString(16).padStart(4, '0');
}

function bytecodeRowsInBlock(node, bytecodeRows) {
  const end = node.endOffset === 0xFFFFFFFF ? Infinity : node.endOffset;
  return bytecodeRows.filter((r) => r.offset >= node.startOffset && r.offset < end);
}

const CFG_OPERAND_MAX_CHARS = 72;

function truncateCfgOperand(op, max = CFG_OPERAND_MAX_CHARS) {
  const s = String(op || '').trim();
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

function formatCfgInsnPlain(row) {
  const off = formatCfgOffset(row.offset);
  const mn = String(row.mnemonic || '').trim();
  const op = truncateCfgOperand(row.operands);
  return `${off}  ${mn}${op ? '  ' + op : ''}`;
}

function cfgInsnLineKind(mnemonic) {
  const m = String(mnemonic || '').toLowerCase();
  if (/^if-|^goto|switch/.test(m)) return 'branch';
  if (/^return/.test(m) || m === 'throw') return 'return';
  if (/^invoke|filled-new-array/.test(m)) return 'invoke';
  return '';
}

function classifyCfgBlock(node, insns, loopHeaders) {
  if (node.id === 0) return 'entry';
  if (loopHeaders.has(node.id)) return 'loop';
  if (!insns.length) return 'empty';
  const lastMn = String(insns[insns.length - 1].mnemonic || '').toLowerCase();
  if (/^return/.test(lastMn)) return 'exit';
  if (lastMn === 'throw') return 'exit-throw';
  if (/^if-|^goto|switch/.test(lastMn)) return 'branch';
  if (/^invoke|filled-new-array/.test(lastMn)) return 'invoke';
  if (insns.some((r) => /^invoke/.test(String(r.mnemonic || '').toLowerCase()))) return 'invoke';
  return 'normal';
}

function cfgBlockKindLabel(kind) {
  const labels = {
    entry: 'entry',
    exit: 'return',
    'exit-throw': 'throw',
    branch: 'branch',
    invoke: 'call',
    loop: 'loop',
    empty: 'empty',
    normal: '',
  };
  return labels[kind] || '';
}

function cfgLocLabel(offset) {
  return 'loc_' + formatCfgOffset(offset).slice(2);
}

function cfgLocForBlockId(blockId, nodeById) {
  const n = nodeById.get(blockId);
  return n ? cfgLocLabel(n.startOffset) : `b${blockId}`;
}

function formatCfgHexDisplay(hex) {
  const s = String(hex || '').replace(/\s+/g, ' ').trim();
  if (s.length <= 23) return s;
  return s.slice(0, 21) + '…';
}

function buildCfgInsnHtml(row, { showHex = false, showAddr = true, isTerm = false } = {}) {
  const opClass = bytecodeOpcodeClass(row.mnemonic);
  const lineKind = cfgInsnLineKind(row.mnemonic);
  const hexRaw = String(row.hex || '').trim();
  const offset = showAddr
    ? `<span class="bc-offset">${formatCfgOffset(row.offset)}</span>`
    : '';
  const hex = showAddr && showHex
    ? `<span class="bc-hex">${escapeHtml(formatCfgHexDisplay(hexRaw))}</span>`
    : '';
  const mnemonic = `<span class="bc-mnemonic${opClass ? ' ' + opClass : ''}">${escapeHtml(row.mnemonic || '')}</span>`;
  const opRaw = String(row.operands || '').trim();
  const opDisp = truncateCfgOperand(opRaw);
  const fieldIdx = fieldIndexFromBytecodeRow(row);
  // Truncate in the CFG overlay — never dump fill-array / long const blobs into tooltips.
  const operands = opDisp
    ? `<span class="bc-operands">${highlightBytecodeOperands(opDisp, { fieldIdx })}</span>`
    : '';
  const termCls = isTerm ? ' cfg-insn-term' : '';
  return `<div class="bytecode-line cfg-insn-line${lineKind ? ' cfg-insn-' + lineKind : ''}${termCls}" data-off="${row.offset}">` +
    `${offset}${hex}${mnemonic}${operands}</div>`;
}

function buildCfgSuccessorTags(fromId, toIds, nodeById, insns, blockKind) {
  if (!toIds?.length) return [];
  const lastMn = insns.length ? String(insns[insns.length - 1].mnemonic || '').toLowerCase() : '';
  return toIds.map((toId, idx) => {
    const loc = cfgLocForBlockId(toId, nodeById);
    if (blockKind === 'branch' && toIds.length === 2 && /^if-/.test(lastMn)) {
      return { text: `→ ${loc}`, cls: idx === 0 ? 'cfg-succ-t' : 'cfg-succ-f', toId };
    }
    if (toIds.length === 1) return { text: `→ ${loc}`, cls: 'cfg-succ-flow', toId };
    return { text: `→ ${loc}`, cls: 'cfg-succ-multi', toId };
  });
}

function buildCfgBlockHtml(node, bytecodeRows, compact, blockKind, succTags, blockState = {}) {
  const insns = bytecodeRowsInBlock(node, bytecodeRows);
  const endStr = node.endOffset === 0xFFFFFFFF ? 'end' : formatCfgOffset(node.endOffset);
  const kindLabel = cfgBlockKindLabel(blockKind);
  const showAddr = cfgShowAddr;
  // Never show hex bytes in CFG — only addresses (optional) + mnemonic/operands.
  const insnOpts = { showHex: false, showAddr };
  let body = '';
  if (!insns.length) {
    body = showAddr
      ? `<div class="cfg-insn-empty"><span class="bc-offset">${formatCfgOffset(node.startOffset)}</span> (empty · ${endStr})</div>`
      : `<div class="cfg-insn-empty">(empty)</div>`;
  } else if (compact) {
    // Compact: last instruction only — block colors stay on the node chrome
    body = buildCfgInsnHtml(insns[insns.length - 1], { ...insnOpts, isTerm: true });
  } else {
    body = insns.map((r, i) => buildCfgInsnHtml(r, { ...insnOpts, isTerm: i === insns.length - 1 })).join('');
  }
  const loc = cfgLocLabel(node.startOffset);
  const rangeComment = compact
    ? (kindLabel ? `<span class="cfg-block-comment">; ${kindLabel}</span>` : '')
    : (showAddr && endStr !== 'end'
      ? `<span class="cfg-block-comment">; ${formatCfgOffset(node.startOffset)}–${endStr}${kindLabel ? ' · ' + kindLabel : ''}</span>`
      : (kindLabel ? `<span class="cfg-block-comment">; ${kindLabel}</span>` : ''));
  // Always show successor edges (even in compact) so they remain clickable navigation targets
  const foot = succTags?.length
    ? `<div class="cfg-block-foot">${succTags.map((s) =>
        `<button type="button" class="cfg-succ ${s.cls}" data-cfg-to="${s.toId}" title="Go to ${escapeAttr(s.text)}">${escapeHtml(s.text)}</button>`
      ).join('')}</div>`
    : '';
  const read = !!blockState.read;
  const note = typeof blockState.note === 'string' ? blockState.note.trim() : '';
  const color = normalizeCfgBlockColor(blockState.color);
  const colorHex = cfgBlockColorHex(color);
  const cls = [
    'cfg-block',
    `cfg-block-${blockKind}`,
    'cfg-no-hex',
    showAddr ? '' : 'cfg-no-addr',
    compact ? 'cfg-compact' : '',
    read ? 'cfg-block-read' : '',
    note ? 'cfg-block-noted' : '',
    color ? 'cfg-block-colored' : '',
  ].filter(Boolean).join(' ');
  const styleAttr = colorHex ? ` style="--cfg-user-color:${colorHex}"` : '';
  const noteHtml = (!compact && note)
    ? `<div class="cfg-block-note" title="${escapeAttr(note)}">${escapeHtml(note)}</div>`
    : '';
  const readBadge = read
    ? `<span class="cfg-block-read-badge" title="Marked as read">✓ read</span>`
    : '';
  const colorTitle = color
    ? `Block color: ${CFG_BLOCK_COLOR_PRESETS.find((c) => c.id === color)?.label || color}`
    : 'Set block color';
  const actions =
    `<div class="cfg-block-actions">` +
    `<button type="button" class="cfg-block-btn cfg-block-color-btn${color ? ' active' : ''}" data-cfg-action="color" data-start="${node.startOffset}" title="${escapeAttr(colorTitle)}" aria-label="Block color"${colorHex ? ` style="--cfg-swatch:${colorHex}"` : ''}><span class="cfg-color-swatch" aria-hidden="true"></span></button>` +
    (compact ? '' :
    `<button type="button" class="cfg-block-btn cfg-block-read-btn${read ? ' active' : ''}" data-cfg-action="read" data-start="${node.startOffset}" title="${read ? 'Mark unread' : 'Mark as read'}">${read ? '✓' : '○'}</button>` +
    `<button type="button" class="cfg-block-btn cfg-block-note-btn${note ? ' active' : ''}" data-cfg-action="note" data-start="${node.startOffset}" title="Annotate block">✎</button>`) +
    `</div>`;
  return `<div class="${cls}" data-node-id="${node.id}" data-start-offset="${node.startOffset}"${color ? ` data-cfg-color="${escapeAttr(color)}"` : ''}${styleAttr}>` +
    `<div class="cfg-block-head">` +
    `<span class="cfg-block-drag" title="Drag to reposition" aria-hidden="true">⋮⋮</span>` +
    `<span class="cfg-block-loc">${loc}</span>${rangeComment}${readBadge}` +
    actions +
    `</div>` +
    noteHtml +
    `<div class="cfg-block-body">${body}</div>` +
    foot +
    `</div>`;
}

function buildCfgBlockPlainText(node, bytecodeRows, compact) {
  const insns = bytecodeRowsInBlock(node, bytecodeRows);
  const header = cfgLocLabel(node.startOffset);
  if (!insns.length) {
    const endStr = node.endOffset === 0xFFFFFFFF ? 'end' : formatCfgOffset(node.endOffset);
    return `${header}\n${formatCfgOffset(node.startOffset)}  (empty · ${endStr})`;
  }
  if (compact) {
    return `${header}\n${formatCfgInsnPlain(insns[insns.length - 1])}`;
  }
  return `${header}\n${insns.map(formatCfgInsnPlain).join('\n')}`;
}

function computeLoopHeaders(edges, levelMap) {
  const headers = new Set();
  for (const e of edges) {
    if ((levelMap[e.toId] ?? 0) <= (levelMap[e.fromId] ?? 0)) {
      headers.add(e.toId);
    }
  }
  headers.delete(0);
  return headers;
}

function buildCfgEdgeStyle(fromId, toId, edgeIdx, outCount, levelMap, fromBlockKind, theme, nodeById, lastMnemonic) {
  const back = (levelMap[toId] ?? 0) <= (levelMap[fromId] ?? 0);
  const lastMn = String(lastMnemonic || '').toLowerCase();
  const labelFont = (color) => ({
    size: 11,
    color,
    face: theme.mono,
    align: 'horizontal',
    strokeWidth: 3,
    strokeColor: theme.bg,
    background: 'transparent',
  });

  // Back-edge (loop) — solid cyan/blue orthogonal side route
  if (back) {
    return {
      color: theme.edgeBack,
      highlight: theme.text,
      hover: theme.edgeBack,
      opacity: 1,
      dashes: false,
      width: 2.4,
      label: '↺',
      font: labelFont(theme.edgeBack),
      edgeKind: 'back',
      smoothHint: 'back',
    };
  }

  // Conditional if-* with two successors — green “yes”, red “no”, solid orthogonal
  if (fromBlockKind === 'branch' && outCount === 2 && /^if-/.test(lastMn)) {
    const isTaken = edgeIdx === 0;
    const color = isTaken ? theme.edgeYes : theme.edgeNo;
    return {
      color,
      highlight: theme.text,
      hover: color,
      opacity: 1,
      dashes: false,
      width: 2.6,
      label: '',
      font: labelFont(color),
      edgeKind: isTaken ? 'taken' : 'fall',
      smoothHint: isTaken ? 'yes' : 'no',
    };
  }

  // Multi-way branch (switch / packed) — primary vs alternatives
  if (fromBlockKind === 'branch' && outCount > 1) {
    const isSecondary = edgeIdx > 0;
    const color = isSecondary ? theme.yellow : theme.edgeFlow;
    return {
      color,
      highlight: theme.text,
      hover: color,
      opacity: 1,
      dashes: false,
      width: isSecondary ? 2.1 : 2.4,
      label: outCount <= 4 ? String(edgeIdx) : '',
      font: labelFont(color),
      edgeKind: isSecondary ? 'alt' : 'flow',
      smoothHint: isSecondary ? 'side' : 'flow',
    };
  }

  // Fall-through / unconditional — Default: muted solid polyline
  return {
    color: theme.edgeFlow,
    highlight: theme.accent,
    hover: theme.accent,
    opacity: 0.95,
    dashes: false,
    width: 2.1,
    label: '',
    font: labelFont(theme.muted),
    edgeKind: 'flow',
    smoothHint: 'flow',
  };
}

/** Build sharp orthogonal (H/V only) polyline between two block centers. */
function buildCfgOrthogonalPoints(fromPos, toPos, fromSize, toSize, opts = {}) {
  const fw = (fromSize?.width || 220) / 2;
  const fh = (fromSize?.height || 64) / 2;
  const tw = (toSize?.width || 220) / 2;
  const th = (toSize?.height || 64) / 2;
  const fx = fromPos.x;
  const fy = fromPos.y;
  const tx = toPos.x;
  const ty = toPos.y;
  const lane = opts.lane || 0;
  const sideSign = opts.sideSign >= 0 ? 1 : -1;
  const isBack = ty + th < fy - fh + 2;

  if (isBack) {
    // Side channel: out → up → in (all axis-aligned)
    const pad = 28 + lane * 16;
    const channelX = sideSign > 0
      ? Math.max(fx + fw, tx + tw) + pad
      : Math.min(fx - fw, tx - tw) - pad;
    const start = { x: fx, y: fy + fh };
    const end = { x: tx, y: ty - th };
    const y1 = start.y + 12 + (lane % 3) * 6;
    const y2 = end.y - 12 - (lane % 3) * 6;
    return [
      start,
      { x: fx, y: y1 },
      { x: channelX, y: y1 },
      { x: channelX, y: y2 },
      { x: tx, y: y2 },
      end,
    ];
  }

  // Forward: exit bottom → horizontal elbow → enter top
  const start = { x: fx, y: fy + fh };
  const end = { x: tx, y: ty - th };
  if (Math.abs(fx - tx) < 1.5) {
    return [start, end];
  }
  const gap = end.y - start.y;
  const frac = Math.min(0.72, Math.max(0.28, 0.5 + lane * 0.08));
  const midY = start.y + gap * frac;
  return [
    start,
    { x: fx, y: midY },
    { x: tx, y: midY },
    end,
  ];
}

function drawCfgArrowHead(ctx, fromPt, toPt, color, size = 9) {
  const dx = toPt.x - fromPt.x;
  const dy = toPt.y - fromPt.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  const tip = toPt;
  const left = {
    x: tip.x - ux * size - uy * size * 0.55,
    y: tip.y - uy * size + ux * size * 0.55,
  };
  const right = {
    x: tip.x - ux * size + uy * size * 0.55,
    y: tip.y - uy * size - ux * size * 0.55,
  };
  ctx.beginPath();
  ctx.moveTo(tip.x, tip.y);
  ctx.lineTo(left.x, left.y);
  ctx.lineTo(right.x, right.y);
  ctx.closePath();
  ctx.fillStyle = color;
  ctx.fill();
}

function drawCfgOrthogonalEdges(ctx) {
  const state = cfgOrthoEdgeState;
  if (!state || !cfgNetwork || !ctx) return;
  const positions = cfgNetwork.getPositions();
  const selected = new Set((cfgNetwork.getSelectedEdges?.() || []).map(String));
  const scale = cfgNetwork.getScale() || 1;
  // Screen-constant stroke width (does not fatten into mush when zoomed in).
  const px = (n) => Math.max(1, n / scale);

  ctx.save();
  ctx.lineCap = 'butt';
  ctx.lineJoin = 'miter';
  ctx.miterLimit = 2;
  // Prefer crisp orthogonal segments over soft AA blobs at high zoom.
  if (typeof ctx.imageSmoothingEnabled === 'boolean') ctx.imageSmoothingEnabled = false;

  for (const edge of state.edges) {
    const fromPos = positions[edge.from];
    const toPos = positions[edge.to];
    if (!fromPos || !toPos) continue;
    const fromSize = state.sizes[edge.from] || { width: 220, height: 64 };
    const toSize = state.sizes[edge.to] || { width: 220, height: 64 };
    const points = buildCfgOrthogonalPoints(fromPos, toPos, fromSize, toSize, {
      lane: edge.lane,
      sideSign: edge.sideSign,
    });
    if (points.length < 2) continue;

    const isSel = selected.has(String(edge.id));
    const color = isSel ? (edge.highlight || edge.color) : edge.color;
    const width = px(isSel ? (edge.width || 2) + 1.2 : (edge.width || 2));

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
    ctx.strokeStyle = color;
    ctx.globalAlpha = edge.opacity == null ? 1 : edge.opacity;
    ctx.lineWidth = width;
    if (edge.dashes) ctx.setLineDash([px(6), px(4)]);
    else ctx.setLineDash([]);
    ctx.stroke();
    ctx.globalAlpha = 1;

    const a = points[points.length - 2];
    const b = points[points.length - 1];
    drawCfgArrowHead(ctx, a, b, color, px(edge.edgeKind === 'back' ? 8 : 9));

    if (edge.label) {
      // Place label on the longest horizontal segment (or mid of path)
      let best = null;
      let bestLen = -1;
      for (let i = 0; i < points.length - 1; i++) {
        const p0 = points[i];
        const p1 = points[i + 1];
        const horiz = Math.abs(p0.y - p1.y) < 0.5;
        const len = Math.hypot(p1.x - p0.x, p1.y - p0.y);
        if (horiz && len > bestLen) {
          bestLen = len;
          best = { x: (p0.x + p1.x) / 2, y: p0.y };
        }
      }
      if (!best) {
        const mid = points[Math.floor(points.length / 2)];
        best = { x: mid.x, y: mid.y };
      }
      const fontPx = Math.max(9, 11 / scale);
      ctx.font = `${fontPx}px ${state.mono || 'monospace'}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      const tw = ctx.measureText(edge.label).width;
      const padX = px(3);
      const padY = px(2);
      const boxH = fontPx + padY * 2;
      ctx.fillStyle = state.bg || 'rgba(23,25,35,0.92)';
      ctx.fillRect(best.x - tw / 2 - padX, best.y - boxH - padY, tw + padX * 2, boxH);
      ctx.fillStyle = color;
      ctx.fillText(edge.label, best.x, best.y - padY);
    }
  }
  ctx.restore();
}

function renderCfgLegend(theme) {
  if (!cfgLegend) return;
  cfgLegend.hidden = false;
  cfgLegend.setAttribute('aria-hidden', 'false');
  const items = [
    ['block-entry', 'Entry'],
    ['block-exit', 'Return'],
    ['block-branch', 'Branch'],
    ['block-loop', 'Loop'],
    ['edge-fall', 'Fall-through'],
    ['edge-taken', 'True'],
    ['edge-fall-f', 'False'],
    ['edge-back', 'Back-edge'],
  ];
  cfgLegend.innerHTML = items.map(([cls, text]) =>
    `<span class="cfg-legend-item"><span class="cfg-legend-swatch ${cls}"></span>${text}</span>`
  ).join('') +
    `<span class="cfg-legend-item muted">· click block → bytecode · scroll → zoom · hold wheel → pan</span>`;
}

function clearCfgLegend() {
  if (!cfgLegend) return;
  cfgLegend.hidden = true;
  cfgLegend.setAttribute('aria-hidden', 'true');
  cfgLegend.innerHTML = '';
}

function setCfgNodeSelected(nodeId) {
  if (!cfgHtmlLayer) return;
  cfgHtmlLayer.querySelectorAll('.cfg-block').forEach((el) => {
    el.classList.toggle('cfg-block-selected', String(el.getAttribute('data-node-id')) === String(nodeId));
  });
}

/** Distance from point to segment (canvas / network coords). */
function cfgDistPointToSeg(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const len2 = dx * dx + dy * dy;
  if (len2 <= 1e-9) return Math.hypot(px - ax, py - ay);
  let t = ((px - ax) * dx + (py - ay) * dy) / len2;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/**
 * Hit-test custom orthogonal edges (vis edges are width:0 / invisible, so
 * params.edges is usually empty on click — we match against the painted polylines).
 */
function hitTestCfgOrthoEdge(domPoint, thresholdPx = 12) {
  if (!cfgNetwork || !cfgOrthoEdgeState || !domPoint) return null;
  let canvasPt;
  try {
    canvasPt = cfgNetwork.DOMtoCanvas({ x: domPoint.x, y: domPoint.y });
  } catch (_) {
    return null;
  }
  if (!canvasPt || !Number.isFinite(canvasPt.x) || !Number.isFinite(canvasPt.y)) return null;
  const scale = cfgNetwork.getScale() || 1;
  const maxDist = Math.max(4, thresholdPx) / scale;
  const positions = cfgNetwork.getPositions();
  const sizes = cfgOrthoEdgeState.sizes || {};
  let best = null;
  let bestDist = maxDist;
  for (const edge of cfgOrthoEdgeState.edges) {
    const fromPos = positions[edge.from];
    const toPos = positions[edge.to];
    if (!fromPos || !toPos) continue;
    const fromSize = sizes[edge.from] || { width: 220, height: 64 };
    const toSize = sizes[edge.to] || { width: 220, height: 64 };
    const points = buildCfgOrthogonalPoints(fromPos, toPos, fromSize, toSize, {
      lane: edge.lane,
      sideSign: edge.sideSign,
    });
    if (!points || points.length < 2) continue;
    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1];
      const b = points[i];
      const d = cfgDistPointToSeg(canvasPt.x, canvasPt.y, a.x, a.y, b.x, b.y);
      if (d < bestDist) {
        bestDist = d;
        best = edge;
      }
    }
  }
  return best;
}

/** Select a CFG block, pan the graph to it, and sync the bytecode listing. */
function navigateToCfgNode(nodeId, { highlightBytecode = true } = {}) {
  const id = Number(nodeId);
  if (!Number.isFinite(id)) return false;
  const ctx = getCodeViewContext();
  const method = ctx?.classes?.[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
  const { nodes } = method ? getMethodCfgData(method) : { nodes: [] };
  const node = nodes.find((n) => Number(n.id) === id);
  if (!node) return false;

  setCfgNodeSelected(id);
  try { cfgNetwork?.selectNodes([id]); } catch (_) {}
  try {
    const edgeIds = (cfgOrthoEdgeState?.edges || [])
      .filter((e) => Number(e.to) === id || Number(e.from) === id)
      .map((e) => e.id);
    if (edgeIds.length && cfgNetwork?.selectEdges) cfgNetwork.selectEdges(edgeIds.slice(0, 1));
  } catch (_) {}

  if (cfgNetwork) {
    // Prefer focus() so the destination is centered even when already partially on-screen.
    try {
      cfgNetwork.focus(id, {
        scale: cfgNetwork.getScale(),
        animation: { duration: 320, easingFunction: 'easeInOutQuad' },
      });
    } catch (_) {
      try {
        const pos = cfgNetwork.getPositions([id])?.[id];
        if (pos) {
          cfgNetwork.moveTo({
            position: pos,
            scale: cfgNetwork.getScale(),
            animation: { duration: 320, easingFunction: 'easeInOutQuad' },
          });
        }
      } catch (_) {}
    }
    // Keep HTML blocks locked to the camera during the pan animation.
    const syncDuringPan = () => {
      syncCfgHtmlOverlay();
    };
    requestAnimationFrame(syncDuringPan);
    window.setTimeout(syncDuringPan, 80);
    window.setTimeout(syncDuringPan, 200);
    window.setTimeout(syncDuringPan, 340);
  }

  const el = cfgHtmlLayer?.querySelector(`.cfg-block[data-node-id="${CSS.escape(String(id))}"]`);
  if (el) {
    el.classList.add('cfg-block-nav-flash');
    window.setTimeout(() => el.classList.remove('cfg-block-nav-flash'), 700);
  }

  if (highlightBytecode) {
    const bcPane = document.getElementById('bytecode-pane');
    if (bcPane && bcPane.dataset.collapsed === 'true' && !getMaximizedPane()) {
      setDockCollapsed(bcPane, false, 'droid2web-bytecode-open');
      updateWorkspaceResizers();
    }
    highlightCfgBlock(node, node.startOffset);
  }
  return true;
}

/** Cap used for hierarchical spacing so one tall block does not explode the graph. */
const CFG_LAYOUT_MAX_H = 260;
const CFG_LAYOUT_MAX_W = 560;
/** Compact: allow wider boxes so full mnemonic names are not clipped. */
const CFG_LAYOUT_MAX_W_COMPACT = 720;
const CFG_LAYOUT_MIN_W = 200;

function cfgLayoutMaxWidth() {
  return cfgCompactLabels ? CFG_LAYOUT_MAX_W_COMPACT : CFG_LAYOUT_MAX_W;
}

function measureCfgBlockSizes() {
  const sizes = {};
  if (!cfgHtmlLayer) return sizes;
  const maxW = cfgLayoutMaxWidth();
  // Measure at 1× so layout metrics match vis node boxes (zoom applies later via --cfg-z).
  cfgHtmlLayer.style.setProperty('--cfg-z', '1');
  for (const el of cfgHtmlLayer.querySelectorAll('.cfg-block')) {
    const id = el.getAttribute('data-node-id');
    if (id == null) continue;
    el.style.height = '';
    el.style.minWidth = '';
    el.style.transform = '';
    // Cap width first so wrapped lines / scrollable body measure correctly.
    el.style.maxWidth = `${maxW}px`;
    el.style.width = '';
    let rawW = Math.max(CFG_LAYOUT_MIN_W, Math.ceil(el.offsetWidth));
    const width = Math.min(maxW, rawW);
    el.style.width = `${width}px`;
    // Height is capped; overflow scrolls inside .cfg-block-body (CSS).
    const rawH = Math.max(40, Math.ceil(el.offsetHeight));
    const height = Math.min(CFG_LAYOUT_MAX_H, rawH);
    el.style.height = `${height}px`;
    sizes[id] = { width, height, rawWidth: rawW, rawHeight: rawH };
    el.dataset.layoutW = String(width);
    el.dataset.layoutH = String(height);
  }
  return sizes;
}

function syncCfgHtmlOverlay() {
  if (!cfgNetwork || !cfgHtmlLayer) return;
  const positions = cfgNetwork.getPositions();
  const scale = cfgNetwork.getScale();
  if (!Number.isFinite(scale) || scale <= 0) return;
  const dpr = (typeof window !== 'undefined' && window.devicePixelRatio) || 1;
  // Keep text sharp: never CSS-scale the HTML (that rasterizes then stretches).
  // Re-size / re-font via --cfg-z and only translate into place.
  cfgHtmlLayer.style.setProperty('--cfg-z', String(scale));
  if (cfgGraphContainer) {
    const grid = Math.max(10, Math.round(20 * scale));
    cfgGraphContainer.style.backgroundSize = `${grid}px ${grid}px`;
  }
  for (const el of cfgHtmlLayer.querySelectorAll('.cfg-block')) {
    const id = el.getAttribute('data-node-id');
    const pos = positions[id];
    if (!pos) continue;
    const dom = cfgNetwork.canvasToDOM({ x: pos.x, y: pos.y });
    const baseW = Number(el.dataset.layoutW) || Math.max(168, el.offsetWidth) || 200;
    const baseH = Number(el.dataset.layoutH) || Math.max(32, el.offsetHeight) || 64;
    const w = baseW * scale;
    const h = baseH * scale;
    // Snap to device pixels to avoid subpixel text blur while panning.
    const left = Math.round((dom.x - w / 2) * dpr) / dpr;
    const top = Math.round((dom.y - h / 2) * dpr) / dpr;
    el.style.width = `${w}px`;
    el.style.height = `${h}px`;
    el.style.maxWidth = 'none';
    el.style.minWidth = '0';
    el.style.transformOrigin = '0 0';
    el.style.transform = `translate3d(${left}px, ${top}px, 0)`;
  }
}

function formatCfgInsnLine(row) {
  return formatCfgInsnPlain(row);
}

function buildCfgBlockLabel(node, bytecodeRows, compact) {
  return buildCfgBlockPlainText(node, bytecodeRows, compact);
}

function computeCfgLevels(nodes, edges, entryId = 0) {
  const levelMap = {};
  const outEdges = {};
  for (const e of edges) {
    if (!outEdges[e.fromId]) outEdges[e.fromId] = [];
    outEdges[e.fromId].push(e.toId);
  }
  let queue = [entryId];
  levelMap[entryId] = 0;
  const seen = new Set([entryId]);
  while (queue.length) {
    const id = queue.shift();
    const level = levelMap[id];
    for (const toId of outEdges[id] || []) {
      if (!seen.has(toId)) {
        seen.add(toId);
        levelMap[toId] = level + 1;
        queue.push(toId);
      }
    }
  }
  const maxLevel = nodes.length;
  for (const n of nodes) {
    if (levelMap[n.id] === undefined) levelMap[n.id] = maxLevel;
  }
  return levelMap;
}

function getCfgThemeColors() {
  const root = document.documentElement;
  const cs = getComputedStyle(root);
  const pick = (v, fallback) => (cs.getPropertyValue(v).trim() || fallback);
  return {
    bg: pick('--surface', '#2d2d30'),
    border: pick('--border', '#3f3f46'),
    text: pick('--text', '#f1f1f1'),
    muted: pick('--text-muted', '#9d9d9d'),
    accent: pick('--accent', '#007acc'),
    green: pick('--green', '#57a64a'),
    orange: pick('--orange', '#dda95b'),
    red: pick('--red', '#d85050'),
    yellow: pick('--yellow', '#dcdcaa'),
    purple: pick('--purple', '#c563bd'),
    // Default graph edge palette (dp701 convention)
    edgeYes: pick('--cfg-edge-yes', '#b8d7a3'),
    edgeNo: pick('--cfg-edge-no', '#d85050'),
    edgeFlow: pick('--cfg-edge-flow', '#9cdcfe'),
    edgeBack: pick('--cfg-edge-back', '#007acc'),
    mono: pick('--mono', 'Consolas, monospace'),
  };
}

function destroyCfgNetwork() {
  closeCfgColorPopover();
  endCfgBlockDragSession();
  if (cfgNetwork) {
    if (cfgNetworkDrawHandler) {
      try { cfgNetwork.off('afterDrawing', cfgNetworkDrawHandler); } catch (_) {}
      cfgNetworkDrawHandler = null;
    }
    try { cfgNetwork.destroy(); } catch (_) {}
    cfgNetwork = null;
  }
  cfgOrthoEdgeState = null;
  if (cfgHtmlLayer) {
    cfgHtmlLayer.innerHTML = '';
    cfgHtmlLayer.hidden = true;
    cfgHtmlLayer.setAttribute('aria-hidden', 'true');
    cfgHtmlLayer.style.removeProperty('--cfg-z');
  }
  if (cfgGraphContainer) {
    cfgGraphContainer.innerHTML = '';
    cfgGraphContainer.style.removeProperty('background-size');
  }
}

function clearCfgBlockHighlight() {
  cfgHighlightBlockId = null;
  if (!bytecodeListing) return;
  bytecodeListing.querySelectorAll('.bytecode-line.cfg-block-highlight, .bytecode-line.cfg-current-insn').forEach((el) => {
    el.classList.remove('cfg-block-highlight', 'cfg-current-insn');
  });
}

function highlightCfgBlock(node, focusOffset) {
  if (!node || !bytecodeListing) return;
  clearCfgBlockHighlight();
  cfgHighlightBlockId = node.id;
  const end = node.endOffset === 0xFFFFFFFF ? Infinity : node.endOffset;
  const lines = [...bytecodeListing.querySelectorAll('.bytecode-line')].filter((el) => {
    const off = parseInt(el.getAttribute('data-offset'), 10);
    return off >= node.startOffset && off < end;
  });
  for (const el of lines) el.classList.add('cfg-block-highlight');
  if (focusOffset != null) {
    const hit = lines.find((el) => parseInt(el.getAttribute('data-offset'), 10) === focusOffset);
    if (hit) {
      hit.classList.add('cfg-current-insn');
      scrollBytecodeLineIntoView(hit, { block: 'center', behavior: 'smooth' });
      return;
    }
  }
  if (lines[0]) scrollBytecodeLineIntoView(lines[0], { block: 'center', behavior: 'smooth' });
}

function setCfgEmptyState(show, title, hint) {
  if (show) clearCfgLegend();
  if (cfgGraphEmpty) {
    cfgGraphEmpty.hidden = !show;
    if (show && title) {
      const t = cfgGraphEmpty.querySelector('.code-empty-title');
      const h = cfgGraphEmpty.querySelector('.code-empty-hint');
      if (t) t.textContent = title;
      if (h) h.textContent = hint || '';
    }
  }
  if (cfgGraphContainer) cfgGraphContainer.hidden = show;
  if (cfgHtmlLayer) {
    cfgHtmlLayer.hidden = show;
    cfgHtmlLayer.setAttribute('aria-hidden', show ? 'true' : 'false');
  }
}

function fitCfgGraph() {
  if (!cfgNetwork) return;
  try {
    cfgNetwork.fit({ animation: { duration: 280, easingFunction: 'easeInOutQuad' } });
  } catch (_) {
    try { cfgNetwork.fit(); } catch (_) {}
  }
}

/** Smooth wheel → scale factor (trackpad-friendly; avoids fixed ±12% jumps). */
function cfgWheelZoomFactor(e) {
  let dy = e.deltaY;
  if (e.deltaMode === 1) dy *= 16; // lines → px-ish
  else if (e.deltaMode === 2) dy *= (cfgGraphContainer?.clientHeight || 600); // pages
  // Pinch-zoom on macOS often arrives as wheel + ctrlKey
  const sensitivity = e.ctrlKey ? 0.012 : 0.0035;
  const factor = Math.exp(-dy * sensitivity);
  return Math.max(0.5, Math.min(2, factor));
}

function cfgPointerInContainer(pointerEvent) {
  const host = cfgGraphContainer;
  if (!host || !pointerEvent || !Number.isFinite(pointerEvent.clientX)) return null;
  const rect = host.getBoundingClientRect();
  return {
    x: pointerEvent.clientX - rect.left,
    y: pointerEvent.clientY - rect.top,
  };
}

/**
 * Zoom CFG. With a pointer event, keep the canvas point under the cursor fixed
 * (vis moveTo({position}) would center that point — that felt jumpy/messy).
 */
function zoomCfgGraph(factor, pointerEvent) {
  if (!cfgNetwork || !Number.isFinite(factor) || factor <= 0) return;
  let scale;
  try {
    scale = cfgNetwork.getScale();
  } catch (_) {
    return;
  }
  if (!Number.isFinite(scale) || scale <= 0) scale = 1;
  const next = Math.max(0.12, Math.min(4, scale * factor));
  if (Math.abs(next - scale) < 1e-4) return;

  const pointer = cfgPointerInContainer(pointerEvent);
  const animate = pointerEvent
    ? false
    : { duration: 160, easingFunction: 'easeInOutQuad' };

  try {
    if (pointer) {
      // Canvas coords currently under the cursor
      const anchor = cfgNetwork.DOMtoCanvas(pointer);
      cfgNetwork.moveTo({ scale: next, animation: false });
      // After scale change around view center, shift view so anchor stays under pointer
      const after = cfgNetwork.canvasToDOM(anchor);
      const view = cfgNetwork.getViewPosition();
      const dx = (pointer.x - after.x) / next;
      const dy = (pointer.y - after.y) / next;
      cfgNetwork.moveTo({
        position: { x: view.x - dx, y: view.y - dy },
        scale: next,
        animation: false,
      });
    } else {
      cfgNetwork.moveTo({ scale: next, animation: animate });
    }
  } catch (_) {
    try { cfgNetwork.moveTo({ scale: next }); } catch (_) {}
  }
  syncCfgHtmlOverlay();
}

function endCfgBlockDragSession() {
  if (!cfgBlockDragSession) return;
  const { el, id, startOffset, moved } = cfgBlockDragSession;
  el?.classList.remove('cfg-block-dragging');
  cfgGraphWrap?.classList.remove('cfg-block-dragging-view');
  if (moved && cfgNetwork && startOffset != null) {
    try {
      const pos = cfgNetwork.getPositions([id])[id];
      if (pos) updateCfgBlockState(startOffset, { x: pos.x, y: pos.y });
    } catch (_) {}
  }
  cfgBlockDragSession = null;
}

function closeCfgColorPopover() {
  if (cfgColorPopover) {
    cfgColorPopover.remove();
    cfgColorPopover = null;
  }
  document.removeEventListener('pointerdown', onCfgColorPopoverOutside, true);
}

function onCfgColorPopoverOutside(e) {
  if (!cfgColorPopover) return;
  if (cfgColorPopover.contains(e.target)) return;
  if (e.target.closest?.('[data-cfg-action="color"]')) return;
  closeCfgColorPopover();
}

function openCfgColorPopover(anchorBtn, startOffset) {
  closeCfgColorPopover();
  const cur = normalizeCfgBlockColor(getCfgBlockState(startOffset).color);
  const pop = document.createElement('div');
  pop.className = 'cfg-color-popover';
  pop.setAttribute('role', 'dialog');
  pop.setAttribute('aria-label', 'Block color');
  pop.innerHTML =
    `<div class="cfg-color-popover-title">Block color</div>` +
    `<div class="cfg-color-swatches">` +
    `<button type="button" class="cfg-color-choice cfg-color-none${!cur ? ' selected' : ''}" data-color="" title="No color">∅</button>` +
    CFG_BLOCK_COLOR_PRESETS.map((c) =>
      `<button type="button" class="cfg-color-choice${cur === c.id ? ' selected' : ''}" data-color="${c.id}" title="${escapeAttr(c.label)}" style="--cfg-swatch:${c.hex}"><span class="cfg-color-swatch"></span></button>`
    ).join('') +
    `</div>`;
  document.body.appendChild(pop);
  cfgColorPopover = pop;

  const place = () => {
    const r = anchorBtn.getBoundingClientRect();
    const pw = pop.offsetWidth || 168;
    const ph = pop.offsetHeight || 72;
    let left = r.left;
    let top = r.bottom + 6;
    if (left + pw > window.innerWidth - 8) left = Math.max(8, window.innerWidth - pw - 8);
    if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 6);
    pop.style.left = `${Math.round(left)}px`;
    pop.style.top = `${Math.round(top)}px`;
  };
  place();

  pop.addEventListener('click', (e) => {
    const choice = e.target.closest('[data-color]');
    if (!choice) return;
    e.preventDefault();
    e.stopPropagation();
    setCfgBlockColor(startOffset, choice.getAttribute('data-color') || '');
    closeCfgColorPopover();
  });
  document.addEventListener('pointerdown', onCfgColorPopoverOutside, true);
}

function setCfgBlockColor(startOffset, colorId) {
  updateCfgBlockState(startOffset, { color: colorId || null });
  refreshCfgBlockChrome(startOffset);
}

function refreshCfgBlockChrome(startOffset) {
  if (!cfgHtmlLayer) return;
  const el = cfgHtmlLayer.querySelector(`.cfg-block[data-start-offset="${startOffset}"]`);
  if (!el) return;
  const st = getCfgBlockState(startOffset);
  const read = !!st.read;
  const note = (st.note || '').trim();
  const color = normalizeCfgBlockColor(st.color);
  const colorHex = cfgBlockColorHex(color);
  el.classList.toggle('cfg-block-read', read);
  el.classList.toggle('cfg-block-noted', !!note);
  el.classList.toggle('cfg-block-colored', !!color);
  if (color) {
    el.setAttribute('data-cfg-color', color);
    el.style.setProperty('--cfg-user-color', colorHex);
  } else {
    el.removeAttribute('data-cfg-color');
    el.style.removeProperty('--cfg-user-color');
  }

  const readBtn = el.querySelector('.cfg-block-read-btn');
  if (readBtn) {
    readBtn.classList.toggle('active', read);
    readBtn.textContent = read ? '✓' : '○';
    readBtn.title = read ? 'Mark unread' : 'Mark as read';
  }
  const noteBtn = el.querySelector('.cfg-block-note-btn');
  if (noteBtn) noteBtn.classList.toggle('active', !!note);

  const colorBtn = el.querySelector('.cfg-block-color-btn');
  if (colorBtn) {
    colorBtn.classList.toggle('active', !!color);
    if (colorHex) {
      colorBtn.style.setProperty('--cfg-swatch', colorHex);
      colorBtn.title = `Block color: ${CFG_BLOCK_COLOR_PRESETS.find((c) => c.id === color)?.label || color}`;
    } else {
      colorBtn.style.removeProperty('--cfg-swatch');
      colorBtn.title = 'Set block color';
    }
  }

  const head = el.querySelector('.cfg-block-head');
  let badge = el.querySelector('.cfg-block-read-badge');
  if (read) {
    if (!badge && head) {
      badge = document.createElement('span');
      badge.className = 'cfg-block-read-badge';
      badge.title = 'Marked as read';
      badge.textContent = '✓ read';
      const actions = head.querySelector('.cfg-block-actions');
      if (actions) head.insertBefore(badge, actions);
      else head.appendChild(badge);
    } else if (badge) {
      badge.hidden = false;
    }
  } else if (badge) {
    badge.remove();
  }

  let noteEl = el.querySelector('.cfg-block-note');
  if (note) {
    if (!noteEl) {
      noteEl = document.createElement('div');
      noteEl.className = 'cfg-block-note';
      const body = el.querySelector('.cfg-block-body');
      el.insertBefore(noteEl, body || null);
    }
    noteEl.textContent = note;
    noteEl.title = note;
  } else if (noteEl) {
    noteEl.remove();
  }
  updateCfgMetaProgress();
  try { updateAnnotationPanel(); } catch (_) {}
}

function updateCfgMetaProgress() {
  if (!cfgMeta) return;
  const text = cfgMeta.textContent || '';
  const base = text.replace(/\s*·\s*\d+\/\d+ read(?:\s*·\s*\d+ noted)?(?:\s*·\s*\d+ colored)?$/, '');
  const blocks = Object.keys(cfgMethodBlockState);
  const readN = blocks.filter((k) => cfgMethodBlockState[k]?.read).length;
  const noteN = blocks.filter((k) => (cfgMethodBlockState[k]?.note || '').trim()).length;
  // Prefer counting against live DOM blocks when available
  const total = cfgHtmlLayer?.querySelectorAll('.cfg-block').length || 0;
  if (!total) {
    cfgMeta.textContent = base;
    return;
  }
  let extra = ` · ${readN}/${total} read`;
  if (noteN) extra += ` · ${noteN} noted`;
  const colorN = blocks.filter((k) => normalizeCfgBlockColor(cfgMethodBlockState[k]?.color)).length;
  if (colorN) extra += ` · ${colorN} colored`;
  cfgMeta.textContent = base + extra;
}

function toggleCfgBlockRead(startOffset) {
  const cur = getCfgBlockState(startOffset);
  updateCfgBlockState(startOffset, { read: !cur.read });
  refreshCfgBlockChrome(startOffset);
}

function editCfgBlockNote(startOffset) {
  const cur = getCfgBlockState(startOffset);
  const loc = cfgLocLabel(startOffset);
  const next = window.prompt(`Annotation for ${loc} (empty to clear):`, cur.note || '');
  if (next == null) return;
  updateCfgBlockState(startOffset, { note: next });
  refreshCfgBlockChrome(startOffset);
}

function bindCfgBlockInteractions(nodeById) {
  if (!cfgHtmlLayer || cfgHtmlLayer.dataset.cfgInteractBound === '1') return;
  cfgHtmlLayer.dataset.cfgInteractBound = '1';

  cfgHtmlLayer.addEventListener('pointerdown', (e) => {
    if (e.button !== 0 || !cfgNetwork) return;
    if (e.target.closest('[data-cfg-action]')) return;
    if (e.target.closest('.cfg-block-body') || e.target.closest('.cfg-block-note')) return;
    const head = e.target.closest('.cfg-block-head, .cfg-block-drag');
    if (!head) return;
    const block = e.target.closest('.cfg-block');
    if (!block) return;
    const id = block.getAttribute('data-node-id');
    const startOffset = Number(block.getAttribute('data-start-offset'));
    let pos;
    let scale;
    try {
      pos = cfgNetwork.getPositions([id])[id];
      scale = cfgNetwork.getScale();
    } catch (_) {
      return;
    }
    if (!pos || !Number.isFinite(scale) || scale <= 0) return;
    endCfgBlockDragSession();
    cfgBlockDragSession = {
      id,
      startOffset,
      el: block,
      originX: pos.x,
      originY: pos.y,
      startClientX: e.clientX,
      startClientY: e.clientY,
      scale,
      moved: false,
      pointerId: e.pointerId,
    };
    block.classList.add('cfg-block-dragging');
    cfgGraphWrap?.classList.add('cfg-block-dragging-view');
    try { block.setPointerCapture(e.pointerId); } catch (_) {}
    e.preventDefault();
    e.stopPropagation();
    setCfgNodeSelected(Number(id));
  });

  cfgHtmlLayer.addEventListener('pointermove', (e) => {
    if (!cfgBlockDragSession || !cfgNetwork) return;
    if (cfgBlockDragSession.pointerId != null && e.pointerId !== cfgBlockDragSession.pointerId) return;
    const dx = (e.clientX - cfgBlockDragSession.startClientX) / cfgBlockDragSession.scale;
    const dy = (e.clientY - cfgBlockDragSession.startClientY) / cfgBlockDragSession.scale;
    if (!cfgBlockDragSession.moved && Math.hypot(dx, dy) < 2) return;
    cfgBlockDragSession.moved = true;
    const x = Math.round(cfgBlockDragSession.originX + dx);
    const y = Math.round(cfgBlockDragSession.originY + dy);
    try {
      cfgNetwork.moveNode(cfgBlockDragSession.id, x, y);
      syncCfgHtmlOverlay();
    } catch (_) {}
    e.preventDefault();
  });

  const endDrag = (e) => {
    if (!cfgBlockDragSession) return;
    if (e && cfgBlockDragSession.pointerId != null && e.pointerId !== cfgBlockDragSession.pointerId) return;
    endCfgBlockDragSession();
  };
  cfgHtmlLayer.addEventListener('pointerup', endDrag);
  cfgHtmlLayer.addEventListener('pointercancel', endDrag);

  cfgHtmlLayer.addEventListener('click', (e) => {
    const succ = e.target.closest('.cfg-succ[data-cfg-to]');
    if (succ && cfgHtmlLayer.contains(succ)) {
      e.preventDefault();
      e.stopPropagation();
      const toId = succ.getAttribute('data-cfg-to');
      navigateToCfgNode(toId);
      return;
    }
    const btn = e.target.closest('[data-cfg-action]');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    const start = Number(btn.getAttribute('data-start'));
    if (!Number.isFinite(start)) return;
    const action = btn.getAttribute('data-cfg-action');
    if (action === 'read') toggleCfgBlockRead(start);
    else if (action === 'note') editCfgBlockNote(start);
    else if (action === 'color') openCfgColorPopover(btn, start);
  });
}

function resetCfgMethodLayoutAndRerender() {
  clearCfgMethodLayout();
  const ctx = getCodeViewContext();
  if (!ctx || codeViewMethodIdx == null) return;
  const method = ctx.classes[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
  if (method) renderCfgGraph(method);
}

function renderCfgGraph(method) {
  destroyCfgNetwork();
  clearCfgBlockHighlight();
  loadCfgMethodBlockState();

  if (typeof vis === 'undefined') {
    setCfgEmptyState(true, 'CFG unavailable', 'vis-network failed to load');
    if (cfgMeta) cfgMeta.textContent = '';
    return;
  }

  const { nodes, edges, bytecode } = getMethodCfgData(method);
  if (!nodes.length) {
    setCfgEmptyState(true, 'No CFG', codeViewMethodIdx === null
      ? 'Select a single method (not “All methods”)'
      : 'This method has no control-flow graph');
    if (cfgMeta) cfgMeta.textContent = '';
    return;
  }

  setCfgEmptyState(false);
  const theme = getCfgThemeColors();
  renderCfgLegend(theme);
  if (cfgMeta) {
    const insnCount = bytecode.length;
    cfgMeta.textContent = `${nodes.length} blocks · ${edges.length} edges · ${insnCount} insn`;
  }

  const levelMap = computeCfgLevels(nodes, edges, 0);
  const loopHeaders = computeLoopHeaders(edges, levelMap);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const outEdges = {};
  const outEdgeIndex = {};
  for (const e of edges) {
    if (!outEdges[e.fromId]) outEdges[e.fromId] = [];
    outEdges[e.fromId].push(e.toId);
  }

  const blockKinds = new Map();
  const blockInsns = new Map();
  for (const n of nodes) {
    const insns = bytecodeRowsInBlock(n, bytecode);
    blockInsns.set(n.id, insns);
    blockKinds.set(n.id, classifyCfgBlock(n, insns, loopHeaders));
  }

  const blockHtmlById = new Map();
  for (const n of nodes) {
    const blockKind = blockKinds.get(n.id) || 'normal';
    const insns = blockInsns.get(n.id) || [];
    const succTags = buildCfgSuccessorTags(n.id, outEdges[n.id] || [], nodeById, insns, blockKind);
    blockHtmlById.set(
      n.id,
      buildCfgBlockHtml(n, bytecode, cfgCompactLabels, blockKind, succTags, getCfgBlockState(n.startOffset))
    );
  }

  if (cfgHtmlLayer) {
    cfgHtmlLayer.innerHTML = [...blockHtmlById.values()].join('');
    cfgHtmlLayer.hidden = false;
    cfgHtmlLayer.setAttribute('aria-hidden', 'false');
    refreshBytecodeRegisterHighlight();
    bindCfgBlockInteractions(nodeById);
  }
  updateCfgMetaProgress();
  try { updateAnnotationPanel(); } catch (_) {}
  const blockSizes = measureCfgBlockSizes();
  const blockHeightVals = Object.values(blockSizes).map((s) => s.height);
  const blockWidthVals = Object.values(blockSizes).map((s) => s.width);
  const maxBlockH = blockHeightVals.length ? Math.max(...blockHeightVals) : 80;
  const maxBlockW = blockWidthVals.length ? Math.max(...blockWidthVals) : 220;
  const avgBlockH = blockHeightVals.length
    ? blockHeightVals.reduce((a, b) => a + b, 0) / blockHeightVals.length
    : 80;
  // CFG blocks omit hex — slightly tighter than full listing, still room for mnemonics.
  const cfgLevelSep = Math.round(Math.max(maxBlockH + (cfgCompactLabels ? 64 : 44), avgBlockH + (cfgCompactLabels ? 80 : 56), cfgCompactLabels ? 180 : 140));
  const cfgNodeSpace = Math.round(Math.max(maxBlockW * (cfgCompactLabels ? 0.6 : 0.52) + (cfgCompactLabels ? 56 : 40), cfgCompactLabels ? 240 : 200));
  const cfgTreeSpace = Math.round(Math.max(maxBlockW * (cfgCompactLabels ? 0.9 : 0.75) + (cfgCompactLabels ? 72 : 56), cfgCompactLabels ? 320 : 260));
  const cfgNodeDist = Math.round(Math.max(maxBlockH, maxBlockW) + (cfgCompactLabels ? 96 : 72));
  const cfgNodeMargin = Math.round(Math.max(8, Math.min(16, avgBlockH * 0.06)));

  const visNodes = nodes.map((n) => {
    const size = blockSizes[n.id] || { width: 220, height: 64 };
    return {
      id: n.id,
      shape: 'box',
      label: '',
      // No title — HTML overlay is the only content surface (avoids huge fill-array tooltips).
      level: levelMap[n.id],
      margin: cfgNodeMargin,
      borderWidth: 0,
      widthConstraint: { minimum: size.width, maximum: size.width },
      heightConstraint: { minimum: size.height, maximum: size.height },
      color: {
        border: 'transparent',
        background: 'transparent',
        highlight: { border: 'transparent', background: 'rgba(99, 179, 237, 0.06)' },
        hover: { border: 'transparent', background: 'rgba(99, 179, 237, 0.04)' },
      },
      shapeProperties: { borderRadius: 0 },
      chosen: false,
    };
  });

  const visEdges = edges.map((e) => {
    const outs = outEdges[e.fromId] || [];
    const idx = outEdgeIndex[e.fromId] ?? 0;
    outEdgeIndex[e.fromId] = idx + 1;
    const insns = blockInsns.get(e.fromId) || [];
    const lastMn = insns.length ? insns[insns.length - 1].mnemonic : '';
    const style = buildCfgEdgeStyle(
      e.fromId, e.toId, idx, outs.length, levelMap,
      blockKinds.get(e.fromId), theme, nodeById, lastMn
    );
    // Keep topology for hierarchical layout, but hide vis strokes —
    // sharp 90° polylines are painted in afterDrawing instead.
    return {
      id: `e${e.fromId}-${e.toId}-${idx}`,
      from: e.fromId,
      to: e.toId,
      arrows: { to: false },
      color: { color: 'rgba(0,0,0,0)', highlight: 'rgba(0,0,0,0)', hover: 'rgba(0,0,0,0)', opacity: 0 },
      width: 0,
      hoverWidth: 0,
      selectionWidth: 0,
      label: undefined,
      smooth: false,
      chosen: false,
      // stash style for ortho painter
      _ortho: style,
      _edgeIdx: idx,
      _outCount: outs.length,
    };
  });

  cfgOrthoEdgeState = {
    bg: theme.bg,
    mono: theme.mono,
    sizes: blockSizes,
    edges: visEdges.map((ve, i) => {
      const style = ve._ortho || {};
      const lane = ve._edgeIdx || 0;
      const sideSign = ((ve.from + lane) % 2) === 0 ? 1 : -1;
      return {
        id: ve.id,
        from: ve.from,
        to: ve.to,
        color: style.color,
        highlight: style.highlight || theme.text,
        width: style.width || 2,
        opacity: style.opacity == null ? 1 : style.opacity,
        dashes: !!style.dashes,
        label: style.label || '',
        edgeKind: style.edgeKind || 'flow',
        lane,
        sideSign: style.edgeKind === 'back' ? sideSign : 1,
      };
    }),
  };

  const data = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
  const options = {
    autoResize: true,
    interaction: {
      hover: true,
      tooltipDelay: 120,
      multiselect: false,
      zoomView: false,
      dragView: true,
      // Block moves go through the HTML header handle only (avoids accidental nudges).
      dragNodes: false,
      navigationButtons: false,
      keyboard: { enabled: false },
      selectConnectedEdges: true,
    },
    nodes: {
      borderWidth: 0,
      shapeProperties: { borderRadius: 0 },
      widthConstraint: { minimum: 168, maximum: cfgLayoutMaxWidth() },
    },
    edges: {
      // Invisible — custom orthogonal painter draws sharp H/V polylines
      width: 0,
      selectionWidth: 0,
      hoverWidth: 0,
      smooth: false,
      color: { opacity: 0 },
    },
    layout: {
      hierarchical: {
        enabled: true,
        direction: 'UD',
        sortMethod: 'directed',
        nodeSpacing: cfgNodeSpace,
        levelSeparation: cfgLevelSep,
        treeSpacing: cfgTreeSpace,
        blockShifting: true,
        edgeMinimization: true,
        parentCentralization: true,
      },
    },
    physics: {
      enabled: true,
      hierarchicalRepulsion: { nodeDistance: cfgNodeDist, centralGravity: 0.04, avoidOverlap: 0.95 },
      stabilization: { iterations: cfgCompactLabels ? 180 : 220, fit: true },
    },
  };

  cfgNetwork = new vis.Network(cfgGraphContainer, data, options);
  cfgNetworkDrawHandler = (ctx) => {
    drawCfgOrthogonalEdges(ctx);
    syncCfgHtmlOverlay();
  };
  cfgNetwork.on('afterDrawing', cfgNetworkDrawHandler);
  syncCfgHtmlOverlay();
  cfgNetwork.once('stabilizationIterationsDone', () => {
    cfgNetwork.setOptions({ physics: false });
    // Pixel-snap node centers so orthogonal edges stay axis-aligned and crisp.
    try {
      const pos = cfgNetwork.getPositions();
      const snapped = {};
      for (const [id, p] of Object.entries(pos)) {
        snapped[id] = { x: Math.round(p.x), y: Math.round(p.y) };
      }
      for (const [id, p] of Object.entries(snapped)) {
        cfgNetwork.moveNode(id, p.x, p.y);
      }
    } catch (_) {}
    // Overlay any user-moved block positions without changing the default layout path.
    applySavedCfgBlockPositions(nodes);
    syncCfgHtmlOverlay();
    fitCfgGraph();
  });

  cfgNetwork.on('click', (params) => {
    // Clicking a graph edge jumps to its destination block.
    // Ortho edges are painted manually (vis width:0), so also hit-test polylines.
    if (!params.nodes.length) {
      let toId = null;
      if (params.edges?.length) {
        try {
          const edge = cfgNetwork.body?.data?.edges?.get?.(params.edges[0]);
          if (edge?.to != null) toId = edge.to;
        } catch (_) {}
      }
      if (toId == null) {
        const hit = hitTestCfgOrthoEdge(params.pointer?.DOM);
        if (hit?.to != null) toId = hit.to;
      }
      if (toId != null && navigateToCfgNode(toId)) return;
      setCfgNodeSelected(null);
      return;
    }
    const nodeId = params.nodes[0];
    navigateToCfgNode(nodeId);
  });

  cfgNetwork.on('doubleClick', (params) => {
    if (params.nodes.length) {
      const node = nodes.find((n) => n.id === params.nodes[0]);
      if (node) highlightCfgBlock(node);
    } else {
      fitCfgGraph();
    }
  });

  cfgNetwork.on('deselectNode', () => setCfgNodeSelected(null));
}

/** Simple color mix helper for vis node fills (hex or rgb tokens). */
function colorMix(a, b, t) {
  const parse = (s) => {
    s = String(s || '').trim();
    if (s.startsWith('#') && s.length >= 7) {
      return [parseInt(s.slice(1, 3), 16), parseInt(s.slice(3, 5), 16), parseInt(s.slice(5, 7), 16)];
    }
    const m = s.match(/(\d+)\s+(\d+)\s+(\d+)/);
    if (m) return [+m[1], +m[2], +m[3]];
    return [30, 35, 50];
  };
  const c1 = parse(a);
  const c2 = parse(b);
  const mix = (i) => Math.round(c1[i] + (c2[i] - c1[i]) * t);
  const r = mix(0);
  const g = mix(1);
  const bl = mix(2);
  return `rgb(${r},${g},${bl})`;
}

function clearCfgGraph() {
  destroyCfgNetwork();
  clearCfgBlockHighlight();
  setCfgEmptyState(true, 'No CFG', 'Select a single method to view its control-flow graph');
  if (cfgMeta) cfgMeta.textContent = '';
}

/** Whether CFG applies to the current file (DEX/APK code only — not XML/ARSC/etc.). */
function cfgAppliesToCurrentFile() {
  return currentType === 'dex' || currentType === 'apk';
}

/** Show or fully hide the CFG dock + resizer (not the same as user collapse). */
function setCfgPaneAvailable(available) {
  const workspace = document.getElementById('code-workspace');
  const pane = document.getElementById('cfg-pane');
  const resizer = document.getElementById('resizer-source-cfg');
  if (workspace) workspace.classList.toggle('cfg-unavailable', !available);
  if (pane) {
    pane.hidden = !available;
    pane.setAttribute('aria-hidden', available ? 'false' : 'true');
  }
  if (!available && getMaximizedPane() === 'cfg') {
    setPaneMaximized(null, { persist: false, fit: false });
  }
  if (resizer) resizer.hidden = !available || pane?.dataset.collapsed === 'true' || !!getMaximizedPane();
  if (!available) clearCfgGraph();
  else updateWorkspaceResizers();
}

/** Sync CFG visibility for the current file type (DEX/APK only). */
function syncCfgPaneAvailability() {
  setCfgPaneAvailable(cfgAppliesToCurrentFile());
}

const bytecodeMeta = document.getElementById('bytecode-meta');
const sourceMeta = document.getElementById('source-meta');
const bytecodeSearchInput = document.getElementById('bytecode-search-input');
const bytecodeSearchPrev = document.getElementById('bytecode-search-prev');
const bytecodeSearchNext = document.getElementById('bytecode-search-next');
const bytecodeSearchCount = document.getElementById('bytecode-search-count');
const bytecodeHexToggle = document.getElementById('bytecode-hex-toggle');
const bytecodeToolbar = document.getElementById('bytecode-toolbar');
const bytecodeParamsInput = document.getElementById('bytecode-params');
const bytecodeMaxStepsInput = document.getElementById('bytecode-max-steps');
const bytecodeRunBtn = document.getElementById('bytecode-run');
const bytecodeEmulatorArea = document.getElementById('bytecode-emulator-area');
const bytecodeStepBar = document.getElementById('bytecode-step-bar');
const bytecodeStatePanel = document.getElementById('bytecode-state-panel');
const sourceCode = document.getElementById('source-code');
const sourceSearchInput = document.getElementById('source-search-input');
const sourceSearchPrev = document.getElementById('source-search-prev');
const sourceSearchNext = document.getElementById('source-search-next');
const sourceSearchCount = document.getElementById('source-search-count');
function ensureManifestViewerStructure() {
  const tab = document.getElementById('manifest-tab');
  if (!tab) return { host: null, toolbar: null, code: null };
  if (!document.getElementById('manifest-viewer') || !document.getElementById('manifest-xml')) {
    tab.innerHTML = `
      <div class="res-viewer" id="manifest-viewer">
        <div class="res-viewer-toolbar" id="manifest-toolbar" hidden></div>
        <div class="res-viewer-scroll">
          <pre class="manifest-xml res-xml" id="manifest-xml"></pre>
        </div>
      </div>`;
  }
  manifestXml = document.getElementById('manifest-xml');
  return {
    host: document.getElementById('manifest-viewer'),
    toolbar: document.getElementById('manifest-toolbar'),
    code: manifestXml,
  };
}
let manifestXml = document.getElementById('manifest-xml');
const rawContent = document.getElementById('raw-content'); // legacy; Raw tab now uses hex editor host
const hexEditorHost = document.getElementById('hex-editor-host');
const rawHexEditor = hexEditorHost
  ? createHexEditor(hexEditorHost, {
      onStatus: (msg) => {
        if (msg) debug('[hex]', msg);
      },
    })
  : null;
const centerTabsDynamic = document.getElementById('center-tabs-dynamic');
const centerTabsFilesGroup = document.getElementById('center-tabs-files-group');
const centerTabsSep = document.getElementById('center-tabs-sep');
const centerTabsCloseAllBtn = document.getElementById('center-tabs-close-all');
const centerTabsMenuBtn = document.getElementById('center-tabs-menu-btn');
const centerTabsMenu = document.getElementById('center-tabs-menu');

const PERMANENT_CENTER_TABS = [
  { id: 'bytecode-tab', label: 'Code' },
  { id: 'manifest-tab', label: 'Manifest' },
  { id: 'permissions-tab', label: 'Permissions' },
  { id: 'components-tab', label: 'Components' },
  { id: 'raw-tab', label: 'Raw' },
  { id: 'info-tab', label: 'Info' },
  { id: 'strings-tab', label: 'Strings' },
  { id: 'security-tab', label: 'Security' },
];

function getVisiblePermanentCenterTabs() {
  const conditional = new Set(['permissions-tab', 'components-tab']);
  return PERMANENT_CENTER_TABS.filter((t) => {
    if (!conditional.has(t.id)) return true;
    const btn = document.getElementById(
      t.id === 'permissions-tab' ? 'permissions-tab-btn' : 'components-tab-btn'
    );
    return btn && !btn.hidden;
  });
}

function getActiveCenterTabId() {
  return document.querySelector('.center-panel .tab-btn.active')?.dataset?.tab || 'bytecode-tab';
}

function updateCenterTabsChrome() {
  const hasFiles = apkOpenFileTabs.length > 0;
  if (centerTabsFilesGroup) centerTabsFilesGroup.hidden = !hasFiles;
  if (centerTabsSep) centerTabsSep.hidden = !hasFiles;
  if (centerTabsCloseAllBtn) centerTabsCloseAllBtn.hidden = !hasFiles;
  if (centerTabsMenu && !centerTabsMenu.hidden) renderCenterTabsMenu();
}

function setCenterTabsMenuOpen(open) {
  if (!centerTabsMenu || !centerTabsMenuBtn) return;
  centerTabsMenu.hidden = !open;
  centerTabsMenuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) renderCenterTabsMenu();
}

function renderCenterTabsMenu() {
  if (!centerTabsMenu) return;
  const activeId = getActiveCenterTabId();
  let html = '<div class="center-tabs-menu-section">Permanent</div>';
  for (const t of getVisiblePermanentCenterTabs()) {
    html += `<button type="button" class="center-tabs-menu-item${activeId === t.id ? ' is-active' : ''}" role="menuitem" data-tab-goto="${escapeAttr(t.id)}">` +
      `<span class="center-tabs-menu-item-label">${escapeHtml(t.label)}</span>` +
      `<span class="center-tabs-menu-item-kind">workspace</span></button>`;
  }
  html += '<div class="center-tabs-menu-section">Opened files</div>';
  if (!apkOpenFileTabs.length) {
    html += '<div class="center-tabs-menu-empty">No file tabs open</div>';
  } else {
    for (const t of apkOpenFileTabs) {
      const kind = t.kind || 'file';
      html += `<div class="center-tabs-menu-item${activeId === t.id ? ' is-active' : ''}" role="menuitem">` +
        `<button type="button" class="center-tabs-menu-item-label" data-tab-goto="${escapeAttr(t.id)}" title="${escapeAttr(t.name)}">${escapeHtml(t.name)}</button>` +
        `<span class="center-tabs-menu-item-kind">${escapeHtml(kind)}</span>` +
        `<button type="button" class="center-tabs-menu-item-close" data-tab-close="${escapeAttr(t.id)}" aria-label="Close ${escapeAttr(t.name)}" title="Close">×</button>` +
        `</div>`;
    }
  }
  centerTabsMenu.innerHTML = html;
}

function shortFileTabLabel(name) {
  if (!name) return 'file';
  const parts = String(name).split('/');
  return parts[parts.length - 1] || name;
}
const centerTabContentsParent = document.getElementById('bytecode-tab').parentElement;
const infoContent = document.getElementById('info-content');
const stringsList = document.getElementById('strings-list');
const stringsSearchInput = document.getElementById('strings-search');
const stringsCountEl = document.getElementById('strings-count');
const stringsDetail = document.getElementById('strings-detail');
const stringsDetailMeta = document.getElementById('strings-detail-meta');
const stringsDetailText = document.getElementById('strings-detail-text');
const stringsRegexCb = document.getElementById('strings-regex');
const stringsCaseCb = document.getElementById('strings-case');
const stringsMinLenInput = document.getElementById('strings-min-len');
const stringsSortSelect = document.getElementById('strings-sort');
const stringsCopyBtn = document.getElementById('strings-copy');
const stringsExportBtn = document.getElementById('strings-export');
const stringsJumpRawBtn = document.getElementById('strings-jump-raw');
const stringsDetailCopyBtn = document.getElementById('strings-detail-copy');
const stringsFiltersEl = document.getElementById('strings-filters');
const methodSelect = document.getElementById('method-select');
const codeViewToolbar = document.getElementById('code-view-toolbar');
const codePackageWrap = document.getElementById('code-package-wrap');
const codePackageSelect = document.getElementById('code-package-select');
const classSelectorWrap = document.getElementById('class-selector-wrap');
const dropZone = document.getElementById('drop-zone');
const searchInput = document.getElementById('search-input');
const loadingOverlay = document.getElementById('loading-overlay');

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    btn.closest('.center-tabs, .right-tabs')?.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    btn.closest('.panel')?.querySelectorAll('.tab-content').forEach(c => {
      c.classList.toggle('active', c.id === tab);
    });
    closeMobileNavIfNeeded();
    if (tab === 'strings-tab') {
      scheduleEnsureDexStringsLoaded();
      requestAnimationFrame(() => paintStringsVirtualWindow());
    }
    if (tab === 'raw-tab' && rawHexEditor && typeof rawHexEditor.refresh === 'function') {
      requestAnimationFrame(() => rawHexEditor.refresh());
    }
    if (tab === 'permissions-tab') {
      renderPermissionsTab();
      ensurePermissionUsageIndex().then(() => renderPermissionsTab()).catch(() => {});
    }
    if (tab === 'components-tab') {
      renderComponentsTab();
    }
  });
});

if (stringsSearchInput) {
  stringsSearchInput.addEventListener('input', () => scheduleRenderStringsList());
  stringsSearchInput.addEventListener('keydown', (e) => e.stopPropagation());
}
[stringsRegexCb, stringsCaseCb, stringsMinLenInput, stringsSortSelect].forEach((el) => {
  el?.addEventListener('change', () => scheduleRenderStringsList(true));
  el?.addEventListener('input', () => scheduleRenderStringsList());
});
stringsFiltersEl?.addEventListener('click', (e) => {
  const chip = e.target.closest('.strings-chip[data-filter]');
  if (!chip) return;
  stringsTypeFilter = chip.dataset.filter || 'all';
  stringsFiltersEl.querySelectorAll('.strings-chip').forEach((c) => {
    c.classList.toggle('active', c === chip);
  });
  scheduleRenderStringsList(true);
});
stringsCopyBtn?.addEventListener('click', () => copySelectedOrFilteredStrings());
stringsExportBtn?.addEventListener('click', () => exportFilteredStrings());
stringsJumpRawBtn?.addEventListener('click', () => {
  if (stringsSelectedIdx == null) return;
  jumpStringToHexEditor(currentStringsArray[stringsSelectedIdx]);
});
stringsDetailCopyBtn?.addEventListener('click', () => {
  if (stringsSelectedIdx == null) return;
  copyTextToClipboard(String(currentStringsArray[stringsSelectedIdx] ?? ''), 'String copied');
});
document.getElementById('strings-detail-usages')?.addEventListener('click', (e) => {
  const rawBtn = e.target.closest('[data-raw-off]');
  if (rawBtn && document.getElementById('strings-detail-usages')?.contains(rawBtn)) {
    e.preventDefault();
    const off = parseInt(rawBtn.getAttribute('data-raw-off'), 10);
    if (!Number.isNaN(off)) jumpDexOffsetToHexEditor(off);
    return;
  }
  const codeBtn = e.target.closest('.strings-usage-link[data-class]');
  if (codeBtn && document.getElementById('strings-detail-usages')?.contains(codeBtn)) {
    e.preventDefault();
    const className = codeBtn.getAttribute('data-class') || '';
    const methodName = codeBtn.getAttribute('data-method') || '';
    const offsetRaw = codeBtn.getAttribute('data-offset');
    const offset = offsetRaw !== '' && offsetRaw != null ? parseInt(offsetRaw, 10) : null;
    if (!className) return;
    navigateToSecurityFinding(className, methodName, '', {
      offset: Number.isFinite(offset) ? offset : undefined,
      hint: '',
    });
  }
});
if (stringsList) {
  stringsList.addEventListener('scroll', () => paintStringsVirtualWindow(), { passive: true });
  stringsList.addEventListener('click', (e) => {
    const item = e.target.closest('.string-item[data-string-idx]');
    if (!item) return;
    const idx = parseInt(item.dataset.stringIdx, 10);
    if (Number.isNaN(idx) || idx < 0 || idx >= currentStringsArray.length) return;
    selectStringIndex(idx, { scrollIntoView: false });
  });
  stringsList.addEventListener('dblclick', (e) => {
    const item = e.target.closest('.string-item[data-string-idx]');
    if (!item) return;
    const idx = parseInt(item.dataset.stringIdx, 10);
    if (Number.isNaN(idx)) return;
    jumpStringToHexEditor(currentStringsArray[idx]);
  });
  stringsList.addEventListener('keydown', (e) => {
    if (!stringsFilteredIdx.length) return;
    const curPos = stringsSelectedIdx == null
      ? -1
      : stringsFilteredIdx.indexOf(stringsSelectedIdx);
    if (e.key === 'ArrowDown' || e.key === 'j') {
      e.preventDefault();
      const next = Math.min(stringsFilteredIdx.length - 1, Math.max(0, curPos + 1));
      selectStringIndex(stringsFilteredIdx[next], { scrollIntoView: true });
    } else if (e.key === 'ArrowUp' || e.key === 'k') {
      e.preventDefault();
      const next = Math.max(0, curPos <= 0 ? 0 : curPos - 1);
      selectStringIndex(stringsFilteredIdx[next], { scrollIntoView: true });
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (stringsSelectedIdx != null) jumpStringToHexEditor(currentStringsArray[stringsSelectedIdx]);
    } else if ((e.key === 'c' || e.key === 'C') && (e.metaKey || e.ctrlKey)) {
      if (stringsSelectedIdx != null) {
        e.preventDefault();
        copyTextToClipboard(String(currentStringsArray[stringsSelectedIdx] ?? ''), 'String copied');
      }
    } else if (e.key === 'Home') {
      e.preventDefault();
      selectStringIndex(stringsFilteredIdx[0], { scrollIntoView: true });
    } else if (e.key === 'End') {
      e.preventDefault();
      selectStringIndex(stringsFilteredIdx[stringsFilteredIdx.length - 1], { scrollIntoView: true });
    }
  });
}
if (infoContent) {
  infoContent.addEventListener('click', (e) => {
    const classBtn = e.target.closest('button.info-class-link');
    if (classBtn) {
      e.preventDefault();
      const className = classBtn.dataset.class || '';
      if (!className) return;
      openClassFromManifest(null, null, className);
      return;
    }
    const resBtn = e.target.closest('button.info-res-link, img.info-res-thumb');
    if (resBtn) {
      e.preventDefault();
      const path = resBtn.dataset.path || '';
      if (!path) return;
      openApkResourceFile(path);
      return;
    }
    const btn = e.target.closest('button.info-perm-use');
    if (!btn) return;
    e.preventDefault();
    handlePermissionUsageClick(btn);
  });
}

document.getElementById('perms-body')?.addEventListener('click', (e) => {
  const btn = e.target.closest('button.info-perm-use, button.perms-use');
  if (!btn) return;
  e.preventDefault();
  handlePermissionUsageClick(btn);
});

function handlePermissionUsageClick(btn) {
  const className = btn.dataset.class || '';
  const methodName = btn.dataset.method || '';
  const dexFile = btn.dataset.dex || '';
  const offsetRaw = btn.dataset.offset;
  const offset = offsetRaw !== '' && offsetRaw != null ? Number(offsetRaw) : null;
  navigateToSecurityFinding(className, methodName, dexFile, {
    offset: Number.isFinite(offset) ? offset : null,
    hint: '',
  });
}

if (methodSelect) {
  methodSelect.addEventListener('change', () => {
    const val = methodSelect.value;
    codeViewMethodIdx = val === 'all' ? null : parseInt(val, 10);
    if (currentType === 'apk' && apkExtractedFile?.kind === 'dex') {
      apkExtractedDexSelection = { classIdx: codeViewClassIdx, methodIdx: codeViewMethodIdx ?? 0 };
    }
    syncBackToClassButton();
    updateSourceNavBackBtn();
    updateCodeView();
  });
}
document.getElementById('code-back-to-class')?.addEventListener('click', () => goBackToClassView());
wireAnnotationPanel();
wireTreeBookmarkStars();
const apkDexClassToolbar = document.getElementById('apk-dex-class-toolbar');
const classSearchInput = document.getElementById('class-search-input');
if (codePackageSelect) {
  codePackageSelect.addEventListener('change', () => {
    codeViewPackage = (codePackageSelect.value || '').trim();
    // Keep left-bar package selector + class tree in sync with the code toolbar.
    selectedDexPackage = codeViewPackage;
    if (dexPackageSelect) dexPackageSelect.value = selectedDexPackage || '';
    const ctx = getCodeViewContext();
    if (ctx) {
      const classes = ctx.classes;
      const inPackage = getClassesInPackage(classes, codeViewPackage);
      if (inPackage.length > 0) {
        codeViewClassIdx = inPackage[0];
        if (ctx.isApk) apkExtractedDexSelection = { classIdx: codeViewClassIdx, methodIdx: 0 };
      }
      codeViewMethodIdx = null;
    }
    updateCodeView();
    if (currentType === 'dex' && currentData != null) {
      const classes = Array.isArray(currentData.classes) ? currentData.classes : [];
      renderClassTreeFromPackageMap(classes, buildDexPackageMap(classes), { isApk: false });
    } else if (currentType === 'apk' && apkLeftMode === 'classes') {
      renderApkClassTree();
    }
  });
}
if (apkDexClassToolbar) {
  apkDexClassToolbar.addEventListener('change', () => {
    codeViewClassIdx = parseInt(apkDexClassToolbar.value, 10);
    apkExtractedDexSelection = { classIdx: codeViewClassIdx, methodIdx: 0 };
    codeViewMethodIdx = null;
    const methodSearchEl = document.getElementById('method-search-input');
    if (methodSearchEl) methodSearchEl.value = '';
    updateCodeView();
  });
}
function filterClassDropdown() {
  const sel = document.getElementById('apk-dex-class-toolbar');
  const searchEl = document.getElementById('class-search-input');
  if (!sel || !searchEl) return;
  const q = (searchEl.value || '').trim().toLowerCase();
  for (let i = 0; i < sel.options.length; i++) {
    const opt = sel.options[i];
    const text = (opt.textContent || opt.innerText || '').toLowerCase();
    opt.hidden = q ? !text.includes(q) : false;
  }
}

/** Filter the Method dropdown by name / descriptor (mirrors class Filter…). */
function filterMethodDropdown() {
  const sel = document.getElementById('method-select');
  const searchEl = document.getElementById('method-search-input');
  if (!sel || !searchEl) return;
  const q = (searchEl.value || '').trim().toLowerCase();
  let visible = 0;
  for (let i = 0; i < sel.options.length; i++) {
    const opt = sel.options[i];
    if (opt.value === 'all') {
      opt.hidden = false;
      continue;
    }
    const hay = (
      opt.getAttribute('data-search')
      || opt.textContent
      || opt.innerText
      || ''
    ).toLowerCase();
    const show = !q || hay.includes(q);
    opt.hidden = !show;
    if (show) visible += 1;
  }
  // Keep "All methods" label honest while filtering
  const allOpt = sel.querySelector('option[value="all"]');
  if (allOpt && q) {
    allOpt.textContent = `All matching (${visible})`;
  } else if (allOpt) {
    const total = Math.max(0, sel.options.length - 1);
    allOpt.textContent = `All methods (${total})`;
  }
}

function refillMethodSelectOptions(methods, classDisplayName) {
  if (!methodSelect) return;
  const prev = methodSelect.value;
  methodSelect.innerHTML = `<option value="all">All methods (${methods.length})</option>` + methods.map((m, i) => {
    const name = getDisplayMethodName(classDisplayName, m?.name || ('method ' + i));
    const desc = String(m?.descriptor || '');
    const search = `${name} ${m?.name || ''} ${desc}`.toLowerCase();
    const label = desc ? `${name}${desc}` : name;
    return `<option value="${i}" data-search="${escapeAttr(search)}" title="${escapeAttr(label)}">${escapeHtml(name)}</option>`;
  }).join('');
  const want = codeViewMethodIdx === null ? 'all' : String(codeViewMethodIdx);
  methodSelect.value = [...methodSelect.options].some((o) => o.value === want) ? want : (prev === 'all' ? 'all' : want);
  if (![...methodSelect.options].some((o) => o.value === methodSelect.value)) {
    methodSelect.value = 'all';
  }
  filterMethodDropdown();
}

if (classSearchInput) {
  classSearchInput.addEventListener('input', () => filterClassDropdown());
  classSearchInput.addEventListener('keydown', (e) => e.stopPropagation());
}
const methodSearchInput = document.getElementById('method-search-input');
if (methodSearchInput) {
  methodSearchInput.addEventListener('input', () => filterMethodDropdown());
  methodSearchInput.addEventListener('keydown', (e) => {
    e.stopPropagation();
    if (e.key === 'Enter') {
      e.preventDefault();
      // Jump to first visible method match
      const sel = methodSelect;
      if (!sel) return;
      for (let i = 0; i < sel.options.length; i++) {
        const opt = sel.options[i];
        if (opt.hidden || opt.value === 'all') continue;
        sel.value = opt.value;
        sel.dispatchEvent(new Event('change', { bubbles: true }));
        break;
      }
    }
  });
}
if (dexPackageSelect) {
  dexPackageSelect.addEventListener('change', () => {
    selectedDexPackage = (dexPackageSelect.value || '').trim();
    if (currentType === 'dex' && currentData != null) render();
    else if (currentType === 'apk' && apkLeftMode === 'classes') renderApkClassTree();
  });
}
if (dexFileSelect) {
  dexFileSelect.addEventListener('change', () => {
    if (currentType === 'apk') {
      const name = (dexFileSelect.value || '').trim();
      apkDexFilter = name; // '' = All DEXes
      selectedDexPackage = '';
      codeViewPackage = '';
      if (name) {
        showApkFile(name).then(() => {
          if (apkLeftMode === 'classes' && apkDexFilter === name) renderApkClassTree();
        }).catch((e) => warn('[dexFileSelect] APK DEX switch failed', e));
      } else if (apkLeftMode === 'classes') {
        renderApkClassTree();
        ensureApkClassIndex().then(() => {
          if (apkLeftMode === 'classes' && !apkDexFilter) renderApkClassTree();
        }).catch(() => {});
      }
      return;
    }
    const idx = parseInt(dexFileSelect.value, 10);
    if (!Number.isNaN(idx)) switchActiveDex(idx);
  });
}
document.getElementById('left-panel-modes')?.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-apk-mode]');
  if (!btn || currentType !== 'apk') return;
  const mode = btn.getAttribute('data-apk-mode');
  if (mode !== 'files' && mode !== 'classes') return;
  setApkLeftMode(mode);
});
if (sourceSearchInput) {
  sourceSearchInput.addEventListener('input', () => {
    sourceSearchQuery = sourceSearchInput.value || '';
    sourceSearchMatchIndex = 0;
    renderSourceWithSearch();
  });
  sourceSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) sourceSearchPrev?.click();
      else sourceSearchNext?.click();
    }
  });
}
if (sourceSearchPrev) {
  sourceSearchPrev.addEventListener('click', () => {
    if (sourceSearchMatches.length === 0) return;
    sourceSearchMatchIndex = (sourceSearchMatchIndex - 1 + sourceSearchMatches.length) % sourceSearchMatches.length;
    sourceSearchMatches.forEach((m, i) => m.classList.toggle('current', i === sourceSearchMatchIndex));
    sourceSearchMatches[sourceSearchMatchIndex]?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    if (sourceSearchCount) sourceSearchCount.textContent = (sourceSearchMatchIndex + 1) + ' / ' + sourceSearchMatches.length;
  });
}
if (sourceSearchNext) {
  sourceSearchNext.addEventListener('click', () => {
    if (sourceSearchMatches.length === 0) return;
    sourceSearchMatchIndex = (sourceSearchMatchIndex + 1) % sourceSearchMatches.length;
    sourceSearchMatches.forEach((m, i) => m.classList.toggle('current', i === sourceSearchMatchIndex));
    sourceSearchMatches[sourceSearchMatchIndex]?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    if (sourceSearchCount) sourceSearchCount.textContent = (sourceSearchMatchIndex + 1) + ' / ' + sourceSearchMatches.length;
  });
}

/** Collect all foldable start keys for the currently displayed source. */
function collectCurrentFoldKeys() {
  const keys = [];
  const addFor = (raw, prefix) => {
    const improved = improveDecompiledJava(raw || '');
    const lines = improved.split('\n');
    const braceRanges = findBraceFoldRanges(lines);
    const arrayFolds = findLongArrayLineFolds(lines);
    const starts = new Set();
    for (const r of braceRanges) starts.add(r.start);
    for (const r of arrayFolds) starts.add(r.start);
    for (const s of starts) keys.push(prefix + ':' + s);
  };
  if (currentSourceBlocks && currentSourceBlocks.length > 0) {
    currentSourceBlocks.forEach((b, bi) => addFor(b.raw, 'm' + bi));
  } else if (currentSourceRaw) {
    addFor(currentSourceRaw, 's');
  }
  return keys;
}

document.getElementById('source-fold-all')?.addEventListener('click', () => {
  for (const k of collectCurrentFoldKeys()) sourceFoldedStarts.add(k);
  renderSourceWithSearch();
});
document.getElementById('source-unfold-all')?.addEventListener('click', () => {
  for (const k of collectCurrentFoldKeys()) sourceFoldedStarts.delete(k);
  renderSourceWithSearch();
});
document.getElementById('source-export-btn')?.addEventListener('click', (e) => {
  e.preventDefault();
  const r = e.currentTarget.getBoundingClientRect();
  openSourceExportMenu(r.left, r.bottom + 4);
});

/* Dock collapse + bytecode search / hex toggle */
(function initCodeViewChrome() {
  let showHex = true;
  let bytecodeOpen = true;
  let sourceOpen = true;
  let cfgOpen = true;
  let emulatorOpen = false;
  try {
    const storedHex = localStorage.getItem('droid2web-show-hex');
    if (storedHex == null && window.matchMedia('(max-width: 768px)').matches) showHex = false;
    else showHex = storedHex !== '0';
    // Bytecode is the primary top pane — default open.
    bytecodeOpen = localStorage.getItem('droid2web-bytecode-open') !== '0';
    sourceOpen = localStorage.getItem('droid2web-source-open') !== '0';
    cfgOpen = localStorage.getItem('droid2web-cfg-open') !== '0';
    emulatorOpen = localStorage.getItem('droid2web-emulator-open') === '1';
    cfgCompactLabels = localStorage.getItem('droid2web-cfg-compact') === '1';
    cfgShowAddr = localStorage.getItem('droid2web-cfg-show-addr') !== '0';
  } catch (_) {}
  if (bytecodeHexToggle) {
    bytecodeHexToggle.checked = showHex;
    bytecodeHexToggle.addEventListener('change', () => applyHexVisibility(!!bytecodeHexToggle.checked));
  }
  function rerenderCfgIfMethodSelected() {
    const ctx = getCodeViewContext();
    if (ctx && codeViewMethodIdx != null) {
      const method = ctx.classes[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
      if (method) renderCfgGraph(method);
    }
  }
  const cfgCompactToggle = document.getElementById('cfg-compact-toggle');
  if (cfgCompactToggle) {
    cfgCompactToggle.checked = cfgCompactLabels;
    cfgCompactToggle.addEventListener('change', () => {
      cfgCompactLabels = !!cfgCompactToggle.checked;
      try { localStorage.setItem('droid2web-cfg-compact', cfgCompactLabels ? '1' : '0'); } catch (_) {}
      rerenderCfgIfMethodSelected();
    });
  }
  const cfgAddrToggle = document.getElementById('cfg-addr-toggle');
  if (cfgAddrToggle) {
    cfgAddrToggle.checked = cfgShowAddr;
    cfgAddrToggle.addEventListener('change', () => {
      cfgShowAddr = !!cfgAddrToggle.checked;
      try { localStorage.setItem('droid2web-cfg-show-addr', cfgShowAddr ? '1' : '0'); } catch (_) {}
      rerenderCfgIfMethodSelected();
    });
  }
  applyHexVisibility(showHex);
  setDockCollapsed(document.getElementById('cfg-pane'), !cfgOpen, 'droid2web-cfg-open');
  setDockCollapsed(document.getElementById('bytecode-pane'), !bytecodeOpen, 'droid2web-bytecode-open');
  setDockCollapsed(document.getElementById('source-pane'), !sourceOpen, 'droid2web-source-open');
  setDockCollapsed(document.getElementById('bytecode-emulator-area'), !emulatorOpen, 'droid2web-emulator-open');
  syncCfgPaneAvailability();
  updateWorkspaceResizers();

  document.getElementById('cfg-collapse-btn')?.addEventListener('click', () => {
    const pane = document.getElementById('cfg-pane');
    const next = pane?.dataset.collapsed !== 'true';
    setDockCollapsed(pane, next, 'droid2web-cfg-open');
    updateWorkspaceResizers();
    if (!next && cfgNetwork) {
      setTimeout(() => {
        try { cfgNetwork.redraw(); } catch (_) {}
        fitCfgGraph();
      }, 140);
    }
  });
  document.getElementById('bytecode-collapse-btn')?.addEventListener('click', () => {
    const pane = document.getElementById('bytecode-pane');
    const next = pane?.dataset.collapsed !== 'true';
    setDockCollapsed(pane, next, 'droid2web-bytecode-open');
    updateWorkspaceResizers();
  });
  document.getElementById('source-collapse-btn')?.addEventListener('click', () => {
    const pane = document.getElementById('source-pane');
    const next = pane?.dataset.collapsed !== 'true';
    setDockCollapsed(pane, next, 'droid2web-source-open');
    updateWorkspaceResizers();
  });
  document.getElementById('emulator-collapse-btn')?.addEventListener('click', () => {
    const pane = document.getElementById('bytecode-emulator-area');
    const next = pane?.dataset.collapsed !== 'true';
    setDockCollapsed(pane, next, 'droid2web-emulator-open');
    updateWorkspaceResizers();
  });
  wireDebugConsoleUi();

  document.getElementById('cfg-fit-btn')?.addEventListener('click', () => fitCfgGraph());
  document.getElementById('cfg-zoom-in-btn')?.addEventListener('click', () => zoomCfgGraph(1.25));
  document.getElementById('cfg-zoom-out-btn')?.addEventListener('click', () => zoomCfgGraph(0.8));
  document.getElementById('cfg-maximize-btn')?.addEventListener('click', () => toggleCfgFullscreen());
  document.getElementById('cfg-fullscreen-btn')?.addEventListener('click', () => toggleCfgFullscreen());
  document.getElementById('bytecode-maximize-btn')?.addEventListener('click', () => togglePaneMaximized('bytecode'));
  document.getElementById('source-maximize-btn')?.addEventListener('click', () => togglePaneMaximized('source'));
  const onCfgBrowserFullscreenChange = () => {
    const pane = document.getElementById('cfg-pane');
    const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
    if (fsEl === pane) {
      document.body.classList.add('cfg-fullscreen');
      if (getMaximizedPane() !== 'cfg') setPaneMaximized('cfg', { persist: true, fit: false });
      syncPaneMaximizeButtons();
      fitCfgAfterLayout();
      return;
    }
    if (document.body.classList.contains('cfg-fullscreen') && !fsEl) {
      document.body.classList.remove('cfg-fullscreen');
      if (getMaximizedPane() === 'cfg') setPaneMaximized(null, { persist: true, fit: true });
      else syncPaneMaximizeButtons();
    }
  };
  document.addEventListener('fullscreenchange', onCfgBrowserFullscreenChange);
  document.addEventListener('webkitfullscreenchange', onCfgBrowserFullscreenChange);
  document.getElementById('cfg-reset-layout-btn')?.addEventListener('click', () => {
    if (cfgMethodHasCustomLayout()) {
      if (!window.confirm('Reset CFG block positions for this method?\n\nRead marks and notes are kept.')) return;
    }
    resetCfgMethodLayoutAndRerender();
  });
  const cfgInsnHost = cfgHtmlLayer || cfgGraphContainer;
  if (cfgInsnHost && !cfgInsnHost.dataset.insnWire) {
    cfgInsnHost.dataset.insnWire = '1';
    cfgInsnHost.addEventListener('mousedown', (e) => {
      const insn = e.target.closest('.bytecode-line.cfg-insn-line');
      if (!insn) return;
      e.stopPropagation();
      const off = parseInt(insn.getAttribute('data-off'), 10);
      const nodeId = parseInt(insn.closest('.cfg-block')?.getAttribute('data-node-id'), 10);
      if (Number.isNaN(nodeId) || Number.isNaN(off)) return;
      setCfgNodeSelected(nodeId);
      const ctx = getCodeViewContext();
      const method = ctx?.classes?.[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
      if (!method) return;
      const { nodes } = getMethodCfgData(method);
      const node = nodes.find((n) => n.id === nodeId);
      if (node) highlightCfgBlock(node, off);
    }, true);
  }
  document.getElementById('cfg-show-bytecode-btn')?.addEventListener('click', () => {
    if (getMaximizedPane()) setPaneMaximized(null, { fit: false });
    const pane = document.getElementById('bytecode-pane');
    setDockCollapsed(pane, false, 'droid2web-bytecode-open');
    updateWorkspaceResizers();
    bytecodeListing?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || e.defaultPrevented) return;
    if (!getMaximizedPane() && !isCfgFullscreen()) return;
    const t = e.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
    // Browser fullscreen consumes Esc first; CSS-only fullscreen we exit here
    if (isCfgFullscreen() && !document.fullscreenElement && !document.webkitFullscreenElement) {
      e.preventDefault();
      setCfgFullscreen(false);
      return;
    }
    if (getMaximizedPane() && getMaximizedPane() !== 'cfg') {
      e.preventDefault();
      setPaneMaximized(null);
    }
  });
  // Restore maximized preference after helpers are defined (see restorePaneMaximizedPreference).

  if (bytecodeSearchInput) {
    bytecodeSearchInput.addEventListener('input', () => {
      bytecodeSearchQuery = bytecodeSearchInput.value || '';
      bytecodeSearchMatchIndex = 0;
      applyBytecodeSearch();
    });
    bytecodeSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (e.shiftKey) bytecodeSearchPrev?.click();
        else bytecodeSearchNext?.click();
      }
    });
  }
  if (bytecodeSearchPrev) {
    bytecodeSearchPrev.addEventListener('click', () => {
      if (bytecodeSearchMatches.length === 0) return;
      bytecodeSearchMatchIndex = (bytecodeSearchMatchIndex - 1 + bytecodeSearchMatches.length) % bytecodeSearchMatches.length;
      applyBytecodeSearch();
    });
  }
  if (bytecodeSearchNext) {
    bytecodeSearchNext.addEventListener('click', () => {
      if (bytecodeSearchMatches.length === 0) return;
      bytecodeSearchMatchIndex = (bytecodeSearchMatchIndex + 1) % bytecodeSearchMatches.length;
      applyBytecodeSearch();
    });
  }
})();

/** Build rename menu items scoped to the click target (method chrome ≠ body word ≠ class).
 *  Variable renames are source-only; bytecode allows method / field (and tree handles class). */
function buildCodeViewRenameMenuItems(wordAtCursor, event, opts = {}) {
  const allowVariables = opts.allowVariables !== false;
  const ctx = getCodeViewContext();
  if (!ctx) return null;
  const { classes } = ctx;
  const resolved = resolveMethodFromEvent(event);
  const className = resolved?.className ?? classes[codeViewClassIdx]?.name ?? '';
  const methodName = resolved?.origName || '';
  const methodKey = resolved?.methodKey || (className && methodName ? `${className}#${methodName}` : '');
  const displayMethod = methodName ? getDisplayMethodName(className, methodName) : '';
  const word = (wordAtCursor || '').trim();
  const target = event?.target;
  const onMethodChrome = !!target?.closest?.(
    '.method-block-header, .method-block-name, .method-block-actions, [data-open-cfg]'
  );
  const wordIsMethodName = !!(
    word
    && methodName
    && (word === methodName || word === displayMethod)
  );

  const methodItems = () => {
    if (!methodName || !methodKey) return [];
    const curMethod = dexRenames.method[methodKey];
    const items = [{
      label: curMethod ? `Rename method → ${curMethod}…` : 'Rename method…',
      onChoose: () => {
        const newName = promptRename('method', getDisplayMethodName(className, methodName));
        if (!newName) return;
        dexRenames.method[methodKey] = newName;
        commitDexRenamesChange();
      },
    }];
    if (curMethod) {
      items.push({
        label: 'Clear method rename',
        onChoose: () => {
          delete dexRenames.method[methodKey];
          commitDexRenamesChange();
        },
      });
    }
    return items;
  };

  // Click on method header / method name → rename method only (never class/field/var).
  if (onMethodChrome || wordIsMethodName) {
    const items = methodItems();
    return items.length ? items : null;
  }

  // Click on an identifier in the body → variable (source only) and/or field.
  if (word && isValidJavaSimpleName(word)) {
    const items = [];
    const looksLikeField = (() => {
      const lineEl = target?.closest?.('.src-line-code, .xml-lc, .bc-line, .bytecode-line');
      const text = (lineEl?.textContent || target?.textContent || '').toString();
      const idx = text.indexOf(word);
      if (idx <= 0) return false;
      return text[idx - 1] === '.';
    })();

    // Variable renames only in decompiled source — not bytecode registers / operands.
    if (allowVariables && methodKey && !looksLikeField) {
      const { orig, current: curVar } = resolveVariableRenameEntry(methodKey, word);
      items.push({
        label: curVar ? `Rename variable "${word}" → ${curVar}…` : `Rename variable "${word}"…`,
        onChoose: () => {
          const newName = promptRename('variable', curVar || word);
          if (!newName) return;
          setVariableRename(methodKey, word, newName);
          commitDexRenamesChange({ wholeClass: false });
        },
      });
      if (curVar || orig !== word) {
        items.push({
          label: `Clear variable rename "${word}"`,
          onChoose: () => {
            clearVariableRename(methodKey, word);
            commitDexRenamesChange({ wholeClass: false });
          },
        });
      }
    } else if (className && (looksLikeField || (allowVariables && !methodKey))) {
      // Field access (obj.foo), or source with no method context → field rename.
      // Bytecode: only when the token looks like a field ref (dotted).
      const fieldKey = className + '#' + word;
      const curField = dexRenames.field[fieldKey];
      items.push({
        label: curField ? `Rename field "${word}" → ${curField}…` : `Rename field "${word}"…`,
        onChoose: () => {
          const newName = promptRename('field', curField || getDisplayFieldName(className, word));
          if (!newName) return;
          dexRenames.field[fieldKey] = newName;
          commitDexRenamesChange({ wholeClass: true });
        },
      });
      if (curField) {
        items.push({
          label: `Clear field rename "${word}"`,
          onChoose: () => {
            delete dexRenames.field[fieldKey];
            commitDexRenamesChange({ wholeClass: true });
          },
        });
      }
    }

    return items.length ? items : null;
  }

  // Empty background click: do not offer a grab-bag of renames.
  return null;
}

if (sourceCode) {
  sourceCode.addEventListener('contextmenu', (e) => {
    const identEl = e.target?.closest?.('.src-ident');
    const word = (
      window.getSelection()?.toString()?.trim()
      || (identEl && (identEl.getAttribute('data-ident') || identEl.textContent || '').trim())
      || getWordAtPoint(sourceCode, e.clientX, e.clientY)
    ).trim();
    const renameItems = buildCodeViewRenameMenuItems(word, e, { allowVariables: true }) || [];
    const commentItems = buildSourceLineCommentMenuItems(e);
    const items = [...commentItems, ...renameItems];
    if (!items.length) return;
    e.preventDefault();
    showRenameContextMenuMultiple(e.clientX, e.clientY, items);
  });
  sourceCode.addEventListener('dblclick', (e) => {
    const lineNo = e.target?.closest?.('.src-line-no');
    if (!lineNo || !sourceCode.contains(lineNo)) return;
    const hit = resolveSourceCommentTarget(e);
    if (!hit) return;
    e.preventDefault();
    editSourceLineComment(hit.methodKey, hit.lineIdx);
  });
}
if (bytecodeListing) {
  bytecodeListing.addEventListener('contextmenu', (e) => {
    const word = (window.getSelection()?.toString()?.trim() || getWordAtPoint(bytecodeListing, e.clientX, e.clientY)).trim();
    const items = buildCodeViewRenameMenuItems(word, e, { allowVariables: false });
    if (!items || items.length === 0) return;
    e.preventDefault();
    showRenameContextMenuMultiple(e.clientX, e.clientY, items);
  });
}

btnUpload.addEventListener('click', () => fileInput.click());

/** Phone / small-tablet: slide-over Contents drawer. */
const MOBILE_NAV_MQ = '(max-width: 768px)';
function isMobileNavLayout() {
  try { return window.matchMedia(MOBILE_NAV_MQ).matches; } catch (_) { return false; }
}
function setMobileNavOpen(open) {
  const want = !!open && isMobileNavLayout();
  document.body.classList.toggle('mobile-nav-open', want);
  const toggle = document.getElementById('mobile-nav-toggle');
  if (toggle) {
    toggle.setAttribute('aria-expanded', want ? 'true' : 'false');
    toggle.setAttribute('aria-label', want ? 'Close contents' : 'Open contents');
    toggle.title = want ? 'Close contents' : 'Contents';
  }
}
function toggleMobileNav() {
  setMobileNavOpen(!document.body.classList.contains('mobile-nav-open'));
}
function closeMobileNavIfNeeded() {
  if (document.body.classList.contains('mobile-nav-open')) setMobileNavOpen(false);
}
(function setupMobileNavDrawer() {
  document.getElementById('mobile-nav-toggle')?.addEventListener('click', (e) => {
    e.preventDefault();
    toggleMobileNav();
  });
  document.getElementById('mobile-nav-close')?.addEventListener('click', (e) => {
    e.preventDefault();
    setMobileNavOpen(false);
  });
  document.getElementById('mobile-nav-backdrop')?.addEventListener('click', () => setMobileNavOpen(false));
  document.getElementById('tree-container')?.addEventListener('click', (e) => {
    if (!isMobileNavLayout()) return;
    // Close after choosing a class / method / file row (not expand-only chevrons if present).
    if (e.target.closest('.tree-item, .tree-file, a[href]')) closeMobileNavIfNeeded();
  });
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMobileNavIfNeeded();
  });
  try {
    window.matchMedia(MOBILE_NAV_MQ).addEventListener('change', (ev) => {
      if (!ev.matches) setMobileNavOpen(false);
    });
  } catch (_) {}
})();

// Layout resizers: left sidebar + vertical docks
(function setupLayoutResizers() {
  const layout = document.getElementById('inspector-layout');
  const leftPanel = document.getElementById('left-panel');
  const resizerLeft = document.getElementById('resizer-left');
  if (!layout || !leftPanel || !resizerLeft) return;

  function beginResize(clientX) {
    if (isMobileNavLayout()) return;
    const startX = clientX;
    const startW = leftPanel.getBoundingClientRect().width;
    const minW = 160;
    const maxW = layout.getBoundingClientRect().width * 0.55;
    function move(ev) {
      const x = ev.touches ? ev.touches[0].clientX : ev.clientX;
      const w = Math.round(Math.max(minW, Math.min(maxW, startW + (x - startX))));
      leftPanel.style.width = w + 'px';
      leftPanel.style.minWidth = minW + 'px';
    }
    function up() {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      document.removeEventListener('touchmove', move);
      document.removeEventListener('touchend', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
    document.addEventListener('touchmove', move, { passive: false });
    document.addEventListener('touchend', up);
  }

  resizerLeft.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    beginResize(e.clientX);
  });
  resizerLeft.addEventListener('touchstart', (e) => {
    if (!e.touches?.[0]) return;
    e.preventDefault();
    beginResize(e.touches[0].clientX);
  }, { passive: false });
})();

(function setupDockResizers() {
  const workspace = document.getElementById('code-workspace');
  const mainRow = document.getElementById('code-main-row');
  const cfgResizer = document.getElementById('resizer-source-cfg');
  const bcResizer = document.getElementById('resizer-cfg-bytecode');
  const emuResizer = document.getElementById('resizer-emulator');
  const cfgPane = document.getElementById('cfg-pane');
  const bcPane = document.getElementById('bytecode-pane');
  const emuPane = document.getElementById('bytecode-emulator-area');
  if (!workspace) return;

  function isCfgSideBySide() {
    return !!(mainRow && window.matchMedia('(min-width: 1101px)').matches);
  }

  function bindVerticalResize(resizer, pane, cssVar, storageKey, minPx, maxRatio) {
    if (!resizer || !pane) return;
    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) workspace.style.setProperty(cssVar, saved);
    } catch (_) {}
    resizer.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const startY = e.clientY;
      const startH = pane.getBoundingClientRect().height;
      const maxH = workspace.getBoundingClientRect().height * maxRatio;
      function move(e) {
        // Dragging the bar above the dock: moving up increases dock height
        const h = Math.round(Math.max(minPx, Math.min(maxH, startH + (startY - e.clientY))));
        const val = h + 'px';
        workspace.style.setProperty(cssVar, val);
        try { localStorage.setItem(storageKey, val); } catch (_) {}
      }
      function up() {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        if (pane === cfgPane && cfgNetwork) setTimeout(() => fitCfgGraph(), 60);
      }
      document.body.style.cursor = 'row-resize';
      document.body.style.userSelect = 'none';
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  }

  function bindCfgResize(resizer, pane) {
    if (!resizer || !pane || !mainRow) return;
    try {
      const savedW = localStorage.getItem('droid2web-cfg-dock-w');
      if (savedW) workspace.style.setProperty('--cfg-dock-width', savedW);
      const savedH = localStorage.getItem('droid2web-cfg-dock-h');
      if (savedH) workspace.style.setProperty('--cfg-dock-height', savedH);
    } catch (_) {}
    resizer.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      if (pane.dataset.collapsed === 'true') return;
      e.preventDefault();
      const side = isCfgSideBySide();
      if (side) {
        const startX = e.clientX;
        const startW = pane.getBoundingClientRect().width;
        const rowW = mainRow.getBoundingClientRect().width;
        const minW = 280;
        const maxW = Math.max(minW + 40, rowW * 0.72);
        function move(e) {
          // Dragging the bar left of CFG: moving left increases CFG width
          const w = Math.round(Math.max(minW, Math.min(maxW, startW + (startX - e.clientX))));
          const val = w + 'px';
          workspace.style.setProperty('--cfg-dock-width', val);
          try { localStorage.setItem('droid2web-cfg-dock-w', val); } catch (_) {}
        }
        function up() {
          document.removeEventListener('mousemove', move);
          document.removeEventListener('mouseup', up);
          document.body.style.cursor = '';
          document.body.style.userSelect = '';
          if (cfgNetwork) setTimeout(() => fitCfgGraph(), 60);
        }
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
      } else {
        const startY = e.clientY;
        const startH = pane.getBoundingClientRect().height;
        const maxH = mainRow.getBoundingClientRect().height * 0.7;
        function move(e) {
          const h = Math.round(Math.max(160, Math.min(maxH, startH + (startY - e.clientY))));
          const val = h + 'px';
          workspace.style.setProperty('--cfg-dock-height', val);
          try { localStorage.setItem('droid2web-cfg-dock-h', val); } catch (_) {}
        }
        function up() {
          document.removeEventListener('mousemove', move);
          document.removeEventListener('mouseup', up);
          document.body.style.cursor = '';
          document.body.style.userSelect = '';
          if (cfgNetwork) setTimeout(() => fitCfgGraph(), 60);
        }
        document.body.style.cursor = 'row-resize';
        document.body.style.userSelect = 'none';
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
      }
    });
  }

  bindCfgResize(cfgResizer, cfgPane);
  const sourcePane = document.getElementById('source-pane');
  bindVerticalResize(bcResizer, sourcePane, '--source-dock-height', 'droid2web-source-dock-h', 120, 0.55);
  bindVerticalResize(emuResizer, emuPane, '--emulator-dock-height', 'droid2web-emulator-dock-h', 140, 0.45);

  window.addEventListener('resize', () => {
    if (cfgNetwork && cfgPane?.dataset.collapsed === 'false') {
      clearTimeout(window.__cfgFitResizeT);
      window.__cfgFitResizeT = setTimeout(() => fitCfgGraph(), 180);
    }
  });
})();

// Search: debounced filter (optimized for huge DEX)
const SEARCH_DEBOUNCE_MS = 160;
function applySearch() {
  searchQuery = (searchInput.value || '').trim().toLowerCase();
  if (currentData != null) render();
}
searchInput.addEventListener('input', () => {
  if (searchDebounceId != null) clearTimeout(searchDebounceId);
  searchDebounceId = setTimeout(() => {
    searchDebounceId = null;
    applySearch();
    syncListBookmarksFilterButton();
  }, SEARCH_DEBOUNCE_MS);
});
searchInput.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    searchInput.value = '';
    searchQuery = '';
    if (searchDebounceId != null) clearTimeout(searchDebounceId);
    searchDebounceId = null;
    if (currentData != null) render();
    syncListBookmarksFilterButton();
    searchInput.blur();
  }
});

const listBookmarksBtn = document.getElementById('list-bookmarks-btn');
if (listBookmarksBtn) {
  listBookmarksBtn.addEventListener('click', () => {
    const on = parseListSearchQuery(searchQuery).bookmarks;
    if (on) {
      searchInput.value = '';
      searchQuery = '';
    } else {
      searchInput.value = 'bookmark:';
      searchQuery = 'bookmark:';
      const panel = document.getElementById('annotation-panel');
      if (panel && !panel.hidden) {
        setAnnoBodyCollapsed(panel, false);
        const bmSection = panel.querySelector('.anno-bookmarks-section');
        if (bmSection) setAnnoSectionCollapsed(bmSection, false);
      }
    }
    if (searchDebounceId != null) clearTimeout(searchDebounceId);
    searchDebounceId = null;
    if (currentData != null) render();
    syncListBookmarksFilterButton();
  });
}

const showAndroidClassesCb = document.getElementById('show-android-classes');
if (showAndroidClassesCb) {
  showAndroidClassesCb.checked = !!showAndroidFrameworkClasses;
  showAndroidClassesCb.addEventListener('change', () => {
    showAndroidFrameworkClasses = !!showAndroidClassesCb.checked;
    try {
      localStorage.setItem(SHOW_ANDROID_CLASSES_KEY, showAndroidFrameworkClasses ? '1' : '0');
    } catch (_) {}
    apkPackageCountsCache = null;
    if (currentData != null) render();
    else if (currentType === 'apk' && apkLeftMode === 'classes') renderApkClassTree();
    try { updateCodeView(); } catch (_) {}
  });
}

/**
 * Normalize params input for the emulator.
 * Supports shorthand for byte arrays: "[B]1,2,3,4,5;[B]0,0,0,0" or "[[B]1,2,3,4,5;[B]0,0,0,0]"
 * -> converts to JSON {"heap":[[1,2,3,4,5],[0,0,0,0]]} so the backend creates two array args (Ref(0), Ref(1)).
 * Otherwise returns the string as-is (JSON array or extended JSON object).
 */
function normalizeEmulatorParamsJson(str) {
  const s = (str || '').trim();
  if (!s) return '[]';
  const stripped = s.replace(/^\[|\]$/g, '').trim();
  const parts = stripped.split(';').map((p) => p.trim());
  const hasByteArrays = parts.some((p) => /\[B\]/i.test(p));
  if (hasByteArrays && parts.length >= 1) {
    const heap = parts.map((part) => {
      const m = part.replace(/\s/g, '').match(/\[B\]\s*([\d,\s]*)/i);
      const numStr = m ? m[1] : part.replace(/\s/g, '');
      if (!numStr) return [];
      return numStr.split(',').map((x) => parseInt(x, 10)).filter((n) => !Number.isNaN(n));
    });
    return JSON.stringify({ heap });
  }
  return s;
}

/** Get current DEX bytes and { classIdx, methodIdx } when viewing a DEX method, or null. */
function getCurrentDexBytesAndSelection() {
  const ctx = getCurrentDexContext();
  return ctx ? { bytes: ctx.bytes, classIdx: ctx.classIdx, methodIdx: ctx.methodIdx } : null;
}

/** Get full DEX context for emulator: bytes, classes array, and current selection. */
function getCurrentDexContext() {
  if (currentType === 'dex' && currentDexBytes && currentData?.classes?.length) {
    return {
      bytes: currentDexBytes,
      classes: currentData.classes,
      classIdx: currentDexSelection.classIdx,
      methodIdx: currentDexSelection.methodIdx,
    };
  }
  if (apkExtractedFile?.kind === 'dex' && apkExtractedFile.bytes && apkExtractedFile.data?.classes?.length) {
    const sel = apkExtractedDexSelection;
    return {
      bytes: apkExtractedFile.bytes,
      classes: apkExtractedFile.data.classes,
      classIdx: sel.classIdx,
      methodIdx: sel.methodIdx,
    };
  }
  return null;
}

function formatEmulatorValue(v) {
  if (v == null) return '—';
  if (typeof v !== 'object') return String(v);
  const t = v.type;
  const val = v.value;
  if (t === 'Int' && val != null) return String(val);
  if (t === 'Long' && val != null) return val + 'L';
  if (t === 'Float' && val != null) return val + 'f';
  if (t === 'Double' && val != null) return val + 'd';
  if (t === 'Str' && val != null) return '"' + escapeHtml(String(val)) + '"';
  if (t === 'Null') return 'null';
  if (t === 'Unset') return '?';
  if (t === 'Ref' && val != null) return '@' + val;
  if (t === 'Unknown' && val != null) return '<' + escapeHtml(String(val)) + '>';
  return escapeHtml(JSON.stringify(v));
}

function renderEmulatorStateSnapshot(state) {
  if (!state) return '';
  let html = '';
  if (state.registers && state.registers.length) {
    html += '<div class="emulator-block emulator-block-registers"><div class="emulator-section">Registers</div><table class="emulator-registers-table"><thead><tr><th>Reg</th><th>Value</th></tr></thead><tbody>';
    state.registers.forEach((r) => {
      html += '<tr><td>' + escapeHtml(r.name || 'v' + r.index) + '</td><td>' + formatEmulatorValue(r.value) + '</td></tr>';
    });
    html += '</tbody></table></div>';
  }
  if (state.heap && state.heap.length) {
    html += '<div class="emulator-block emulator-block-heap"><div class="emulator-section">Heap</div><table class="emulator-heap-table"><thead><tr><th>#</th><th>Type</th><th>Content</th></tr></thead><tbody>';
    state.heap.forEach((h) => {
      const obj = h.object;
      let content = '';
      if (obj) {
        if (obj.type === 'Array') content = (obj.values || []).map(formatEmulatorValue).join(', ');
        else if (obj.type === 'Instance') content = (obj.class || '') + (obj.fields ? ' ' + JSON.stringify(obj.fields) : '');
      }
      if (!content) content = '—';
      html += '<tr><td>' + h.index + '</td><td>' + escapeHtml((obj && obj.type) || '') + '</td><td>' + escapeHtml(content) + '</td></tr>';
    });
    html += '</tbody></table></div>';
  }
  if (state.console_output && state.console_output.length) {
    html += '<div class="emulator-block emulator-block-console"><div class="emulator-section">Console</div><pre class="emulator-console">' + escapeHtml(state.console_output.join('\n')) + '</pre></div>';
  }
  if (state.finished && state.return_value != null) {
    html += '<div class="emulator-block emulator-block-return"><div class="emulator-section">Return</div><pre class="emulator-return">' + formatEmulatorValue(state.return_value) + '</pre></div>';
  }
  if (state.exception) {
    html += '<div class="emulator-error">' + escapeHtml(state.exception) + '</div>';
  }
  return html || '<div class="muted">No state</div>';
}

function updateBytecodeEmulatorStep() {
  if (!lastEmulatorRun || !bytecodeListing || !bytecodeStepBar || !bytecodeStatePanel) return;
  const { history, stepIndex } = lastEmulatorRun;
  const rec = history[stepIndex];
  if (!rec || !rec.instruction) return;
  const offset = rec.instruction.offset;
  const offsetNum = Number(offset);
  const total = history.length;
  bytecodeListing.querySelectorAll('.bytecode-line').forEach((el) => {
    const lineOffset = Number(el.dataset.offset);
    const isCurrent = !Number.isNaN(lineOffset) && lineOffset === offsetNum;
    el.classList.toggle('emulator-current-step', isCurrent);
    if (isCurrent) {
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth', inline: 'nearest' });
    }
  });
  showEmulatorDock(true);
  const insn = rec.instruction;
  const currentInsnText = (insn.mnemonic || '') + (insn.operands ? ' ' + insn.operands : '');
  bytecodeStepBar.innerHTML =
    '<button type="button" class="btn btn-step" id="bytecode-step-first" title="First step">⏮</button>' +
    '<button type="button" class="btn btn-step" id="bytecode-step-prev" title="Previous">◀ Prev</button>' +
    '<input type="range" class="bytecode-step-slider" id="bytecode-step-slider" min="0" max="' + Math.max(0, total - 1) + '" value="' + stepIndex + '" aria-label="Step">' +
    '<span class="step-info">' + (stepIndex + 1) + ' / ' + total + '</span>' +
    '<button type="button" class="btn btn-step" id="bytecode-step-next" title="Next">Next ▶</button>' +
    '<button type="button" class="btn btn-step" id="bytecode-step-last" title="Last step">⏭</button>';
  const slider = bytecodeStepBar.querySelector('#bytecode-step-slider');
  if (slider) {
    slider.oninput = () => {
      const v = parseInt(slider.value, 10);
      if (!Number.isNaN(v) && lastEmulatorRun && v >= 0 && v < lastEmulatorRun.history.length) {
        lastEmulatorRun.stepIndex = v;
        updateBytecodeEmulatorStep();
      }
    };
  }
  bytecodeStepBar.querySelector('#bytecode-step-first').onclick = () => {
    if (lastEmulatorRun && lastEmulatorRun.stepIndex > 0) {
      lastEmulatorRun.stepIndex = 0;
      updateBytecodeEmulatorStep();
    }
  };
  bytecodeStepBar.querySelector('#bytecode-step-prev').onclick = () => {
    if (lastEmulatorRun && lastEmulatorRun.stepIndex > 0) {
      lastEmulatorRun.stepIndex--;
      updateBytecodeEmulatorStep();
    }
  };
  bytecodeStepBar.querySelector('#bytecode-step-next').onclick = () => {
    if (lastEmulatorRun && lastEmulatorRun.stepIndex < lastEmulatorRun.history.length - 1) {
      lastEmulatorRun.stepIndex++;
      updateBytecodeEmulatorStep();
    }
  };
  bytecodeStepBar.querySelector('#bytecode-step-last').onclick = () => {
    if (lastEmulatorRun && lastEmulatorRun.stepIndex < lastEmulatorRun.history.length - 1) {
      lastEmulatorRun.stepIndex = lastEmulatorRun.history.length - 1;
      updateBytecodeEmulatorStep();
    }
  };
  let stateHtml = '<div class="emulator-current-insn">' +
    '<span class="emulator-current-insn-label">Current:</span> ' +
    '<code class="emulator-current-insn-code">' + escapeHtml('0x' + (offset >>> 0).toString(16).padStart(4, '0') + '  ' + currentInsnText) + '</code></div>';
  if (rec.description) stateHtml += '<div class="emulator-meta">' + escapeHtml(rec.description) + '</div>';
  stateHtml += '<div class="emulator-state-grid">' + renderEmulatorStateSnapshot(rec.state_after) + '</div>';
  bytecodeStatePanel.innerHTML = stateHtml;
}

function runBytecodeEmulator() {
  const ctx = getCurrentDexBytesAndSelection();
  showEmulatorDock(true);
  if (bytecodeStatePanel) {
    if (!ctx) {
      bytecodeStatePanel.innerHTML = '<div class="muted">Select a method first: pick a class and method in the tree (or use the class/method dropdowns if viewing a DEX from an APK).</div>';
      return;
    }
    if (!ctx.bytes || ctx.bytes.length === 0) {
      bytecodeStatePanel.innerHTML = '<div class="emulator-error">No DEX bytes available. Try reopening the file.</div>';
      return;
    }
  } else if (!ctx) return;

  const paramsRaw = (bytecodeParamsInput && bytecodeParamsInput.value) ? bytecodeParamsInput.value.trim() || '[]' : '[]';
  const paramsJson = normalizeEmulatorParamsJson(paramsRaw);
  let maxSteps = 5000;
  if (bytecodeMaxStepsInput) {
    const v = parseInt(bytecodeMaxStepsInput.value, 10);
    if (!Number.isNaN(v) && v >= 0) maxSteps = v;
  }
  if (bytecodeStatePanel) bytecodeStatePanel.innerHTML = '<div class="muted">Running…</div>';
  try {
    const result = run_dex_emulator_with_history(ctx.bytes, ctx.classIdx, ctx.methodIdx, paramsJson, maxSteps);
    if (!bytecodeStatePanel) return;
    if (!result || !result.ok) {
      bytecodeStatePanel.innerHTML = '<div class="emulator-error">' + escapeHtml(result?.error || 'Emulator failed') + '</div>';
      return;
    }
    const d = result.data;
    const history = d.history || [];
    if (history.length === 0) {
      let msg = '';
      if (d.error) msg += '<div class="emulator-error">' + escapeHtml(d.error) + '</div>';
      msg += renderEmulatorStateSnapshot({ registers: [], heap: [], console_output: d.console_output || [], return_value: d.return_value, exception: d.error ? d.error : null });
      bytecodeStatePanel.innerHTML = msg;
      return;
    }
    lastEmulatorRun = { history, stepIndex: history.length - 1 };
    updateBytecodeEmulatorStep();
  } catch (e) {
    if (bytecodeStatePanel) bytecodeStatePanel.innerHTML = '<div class="emulator-error">' + escapeHtml(String(e?.message || e)) + '</div>';
  }
}

function runBytecodeEmulatorStep() {
  const ctx = getCurrentDexBytesAndSelection();
  showEmulatorDock(true);
  if (bytecodeStatePanel) {
    if (!ctx) {
      bytecodeStatePanel.innerHTML = '<div class="muted">Select a method first: pick a class and method in the tree.</div>';
      return;
    }
    if (!ctx.bytes || ctx.bytes.length === 0) {
      bytecodeStatePanel.innerHTML = '<div class="emulator-error">No DEX bytes available. Try reopening the file.</div>';
      return;
    }
  } else if (!ctx) return;

  const currentSteps = (lastEmulatorRun && lastEmulatorRun.history) ? lastEmulatorRun.history.length : 0;
  const maxSteps = currentSteps + 1;
  const paramsRaw = (bytecodeParamsInput && bytecodeParamsInput.value) ? bytecodeParamsInput.value.trim() || '[]' : '[]';
  const paramsJson = normalizeEmulatorParamsJson(paramsRaw);
  showEmulatorDock(true);
  if (bytecodeStatePanel) bytecodeStatePanel.innerHTML = '<div class="muted">Stepping…</div>';
  try {
    const result = run_dex_emulator_with_history(ctx.bytes, ctx.classIdx, ctx.methodIdx, paramsJson, maxSteps);
    if (!bytecodeStatePanel) return;
    if (!result || !result.ok) {
      bytecodeStatePanel.innerHTML = '<div class="emulator-error">' + escapeHtml(result?.error || 'Emulator failed') + '</div>';
      return;
    }
    const d = result.data;
    const history = d.history || [];
    if (history.length === 0) {
      let msg = '';
      if (d.error) msg += '<div class="emulator-error">' + escapeHtml(d.error) + '</div>';
      msg += renderEmulatorStateSnapshot({ registers: [], heap: [], console_output: d.console_output || [], return_value: d.return_value, exception: d.error ? d.error : null });
      bytecodeStatePanel.innerHTML = msg;
      return;
    }
    lastEmulatorRun = { history, stepIndex: history.length - 1 };
    updateBytecodeEmulatorStep();
  } catch (e) {
    if (bytecodeStatePanel) bytecodeStatePanel.innerHTML = '<div class="emulator-error">' + escapeHtml(String(e?.message || e)) + '</div>';
  }
}

if (bytecodeRunBtn) {
  bytecodeRunBtn.addEventListener('click', () => runBytecodeEmulator());
}
const bytecodeStepBtn = document.getElementById('bytecode-step');
if (bytecodeStepBtn) {
  bytecodeStepBtn.addEventListener('click', () => runBytecodeEmulatorStep());
}

function resetEmulatorVM() {
  lastEmulatorRun = null;
  if (bytecodeListing) {
    bytecodeListing.querySelectorAll('.bytecode-line').forEach((el) => el.classList.remove('emulator-current-step'));
  }
  hideEmulatorResults();
  if (bytecodeStepBar) bytecodeStepBar.innerHTML = '';
  if (bytecodeStatePanel) bytecodeStatePanel.innerHTML = '';
}

const bytecodeResetBtn = document.getElementById('bytecode-reset');
if (bytecodeResetBtn) {
  bytecodeResetBtn.addEventListener('click', () => resetEmulatorVM());
}

const shortcutsHelpBtn = document.getElementById('bytecode-shortcuts-help');
const shortcutsPopup = document.getElementById('shortcuts-popup');
function showShortcutsPopup() {
  if (shortcutsPopup) {
    shortcutsPopup.setAttribute('aria-hidden', 'false');
    document.addEventListener('click', closeShortcutsPopupOnClickOutside);
  }
}
function closeShortcutsPopup() {
  if (shortcutsPopup) {
    shortcutsPopup.setAttribute('aria-hidden', 'true');
    document.removeEventListener('click', closeShortcutsPopupOnClickOutside);
  }
}
function closeShortcutsPopupOnClickOutside(e) {
  if (shortcutsPopup && !shortcutsPopup.contains(e.target) && !shortcutsHelpBtn?.contains(e.target)) {
    closeShortcutsPopup();
  }
}
if (shortcutsHelpBtn && shortcutsPopup) {
  shortcutsHelpBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = shortcutsPopup.getAttribute('aria-hidden') !== 'true';
    if (isOpen) closeShortcutsPopup();
    else showShortcutsPopup();
  });
}

// Emulator keyboard shortcuts (ignore when typing in input/textarea)
document.addEventListener('keydown', (e) => {
  const inInput = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
  if (inInput && e.key !== 'Escape') return;

  const ctx = getCurrentDexContext();
  const hasDexContext = !!ctx;

  if (e.key === 'Escape') {
    if (shortcutsPopup?.getAttribute('aria-hidden') !== 'true') {
      closeShortcutsPopup();
      e.preventDefault();
      return;
    }
    if (lastEmulatorRun && bytecodeEmulatorArea?.dataset?.collapsed === 'false') {
      resetEmulatorVM();
      e.preventDefault();
    }
    return;
  }

  // Source / bytecode jump history (elfbrowser-style back)
  if ((e.altKey || e.metaKey) && e.key === 'ArrowLeft') {
    if (sourceNavStack.length || codeViewMethodIdx != null) {
      sourceNavBack();
      e.preventDefault();
      return;
    }
    if (bytecodeNavStack.length) {
      bytecodeNavBack();
      e.preventDefault();
      return;
    }
  }

  if (lastEmulatorRun && bytecodeStepBar?.contains(document.activeElement) === false) {
    const { history, stepIndex } = lastEmulatorRun;
    if (e.key === 'ArrowLeft') {
      if (stepIndex > 0) {
        lastEmulatorRun.stepIndex--;
        updateBytecodeEmulatorStep();
        e.preventDefault();
      }
      return;
    }
    if (e.key === 'ArrowRight') {
      if (stepIndex < history.length - 1) {
        lastEmulatorRun.stepIndex++;
        updateBytecodeEmulatorStep();
        e.preventDefault();
      }
      return;
    }
    if (e.key === 'Home') {
      if (stepIndex > 0) {
        lastEmulatorRun.stepIndex = 0;
        updateBytecodeEmulatorStep();
        e.preventDefault();
      }
      return;
    }
    if (e.key === 'End') {
      if (stepIndex < history.length - 1) {
        lastEmulatorRun.stepIndex = history.length - 1;
        updateBytecodeEmulatorStep();
        e.preventDefault();
      }
      return;
    }
  }

  if (!hasDexContext) return;
  if (e.ctrlKey || e.metaKey) {
    if (e.key === 'Enter') {
      runBytecodeEmulator();
      e.preventDefault();
    }
    return;
  }
  if (e.key === 's' || e.key === 'S') {
    runBytecodeEmulatorStep();
    e.preventDefault();
  } else if (e.key === 'r' || e.key === 'R') {
    runBytecodeEmulator();
    e.preventDefault();
  }
});

if (bytecodeListing) {
  bytecodeListing.addEventListener('click', (e) => {
    const stringXrefNav = e.target.closest('.string-xref-ref');
    if (stringXrefNav && bytecodeListing.contains(stringXrefNav)) {
      e.preventDefault();
      e.stopPropagation();
      if (!stringXrefNav.classList.contains('is-here')) navigateToStringXref(stringXrefNav);
      return;
    }
    const stringXrefSlot = e.target.closest('.bytecode-string-xref.is-pending');
    if (stringXrefSlot && bytecodeListing.contains(stringXrefSlot)) {
      e.preventDefault();
      e.stopPropagation();
      const idx = parseInt(stringXrefSlot.getAttribute('data-string-idx'), 10);
      if (!Number.isNaN(idx)) loadBytecodeStringXrefs(idx, { triggerSlot: stringXrefSlot });
      return;
    }
    const strTok = e.target.closest('.bc-str[data-string-idx]');
    if (strTok && bytecodeListing.contains(strTok)) {
      e.preventDefault();
      e.stopPropagation();
      const idx = parseInt(strTok.getAttribute('data-string-idx'), 10);
      if (!Number.isNaN(idx)) loadBytecodeStringXrefs(idx);
      return;
    }
    const fieldXrefEl = e.target.closest('.field-xref-ref');
    if (fieldXrefEl && bytecodeListing.contains(fieldXrefEl)) {
      e.preventDefault();
      e.stopPropagation();
      navigateToFieldXref(fieldXrefEl);
      return;
    }
    const fieldRef = e.target.closest('.bc-field-ref, .class-field-chip');
    if (fieldRef && bytecodeListing.contains(fieldRef)) {
      e.preventDefault();
      e.stopPropagation();
      const idx = parseInt(fieldRef.getAttribute('data-field-idx'), 10);
      if (!Number.isNaN(idx)) openFieldXrefsPanel(idx);
      return;
    }
    const callerEl = e.target.closest('.method-caller-ref, .method-callee-ref');
    if (callerEl && bytecodeListing.contains(callerEl)) {
      e.preventDefault();
      e.stopPropagation();
      navigateToMethodCaller(callerEl);
      return;
    }
    const jumpEl = e.target.closest('.bc-jump-arrow, .bc-xref-ref, .bc-addr-link');
    if (jumpEl) {
      e.preventDefault();
      e.stopPropagation();
      const target = parseInt(jumpEl.getAttribute('data-target-offset'), 10);
      const fromLine = e.target.closest('.bytecode-line, .bytecode-xref-line');
      const fromOffset = fromLine
        ? parseInt(fromLine.getAttribute('data-offset') || fromLine.getAttribute('data-xref-for'), 10)
        : NaN;
      if (!Number.isNaN(target)) {
        jumpBytecodeToOffset(target, {
          fromOffset: Number.isNaN(fromOffset) ? null : fromOffset,
          push: true,
        });
      }
      return;
    }
    const backClass = e.target.closest('[data-back-class]');
    if (backClass && bytecodeListing.contains(backClass)) {
      e.preventDefault();
      e.stopPropagation();
      goBackToClassView();
      return;
    }
    const methodChrome = e.target.closest(
      '.bytecode-method-block .method-block-header, .bytecode-method-block [data-open-cfg], .bytecode-method-view [data-open-cfg]'
    );
    if (methodChrome) {
      e.preventDefault();
      e.stopPropagation();
      openMethodFromUiEvent(e);
      return;
    }
    const line = e.target.closest('.bytecode-line');
    if (!line || !lastEmulatorRun) return;
    const offset = Number(line.dataset.offset);
    if (Number.isNaN(offset)) return;
    const idx = lastEmulatorRun.history.findIndex((r) => r.instruction && Number(r.instruction.offset) === offset);
    if (idx >= 0) {
      lastEmulatorRun.stepIndex = idx;
      updateBytecodeEmulatorStep();
    }
  });
  wireBytecodeRegisterHighlight(bytecodeListing);
}
wireBytecodeRegisterHighlight(cfgHtmlLayer);

/** Active register under cursor for cross-highlight in bytecode + CFG. */
let bytecodeHoveredReg = null;
/** Scope element for register highlight (method block / CFG); null = whole listing. */
let bytecodeHoveredRegScope = null;
/** Active constant/string key (`n:42` / `s:hello`) across source + bytecode + CFG. */
let crossHoveredConst = null;

function bytecodeRegHighlightRoots() {
  return [bytecodeListing, cfgHtmlLayer].filter(Boolean);
}

function crossConstHighlightRoots() {
  return [bytecodeListing, cfgHtmlLayer, document.getElementById('source-code')].filter(Boolean);
}

/** Normalize immediates/strings so source `42` matches bytecode `0x2a`, etc. */
function normalizeCrossConstKey(raw) {
  let s = String(raw || '').trim();
  if (!s) return '';
  s = s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return 's:' + s.slice(1, -1);
  }
  // Java long/float suffixes
  const numTok = s.replace(/[fFdDlL]$/, '');
  if (/^0x[0-9a-fA-F]+$/i.test(numTok)) {
    const n = parseInt(numTok, 16);
    return Number.isFinite(n) ? 'n:' + (n | 0) : '';
  }
  if (/^[+-]?\d+$/.test(numTok)) {
    const n = parseInt(numTok, 10);
    return Number.isFinite(n) ? 'n:' + (n | 0) : '';
  }
  if (/^[+-]?\d+\.\d*([eE][+-]?\d+)?$/.test(numTok) || /^[+-]?\d+[eE][+-]?\d+$/.test(numTok)) {
    const n = Number(numTok);
    return Number.isFinite(n) ? 'n:' + String(n) : '';
  }
  return '';
}

/** Limit register highlight to one method when viewing “All methods”. */
function resolveRegHighlightScope(fromEl) {
  if (!fromEl || typeof fromEl.closest !== 'function') return null;
  const methodBlock = fromEl.closest('.bytecode-method-block, .bytecode-method-view, .source-method-block, .source-method-view');
  if (methodBlock) return methodBlock;
  if (cfgHtmlLayer && cfgHtmlLayer.contains(fromEl)) return cfgHtmlLayer;
  return null;
}

function clearBytecodeRegisterHighlight() {
  if (!bytecodeHoveredReg) return;
  for (const root of bytecodeRegHighlightRoots()) {
    root.querySelectorAll('.bc-reg.bc-reg-active').forEach((el) => el.classList.remove('bc-reg-active'));
    root.querySelectorAll('.bytecode-line.bc-reg-line-active, .cfg-insn-line.bc-reg-line-active').forEach((el) => {
      el.classList.remove('bc-reg-line-active');
      el.style.removeProperty('--bc-reg-hue');
    });
  }
  bytecodeHoveredReg = null;
  bytecodeHoveredRegScope = null;
}

function clearCrossConstHighlight() {
  if (!crossHoveredConst) return;
  for (const root of crossConstHighlightRoots()) {
    root.querySelectorAll('.cross-const-active').forEach((el) => el.classList.remove('cross-const-active'));
    root.querySelectorAll('.bytecode-line.cross-const-line-active, .cfg-insn-line.cross-const-line-active, .src-line.cross-const-line-active').forEach((el) => {
      el.classList.remove('cross-const-line-active');
    });
  }
  crossHoveredConst = null;
}

function setBytecodeRegisterHighlight(reg, scopeEl = null) {
  const name = String(reg || '').trim();
  if (!name || !/^([vp]\d+)$/.test(name)) {
    clearBytecodeRegisterHighlight();
    return;
  }
  clearCrossConstHighlight();
  const scope = scopeEl || null;
  if (bytecodeHoveredReg === name && bytecodeHoveredRegScope === scope) {
    refreshBytecodeRegisterHighlight();
    return;
  }
  clearBytecodeRegisterHighlight();
  bytecodeHoveredReg = name;
  bytecodeHoveredRegScope = scope;
  refreshBytecodeRegisterHighlight();
}

function setCrossConstHighlight(key) {
  const k = String(key || '').trim();
  if (!k || !(k.startsWith('n:') || k.startsWith('s:'))) {
    clearCrossConstHighlight();
    return;
  }
  clearBytecodeRegisterHighlight();
  if (crossHoveredConst === k) {
    refreshCrossConstHighlight();
    return;
  }
  clearCrossConstHighlight();
  crossHoveredConst = k;
  refreshCrossConstHighlight();
}

function applyBytecodeRegisterHighlightIn(container, sel, hue) {
  if (!container) return;
  container.querySelectorAll(sel).forEach((el) => {
    el.classList.add('bc-reg-active');
    const line = el.closest('.bytecode-line, .cfg-insn-line');
    if (line) {
      line.classList.add('bc-reg-line-active');
      line.style.setProperty('--bc-reg-hue', String(hue));
    }
  });
}

function refreshBytecodeRegisterHighlight() {
  const name = bytecodeHoveredReg;
  if (!name) return;
  const sel = `.bc-reg[data-reg="${CSS.escape(name)}"]`;
  const hue = registerColorIndex(name);
  const scope = bytecodeHoveredRegScope;

  // Single-method / no scope: keep prior behavior (bytecode ↔ CFG).
  if (!scope) {
    for (const root of bytecodeRegHighlightRoots()) {
      applyBytecodeRegisterHighlightIn(root, sel, hue);
    }
    return;
  }

  // Multi-method class view or single-method wrapper: only the hovered method block.
  applyBytecodeRegisterHighlightIn(scope, sel, hue);

  const isBytecodeMethodScope = !!(
    scope.classList?.contains('bytecode-method-block') ||
    scope.classList?.contains('bytecode-method-view')
  );

  // Also light up CFG when it is showing that same method.
  if (
    cfgHtmlLayer &&
    scope !== cfgHtmlLayer &&
    isBytecodeMethodScope &&
    codeViewMethodIdx != null
  ) {
    const mi = parseInt(scope.getAttribute('data-method-idx'), 10);
    const ci = parseInt(scope.getAttribute('data-class-idx'), 10);
    const sameMethod =
      Number.isNaN(mi) || Number.isNaN(ci)
        ? true
        : (Number(mi) === Number(codeViewMethodIdx) && Number(ci) === Number(codeViewClassIdx));
    if (sameMethod) {
      applyBytecodeRegisterHighlightIn(cfgHtmlLayer, sel, hue);
    }
  }

  // Hover originated in CFG: also highlight that method’s bytecode block (or whole listing).
  if (cfgHtmlLayer && scope === cfgHtmlLayer && bytecodeListing) {
    if (codeViewMethodIdx != null && codeViewClassIdx != null) {
      const block = bytecodeListing.querySelector(
        `.bytecode-method-block[data-class-idx="${CSS.escape(String(codeViewClassIdx))}"][data-method-idx="${CSS.escape(String(codeViewMethodIdx))}"],` +
        `.bytecode-method-view[data-class-idx="${CSS.escape(String(codeViewClassIdx))}"][data-method-idx="${CSS.escape(String(codeViewMethodIdx))}"]`
      );
      applyBytecodeRegisterHighlightIn(block || bytecodeListing, sel, hue);
    } else if (!bytecodeListing.querySelector('.bytecode-method-block, .bytecode-method-view')) {
      applyBytecodeRegisterHighlightIn(bytecodeListing, sel, hue);
    }
  }
}

function refreshCrossConstHighlight() {
  const key = crossHoveredConst;
  if (!key) return;
  const sel = `[data-const="${CSS.escape(key)}"]`;
  for (const root of crossConstHighlightRoots()) {
    root.querySelectorAll(sel).forEach((el) => {
      el.classList.add('cross-const-active');
      el.closest('.bytecode-line, .cfg-insn-line, .src-line')?.classList.add('cross-const-line-active');
    });
  }
}

function wireBytecodeRegisterHighlight(root) {
  if (!root || root.dataset.regHighlightWired === '1') return;
  root.dataset.regHighlightWired = '1';
  root.addEventListener('mouseover', (e) => {
    const regEl = e.target.closest?.('.bc-reg');
    if (regEl && root.contains(regEl)) {
      setBytecodeRegisterHighlight(regEl.getAttribute('data-reg'), resolveRegHighlightScope(regEl));
      return;
    }
    const constEl = e.target.closest?.('[data-const]');
    if (constEl && root.contains(constEl)) {
      setCrossConstHighlight(constEl.getAttribute('data-const'));
    }
  });
  root.addEventListener('mouseout', (e) => {
    const fromReg = e.target.closest?.('.bc-reg');
    const fromConst = e.target.closest?.('[data-const]');
    if (!fromReg && !fromConst) return;
    if ((fromReg && !root.contains(fromReg)) || (fromConst && !root.contains(fromConst))) return;
    const to = e.relatedTarget;
    if (to && typeof to.closest === 'function') {
      const stillIn = crossConstHighlightRoots().some((r) => r.contains(to));
      if (stillIn) {
        const nextReg = to.closest('.bc-reg');
        if (nextReg) {
          setBytecodeRegisterHighlight(nextReg.getAttribute('data-reg'), resolveRegHighlightScope(nextReg));
          return;
        }
        const nextConst = to.closest('[data-const]');
        if (nextConst) {
          setCrossConstHighlight(nextConst.getAttribute('data-const'));
          return;
        }
        clearBytecodeRegisterHighlight();
        clearCrossConstHighlight();
        return;
      }
    }
    clearBytecodeRegisterHighlight();
    clearCrossConstHighlight();
  });
}

function wireSourceConstHighlight() {
  const root = document.getElementById('source-code');
  if (!root || root.dataset.constHighlightWired === '1') return;
  root.dataset.constHighlightWired = '1';
  root.addEventListener('mouseover', (e) => {
    const el = e.target.closest?.('[data-const]');
    if (!el || !root.contains(el)) return;
    setCrossConstHighlight(el.getAttribute('data-const'));
  });
  root.addEventListener('mouseout', (e) => {
    const from = e.target.closest?.('[data-const]');
    if (!from || !root.contains(from)) return;
    const to = e.relatedTarget;
    if (to && typeof to.closest === 'function') {
      const stillIn = crossConstHighlightRoots().some((r) => r.contains(to));
      if (stillIn) {
        const nextReg = to.closest('.bc-reg');
        if (nextReg) {
          setBytecodeRegisterHighlight(nextReg.getAttribute('data-reg'));
          return;
        }
        const nextConst = to.closest('[data-const]');
        if (nextConst) {
          setCrossConstHighlight(nextConst.getAttribute('data-const'));
          return;
        }
        clearCrossConstHighlight();
        return;
      }
    }
    clearCrossConstHighlight();
  });
}

// Wire once DOM is ready
wireSourceConstHighlight();

// Manifest: click on class link / component chip -> open that DEX class in Code
document.getElementById('manifest-tab')?.addEventListener('click', async (e) => {
  const chip = e.target.closest('.manifest-comp-chip.is-linked');
  if (chip) {
    e.preventDefault();
    await openClassFromManifest(
      chip.dataset.file,
      parseInt(chip.dataset.classIdx, 10),
      chip.dataset.class
    );
    return;
  }
  const a = e.target.closest('.manifest-class-link');
  if (!a) return;
  e.preventDefault();
  await openClassFromManifest(
    a.dataset.file,
    parseInt(a.dataset.classIdx, 10),
    a.dataset.class
  );
});

// Drag and drop — overlay appears when dragging files over the page
function setupDropZone() {
  let dragCount = 0;
  const prevent = (e) => { e.preventDefault(); e.stopPropagation(); };
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => {
    document.body.addEventListener(ev, prevent);
  });
  document.body.addEventListener('dragenter', (e) => {
    if (e.dataTransfer?.types?.includes('Files')) {
      dragCount++;
      debug('dragenter, dragCount=', dragCount);
      dropZone.classList.add('drag-over');
    }
  });
  document.body.addEventListener('dragleave', () => {
    dragCount--;
    if (dragCount <= 0) {
      dragCount = 0;
      dropZone.classList.remove('drag-over');
    }
  });
  document.body.addEventListener('drop', (e) => {
    dragCount = 0;
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer?.files ? Array.from(e.dataTransfer.files) : [];
    debug('drop', files.length ? files.map((f) => f.name) : 'no file');
    if (files.length) processFiles(files);
  });
}
setupDropZone();
debug('drop zone set up');

function isLikelyDexFile(file, bytes) {
  const n = (file?.name || '').toLowerCase();
  if (bytes && bytes.length >= 4 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a) {
    return true;
  }
  // magic "dex\n" — also accept without checking 4th if extension says .dex
  if (bytes && bytes.length >= 3 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78) return true;
  return n.endsWith('.dex');
}

function clearStandaloneDexSession() {
  loadedDexFiles = [];
  activeDexIndex = 0;
  if (dexFileWrap) dexFileWrap.style.display = 'none';
}

function updateDexFileSelector() {
  if (!dexFileWrap || !dexFileSelect) return;
  if (currentType !== 'dex' || loadedDexFiles.length === 0) {
    dexFileWrap.style.display = 'none';
    return;
  }
  // Always show when ≥1 DEX so single DEX is consistent; optional: hide when length===1
  dexFileWrap.style.display = loadedDexFiles.length > 1 ? 'flex' : 'none';
  dexFileSelect.innerHTML = loadedDexFiles.map((d, i) => {
    const cm = `${formatCount(d.classCount)} cls · ${formatCount(d.methodCount)} mtd`;
    return `<option value="${i}">${escapeHtml(d.name || `dex-${i}`)} (${cm})</option>`;
  }).join('');
  dexFileSelect.value = String(activeDexIndex);
}

function applyActiveDexToState(index) {
  const entry = loadedDexFiles[index];
  if (!entry) return false;
  activeDexIndex = index;
  currentData = entry.data;
  currentDexBytes = entry.bytes;
  currentFilename = entry.name || currentFilename;
  currentType = 'dex';
  currentDexSelection = { classIdx: 0, methodIdx: 0 };
  codeViewClassIdx = 0;
  codeViewMethodIdx = null;
  codeViewPackage = '';
  selectedDexPackage = '';
  dexSearchIndex = null;
  loadDexRenamesFromStorage();
  loadDexAnnotationsFromStorage();
  loadDexBookmarksFromStorage();
  loadCfgMethodBlockState();
  lastEmulatorRun = null;
  if (fileName) {
    const label = loadedDexFiles.length > 1
      ? `${entry.name} (${index + 1}/${loadedDexFiles.length})`
      : entry.name;
    fileName.textContent = label;
    fileName.title = loadedDexFiles.map((d) => d.name).join(', ');
  }
  currentFileBytes = entry.bytes || currentFileBytes;
  setHexEditorBytes(entry.bytes, entry.name || 'classes.dex');
  return true;
}

function switchActiveDex(index) {
  if (index < 0 || index >= loadedDexFiles.length) return;
  if (index === activeDexIndex && currentData === loadedDexFiles[index]?.data) {
    updateDexFileSelector();
    return;
  }
  if (!applyActiveDexToState(index)) return;
  updateDexFileSelector();
  render();
  updateStatusBar();
}

function summarizeDexEntry(name, bytes, data) {
  const classes = Array.isArray(data?.classes) ? data.classes : [];
  const cm = countDexClassesMethods(classes);
  return {
    name: name || 'classes.dex',
    bytes,
    data,
    classCount: cm.classes,
    methodCount: cm.methods,
  };
}

function loadedDexTotals() {
  let classes = 0;
  let methods = 0;
  for (const d of loadedDexFiles) {
    classes += d.classCount || 0;
    methods += d.methodCount || 0;
  }
  return { classes, methods, dexFiles: loadedDexFiles.length };
}

/** Entry: one or many File objects (upload / drop). */
async function processFiles(fileList) {
  const files = Array.from(fileList || []).filter(Boolean);
  if (!files.length) return;

  if (files.length === 1) {
    await processFile(files[0]);
    return;
  }

  // Multi-file: prefer all DEX files; if none, fall back to first file.
  const buffers = [];
  for (const file of files) {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    buffers.push({ file, bytes });
  }
  const dexOnes = buffers.filter(({ file, bytes }) => isLikelyDexFile(file, bytes));
  if (dexOnes.length >= 1) {
    await processDexList(dexOnes.map(({ file, bytes }) => ({ name: file.name, bytes })));
    return;
  }
  await processFile(files[0]);
}

async function processDexList(entries) {
  const list = (entries || []).filter((e) => e?.bytes?.length);
  if (!list.length) {
    showError('No DEX bytes to load');
    return;
  }
  if (list.length === 1) {
    // Reuse single-file path for identical UX / cache fingerprint naming
    const f = new File([list[0].bytes], list[0].name || 'classes.dex', { type: 'application/octet-stream' });
    await processFile(f);
    return;
  }

  const step = (s) => debug('[processDexList]', s);
  step('start count=' + list.length);
  if (securityCachePromptResolver) closeSecurityCacheModal('keep');

  loadingOverlay.classList.add('visible');
  loadingOverlay.setAttribute('aria-hidden', 'false');
  setUiActivity('load', 'Loading DEX list', `${list.length} files`);
  ensureMainWasm();

  const loaded = [];
  try {
    await ensureMainWasm();
    for (let i = 0; i < list.length; i++) {
      const { name, bytes } = list[i];
      step(`parse ${i + 1}/${list.length}: ${name}`);
      setUiActivity('load', 'Loading DEX list', `${i + 1}/${list.length} · ${shortDexLabel(name)}`);
      const bytesForWorker = bytes.slice();
      const bytesForMain = new Uint8Array(bytes);
      let raw;
      try {
        raw = await parseFileInWorker(bytesForWorker, name);
      } catch (parseErr) {
        warn('[processDexList] parse failed', name, parseErr);
        continue;
      }
      let result;
      try {
        // parseFileInWorker already decodes transferable UTF-8 JSON.
        result = typeof raw === 'string' ? JSON.parse(raw) : raw;
      } catch (jsonErr) {
        warn('[processDexList] decode failed', name, jsonErr);
        continue;
      }
      if (!result?.ok || !result.data) {
        warn('[processDexList] not ok', name, result?.error);
        continue;
      }
      const data = result.data;
      if (!Array.isArray(data.classes)) data.classes = data.classes ?? [];
      if (!Array.isArray(data.strings)) data.strings = data.strings ?? [];
      const type = detectType(bytesForMain, name);
      if (type !== 'dex') {
        warn('[processDexList] skip non-dex', name, type);
        continue;
      }
      loaded.push(summarizeDexEntry(name, bytesForMain, data));
      await yieldToUi();
    }

    if (!loaded.length) {
      showError('Could not parse any DEX from the selection');
      return;
    }

    currentApkBytes = null;
    clearApkResourceMap();
    apkExtractedFile = null;
    apkExtractedDexSelection = { classIdx: 0, methodIdx: 0 };
    resetApkClassIndexMaps();
    apkClassIndexPromise = null;
    apkPermissionUsageIndex = null;
    apkPermissionUsagePromise = null;
    apkPermissionUsageStatus = '';
    apkDexStats = { dexFiles: 0, classes: 0, methods: 0, ready: false, totalDex: 0, current: 0, currentName: '' };
    clearAllUiActivity();
    closeAllApkFileTabs();
    clearSecurityResultsInMemory();

    loadedDexFiles = loaded;
    applyActiveDexToState(0);
    updateDexFileSelector();
    renderSecurityPanel();
    setSecurityStatus('DEX list loaded — checking security cache…');
    render();
    step('done loaded=' + loaded.length);
  } catch (err) {
    error('processDexList error', err);
    showError(err.message || String(err));
  } finally {
    loadingOverlay.classList.remove('visible');
    loadingOverlay.setAttribute('aria-hidden', 'true');
    clearUiActivity('load');
  }

  if (currentData && currentType === 'dex') {
    await resetSecurityResults();
  }
}

async function processFile(file) {
  const step = (s) => {
    debug('[processFile]', s, file.name);
  };
  step('start');
  startPerfSession(`load:${file.name}`);
  xmlViewerMountCache = null;
  if (securityCachePromptResolver) closeSecurityCacheModal('keep');
  currentFilename = file.name;
  fileName.textContent = file.name;
  fileName.title = file.name;
  clearSourceNavStack();

  loadingOverlay.classList.add('visible');
  loadingOverlay.setAttribute('aria-hidden', 'false');
  setUiActivity('load', 'Loading file', file.name);
  if (file.size > 40 * 1024 * 1024) {
    setWorkNotice(
      'Loading large file in this browser',
      `${formatFileSize(file.size)} — parsing and indexing run locally (WASM). Brief freezes are normal; watch the bottom status bar.`,
      { tone: 'warn', sticky: true }
    );
  } else {
    setWorkNotice(null);
  }

  const loadingTimeoutMs = 30000;
  const loadingTimeoutId = setTimeout(() => {
    if (loadingOverlay.classList.contains('visible')) {
      warn('[processFile] loading still visible after', loadingTimeoutMs / 1000, 's — check console for last [processFile] or [timing] step');
    }
  }, loadingTimeoutMs);
  const loadingWarn5s = setTimeout(() => {
    if (loadingOverlay.classList.contains('visible')) {
      debug('[processFile] still loading after 5s (large file?) — wait for parse_file / render or check last step');
    }
  }, 5000);

  try {
    const t = timer();
    step('reading arrayBuffer... file.size=' + file.size);
    const buf = await file.arrayBuffer();
    t('after arrayBuffer');
    const bytes = new Uint8Array(buf);
    const bytesForWorker = bytes.slice();
    const bytesForMain = new Uint8Array(bytes);
    step('arrayBuffer done, bytes=' + bytes.length + ' (MB=' + (bytes.length / (1024 * 1024)).toFixed(2) + ') first8=' + Array.from(bytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Parse runs in a worker (its own WASM). Kick that off immediately; init main-thread
    // WASM in parallel (only needed later for get_apk_file_content / get_dex_method).
    ensureMainWasm(); // start early — do not await yet

    step('parse_file (worker)... bytes.length=' + bytesForWorker.length);
    setUiActivity('load', 'Parsing file', `${file.name} · ${formatFileSize(bytes.length)}`);
    let result;
    try {
      result = await parseFileInWorker(bytesForWorker, file.name);
    } catch (parseErr) {
      error('[processFile] parse_file (worker) failed', parseErr, 'bytes.length=' + bytesForWorker.length, 'name=' + file.name);
      throw parseErr;
    }
    t('parse_file (worker) done');
    step('parse_file returned type=' + typeof result + (result && typeof result === 'object' ? ' keys=' + Object.keys(result).join(',') : ''));

    step('waiting for main-thread WASM (if still loading)…');
    await ensureMainWasm();
    t('main WASM ready');

    step('parse result ok=' + !!result?.ok + (result?.ok ? ' dataKeys=' + (result.data ? Object.keys(result.data).join(',') : '') : ' error=' + (result?.error || '')));

    if (result.ok) {
      currentData = result.data;
      currentType = detectType(bytesForMain, file.name);
      currentDexBytes = currentType === 'dex' ? bytesForMain : null;
      currentFileBytes = bytesForMain;
      if (currentType === 'dex') currentDexSelection = { classIdx: 0, methodIdx: 0 };
      dexSearchIndex = null;
      apkExtractedFile = null;
      apkExtractedDexSelection = { classIdx: 0, methodIdx: 0 };
      apkLeftMode = 'classes';
      apkDexFilter = '';
      resetApkClassIndexMaps();
      apkClassIndexPromise = null;
      apkPermissionUsageIndex = null;
      apkPermissionUsagePromise = null;
      apkPermissionUsageStatus = '';
      apkDexStats = { dexFiles: 0, classes: 0, methods: 0, ready: false, totalDex: 0, current: 0, currentName: '' };
      clearAllUiActivity();
      closeAllApkFileTabs();
      if (currentType === 'dex' && currentData != null) {
        if (!Array.isArray(currentData.classes)) {
          warn('DEX data.classes missing or not array, keys=', Object.keys(currentData));
          currentData = { file_info: currentData.file_info, strings: currentData.strings ?? [], classes: currentData.classes ?? [] };
        }
        if (!Array.isArray(currentData.strings)) currentData.strings = [];
        const nc = (currentData.classes || []).length;
        const nm = (currentData.classes || []).reduce((s, c) => s + (c?.methods?.length ?? 0), 0);
        debug(
          'DEX loaded',
          'classes=', nc,
          'methods total=', nm,
          'strings=', (currentData.strings || []).length,
          currentData.strings_omitted ? `(omitted, count=${currentData.string_count || 0})` : ''
        );
        loadedDexFiles = [summarizeDexEntry(file.name, bytesForMain, currentData)];
        activeDexIndex = 0;
        updateDexFileSelector();
      } else {
        clearStandaloneDexSession();
      }
      if (currentType === 'apk') {
        currentApkBytes = bytesForMain;
        clearApkResourceMap();
        // Warm ARSC → R.* map for decompiler (async, non-blocking).
        ensureApkResourceMap().catch(() => {});
      } else {
        currentApkBytes = null;
        clearApkResourceMap();
      }
      loadDexRenamesFromStorage();
      loadDexAnnotationsFromStorage();
      loadDexBookmarksFromStorage();
      loadCfgMethodBlockState();
      // Clear in-memory security UI; prompt for localStorage after overlay hides
      clearSecurityResultsInMemory();
      renderSecurityPanel();
      setSecurityStatus('File loaded — checking security cache…');
      step('detected type=' + currentType + (currentType === 'dex' && currentData?.classes != null ? ' classes=' + currentData.classes.length : '') + (currentType === 'apk' && currentData?.files != null ? ' files=' + currentData.files.length : ''));

      step('render...');
      render();
      t('render done (total load)');
      step('render done');
    } else {
      currentData = null;
      currentType = null;
      clearStandaloneDexSession();
      dexRenames = emptyDexRenames();
      warn('parse failed:', result.error);
      showError(result.error || 'Parse failed');
    }
  } catch (err) {
    currentData = null;
    clearStandaloneDexSession();
    dexRenames = emptyDexRenames();
    error('processFile error', err);
    showError(err.message || String(err));
  } finally {
    clearTimeout(loadingTimeoutId);
    clearTimeout(loadingWarn5s);
    step('finally: hiding loading overlay');
    loadingOverlay.classList.remove('visible');
    loadingOverlay.setAttribute('aria-hidden', 'true');
    clearUiActivity('load');
  }
  // Ask keep/clear after load UI is interactive (same APK/DEX with cached scans)
  if (currentData && (currentType === 'apk' || currentType === 'dex' || currentType === 'axml')) {
    await resetSecurityResults();
  }
}

fileInput.addEventListener('change', async (e) => {
  const files = e.target.files ? Array.from(e.target.files) : [];
  debug('file input change', files.map((f) => f.name));
  e.target.value = '';
  if (!files.length) return;
  processFiles(files);
});

function detectType(bytes, name) {
  const n = name.toLowerCase();
  if (bytes.length >= 4 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78) return 'dex';
  if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b) return 'apk';
  if (bytes.length >= 4 && bytes[0] === 0x03 && bytes[1] === 0x00 && bytes[2] === 0x08) return 'axml';
  if (bytes.length >= 4 && bytes[0] === 0x02 && bytes[1] === 0x00 && bytes[2] === 0x0c) return 'arsc';
  if (n.endsWith('.dex')) return 'dex';
  if (n.endsWith('.apk') || n.endsWith('.jar') || n.endsWith('.zip')) return 'apk';
  if (n.endsWith('.xml') || n.endsWith('.axml')) return 'axml';
  if (n.endsWith('.arsc')) return 'arsc';
  return 'unknown';
}

function showError(msg) {
  debug('showError', msg);
  treePlaceholder.textContent = msg;
  treePlaceholder.style.display = 'block';
  treeContent.style.display = 'none';
  treeContent.innerHTML = '';
  if (listSearchWrap) listSearchWrap.style.display = 'none';
  if (dexPackageWrap) dexPackageWrap.style.display = 'none';
  if (dexFileWrap) dexFileWrap.style.display = 'none';
  updateApkLeftModeButtons();
  bytecodeListing.innerHTML = `<div class="muted">${escapeHtml(msg)}</div>`;
  sourceCode.innerHTML = '';
  setManifestPlaceholder('');
  infoContent.innerHTML = `<div class="muted">${escapeHtml(msg)}</div>`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Update currentStringsArray and re-render strings list. */
function setStringsAndRender(stringsArray) {
  currentStringsArray = Array.isArray(stringsArray) ? stringsArray : [];
  stringsSelectedIdx = null;
  stringsFilteredIdx = [];
  stringsUsageCache = new Map();
  stringsUsageCacheKey = '';
  renderStringsList(true);
}

/** @type {Promise<void>|null} */
let dexStringsLoadPromise = null;

/**
 * Browse parse omits the string pool (`strings_omitted`). Load it in the worker
 * when the Strings tab / search needs it — still 100% in-browser WASM.
 */
function scheduleEnsureDexStringsLoaded() {
  ensureDexStringsLoaded().catch((e) => warn('[strings] lazy load failed', e));
}

async function ensureDexStringsLoaded() {
  const data = (currentType === 'apk' && apkExtractedFile?.kind === 'dex')
    ? apkExtractedFile.data
    : currentData;
  if (!data || !data.strings_omitted) {
    const existing = Array.isArray(data?.strings) ? data.strings : [];
    if (existing.length && currentStringsArray !== existing) setStringsAndRender(existing);
    return;
  }
  if (Array.isArray(data.strings) && data.strings.length > 0) {
    setStringsAndRender(data.strings);
    return;
  }
  if (dexStringsLoadPromise) return dexStringsLoadPromise;

  const bytes = (currentType === 'apk' && apkExtractedFile?.kind === 'dex')
    ? (apkExtractedFileRawBytes || apkExtractedFile.bytes)
    : currentDexBytes;
  if (!bytes || !bytes.length) {
    if (stringsCountEl) {
      stringsCountEl.textContent = data.string_count
        ? `${formatCount(data.string_count)} strings (not loaded)`
        : '';
    }
    return;
  }

  dexStringsLoadPromise = (async () => {
    setUiActivity('strings', 'Loading strings', formatCount(data.string_count || 0));
    try {
      const result = await getDexStringsInWorker(bytes);
      const list = result?.ok && Array.isArray(result.data) ? result.data : [];
      data.strings = list;
      data.strings_omitted = false;
      setStringsAndRender(list);
      debug('[strings] loaded', list.length);
    } finally {
      clearUiActivity('strings');
      dexStringsLoadPromise = null;
    }
  })();
  return dexStringsLoadPromise;
}

function scheduleRenderStringsList(immediate = false) {
  clearTimeout(stringsRenderTimer);
  if (immediate) {
    renderStringsList();
    return;
  }
  stringsRenderTimer = setTimeout(() => renderStringsList(), 80);
}

function classifyStringKind(text) {
  const s = String(text ?? '');
  if (!s) return '';
  if (/^https?:\/\//i.test(s) || /^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return 'url';
  if (/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?$/.test(s)
    || /^\[?[0-9a-f:]+\]?(?::\d+)?$/i.test(s) && s.includes(':')) return 'ip';
  if ((s.startsWith('{') && s.endsWith('}')) || (s.startsWith('[') && s.endsWith(']'))) {
    if (/[{}\[\]":,]/.test(s) && s.length >= 2) return 'json';
  }
  if (/^L[\w/$]+;$/.test(s) || /^\[*L[\w/$]+;$/.test(s) || /^[\w.$]+(\.[\w$]+)+$/.test(s) && /[A-Z]/.test(s)) return 'class';
  if (/^(\/[\w.\-@%]+)+\/?$/.test(s) || /^[A-Za-z]:\\/.test(s) || s.includes('://') === false && (s.startsWith('./') || s.startsWith('../'))) return 'path';
  if (s.length >= 16 && s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s)) return 'base64';
  if (s.length >= 80) return 'long';
  return '';
}

function stringMatchesTypeFilter(text, kind, filter) {
  if (!filter || filter === 'all') return true;
  if (filter === 'long') return String(text ?? '').length >= 80;
  return kind === filter;
}

function buildStringsFilterPredicate() {
  const raw = (stringsSearchInput?.value || '').trim();
  const caseSensitive = !!stringsCaseCb?.checked;
  const useRegex = !!stringsRegexCb?.checked;
  const minLen = Math.max(0, parseInt(stringsMinLenInput?.value || '0', 10) || 0);
  let re = null;
  let needle = '';
  if (raw) {
    if (useRegex) {
      try {
        re = new RegExp(raw, caseSensitive ? '' : 'i');
      } catch (_) {
        return () => false;
      }
    } else {
      needle = caseSensitive ? raw : raw.toLowerCase();
    }
  }
  return (text) => {
    const s = String(text ?? '');
    if (s.length < minLen) return false;
    if (!raw) return true;
    if (re) return re.test(s);
    return caseSensitive ? s.includes(needle) : s.toLowerCase().includes(needle);
  };
}

function rebuildStringsFilteredIdx() {
  const pred = buildStringsFilterPredicate();
  const type = stringsTypeFilter || 'all';
  const out = [];
  for (let i = 0; i < currentStringsArray.length; i++) {
    const s = currentStringsArray[i];
    if (!pred(s)) continue;
    const kind = classifyStringKind(s);
    if (!stringMatchesTypeFilter(s, kind, type)) continue;
    out.push(i);
  }
  const sort = stringsSortSelect?.value || 'index';
  if (sort === 'length-desc') {
    out.sort((a, b) => String(currentStringsArray[b] ?? '').length - String(currentStringsArray[a] ?? '').length || a - b);
  } else if (sort === 'length-asc') {
    out.sort((a, b) => String(currentStringsArray[a] ?? '').length - String(currentStringsArray[b] ?? '').length || a - b);
  } else if (sort === 'alpha') {
    out.sort((a, b) => String(currentStringsArray[a] ?? '').localeCompare(String(currentStringsArray[b] ?? '')) || a - b);
  }
  stringsFilteredIdx = out;
  if (stringsSelectedIdx != null && !out.includes(stringsSelectedIdx)) {
    stringsSelectedIdx = out.length ? out[0] : null;
  }
}

/** Render strings list using currentStringsArray and toolbar filters (virtualized). */
function renderStringsList(resetScroll = false) {
  if (!stringsList) return;
  rebuildStringsFilteredIdx();
  if (resetScroll) stringsList.scrollTop = 0;

  const total = currentStringsArray.length;
  const shown = stringsFilteredIdx.length;
  const omittedHint = (() => {
    const data = (currentType === 'apk' && apkExtractedFile?.kind === 'dex')
      ? apkExtractedFile.data
      : currentData;
    if (data?.strings_omitted && !total) {
      return Number(data.string_count) || 0;
    }
    return 0;
  })();
  if (stringsCountEl) {
    if (omittedHint) stringsCountEl.textContent = `${formatCount(omittedHint)} strings (loading…)`;
    else if (!total) stringsCountEl.textContent = '';
    else if (shown === total) stringsCountEl.textContent = `${formatCount(total)} strings`;
    else stringsCountEl.textContent = `${formatCount(shown)} of ${formatCount(total)}`;
  }

  if (!total) {
    stringsList.innerHTML = omittedHint
      ? '<div class="strings-empty">Loading string pool…</div>'
      : '<div class="strings-empty">No strings in this DEX.</div>';
    updateStringsDetail();
    updateStringsActionButtons();
    return;
  }
  if (!shown) {
    const filter = (stringsSearchInput?.value || '').trim();
    stringsList.innerHTML = `<div class="strings-empty">No strings match${filter ? ` “${escapeHtml(filter)}”` : ''}.</div>`;
    updateStringsDetail();
    updateStringsActionButtons();
    return;
  }

  stringsList.innerHTML = `<div class="strings-virt" id="strings-virt" style="height:${shown * STRINGS_ROW_H}px"></div>`;
  paintStringsVirtualWindow();
  updateStringsDetail();
  updateStringsActionButtons();
}

function paintStringsVirtualWindow() {
  const virt = document.getElementById('strings-virt');
  if (!virt || !stringsList) return;
  const shown = stringsFilteredIdx.length;
  virt.style.height = `${shown * STRINGS_ROW_H}px`;
  const viewH = stringsList.clientHeight || 400;
  const scrollTop = stringsList.scrollTop;
  let start = Math.floor(scrollTop / STRINGS_ROW_H) - STRINGS_OVERSCAN;
  let end = Math.ceil((scrollTop + viewH) / STRINGS_ROW_H) + STRINGS_OVERSCAN;
  start = Math.max(0, start);
  end = Math.min(shown, end);
  let html = '';
  for (let row = start; row < end; row++) {
    const idx = stringsFilteredIdx[row];
    const text = String(currentStringsArray[idx] ?? '');
    const kind = classifyStringKind(text);
    const selected = idx === stringsSelectedIdx ? ' selected' : '';
    html += `<div class="string-item${selected}" role="option" aria-selected="${idx === stringsSelectedIdx ? 'true' : 'false'}" data-string-idx="${idx}" data-row="${row}" style="top:${row * STRINGS_ROW_H}px" title="${escapeAttr(text.length > 200 ? text.slice(0, 197) + '…' : text)}">` +
      `<span class="string-item-idx">${idx}</span>` +
      `<span class="string-item-text">${escapeHtml(text)}</span>` +
      (kind ? `<span class="string-item-kind">${kind}</span>` : '') +
      `<span class="string-item-len">${text.length}</span>` +
      `</div>`;
  }
  virt.innerHTML = html;
}

function selectStringIndex(idx, { scrollIntoView = false } = {}) {
  if (idx == null || idx < 0 || idx >= currentStringsArray.length) return;
  stringsSelectedIdx = idx;
  updateStringsDetail();
  updateStringsActionButtons();
  if (scrollIntoView) {
    const pos = stringsFilteredIdx.indexOf(idx);
    if (pos >= 0 && stringsList) {
      const top = pos * STRINGS_ROW_H;
      const bottom = top + STRINGS_ROW_H;
      if (top < stringsList.scrollTop) stringsList.scrollTop = top;
      else if (bottom > stringsList.scrollTop + stringsList.clientHeight) {
        stringsList.scrollTop = bottom - stringsList.clientHeight;
      }
    }
  }
  paintStringsVirtualWindow();
}

function getActiveStringsDexBytes() {
  const ctx = typeof getCodeViewContext === 'function' ? getCodeViewContext() : null;
  if (ctx?.bytes?.length) return { bytes: ctx.bytes, label: ctx.isApk ? (apkExtractedFile?.name || 'classes.dex') : (currentFilename || 'classes.dex') };
  if (currentType === 'dex' && currentDexBytes?.length) {
    return { bytes: currentDexBytes, label: currentFilename || 'classes.dex' };
  }
  if (apkExtractedFile?.kind === 'dex' && apkExtractedFile.bytes?.length) {
    return { bytes: apkExtractedFile.bytes, label: apkExtractedFile.name || 'classes.dex' };
  }
  return null;
}

function stringsUsageCacheFingerprint(bytes) {
  return `${bytes?.length || 0}|${currentFilename || ''}|${apkExtractedFile?.name || ''}|${activeDexIndex}`;
}

function jumpDexOffsetToHexEditor(fileOffset, label) {
  if (!rawHexEditor || fileOffset == null || Number.isNaN(Number(fileOffset))) return;
  const off = Number(fileOffset) >>> 0;
  const dex = getActiveStringsDexBytes();
  const bytes = dex?.bytes;
  const name = label || dex?.label || 'classes.dex';
  if (bytes?.length) setHexEditorBytes(bytes, name);
  else if (!rawHexEditor.getBytes()?.length && currentDexBytes?.length) {
    setHexEditorBytes(currentDexBytes, currentFilename || 'classes.dex');
  }
  switchToCenterTab('raw-tab');
  if (typeof rawHexEditor.goTo === 'function') {
    rawHexEditor.goTo(off, { selectLen: 4 });
  } else if (typeof rawHexEditor.highlightRange === 'function') {
    rawHexEditor.highlightRange(off, 4);
  }
}

function renderStringsUsagesHtml(info) {
  if (!info) return '<div class="muted">No usage data</div>';
  const poolBits = [];
  if (info.string_data_off != null || info.stringDataOff != null) {
    const dataOff = info.string_data_off ?? info.stringDataOff;
    poolBits.push(
      `<button type="button" class="strings-usage-link" data-raw-off="${dataOff}" title="Jump to string_data in Raw">pool ${formatSecHexOffset(dataOff)}</button>`
    );
  }
  if (info.string_id_off != null || info.stringIdOff != null) {
    const idOff = info.string_id_off ?? info.stringIdOff;
    poolBits.push(
      `<button type="button" class="strings-usage-link" data-raw-off="${idOff}" title="Jump to string_id item in Raw">id ${formatSecHexOffset(idOff)}</button>`
    );
  }
  const usages = Array.isArray(info.usages) ? info.usages : [];
  const truncated = !!(info.truncated);
  let body;
  if (!usages.length) {
    body = `<div class="muted">No const-string references in this DEX</div>`;
  } else {
    const max = 80;
    const rows = usages.slice(0, max).map((u) => {
      const className = u.class_name || u.className || '';
      const methodName = u.method_name || u.methodName || '';
      const simple = className.split('.').pop() || className || '?';
      const insnOff = u.offset;
      const fileOff = u.file_offset ?? u.fileOffset;
      const loc = `${simple}.${methodName || '?'}`;
      const codeBtn = `<button type="button" class="strings-usage-link" data-class="${escapeAttr(className)}" data-method="${escapeAttr(methodName)}" data-offset="${insnOff ?? ''}" title="Open in Code @ ${formatSecHexOffset(insnOff)}">${escapeHtml(loc)}</button>`;
      const rawBtn = fileOff != null
        ? `<button type="button" class="strings-usage-raw" data-raw-off="${fileOff}" title="Raw @ ${formatSecHexOffset(fileOff)}">${escapeHtml(formatSecHexOffset(fileOff))}</button>`
        : '';
      return `<div class="strings-usage-row">${codeBtn}${rawBtn}</div>`;
    }).join('');
    const more = usages.length > max
      ? `<div class="muted">+${usages.length - max} more</div>`
      : (truncated ? `<div class="muted">…truncated</div>` : '');
    body = `<div class="strings-usage-list">${rows}${more}</div>`;
  }
  const countLabel = usages.length
    ? `${usages.length} use${usages.length === 1 ? '' : 's'}${truncated ? '+' : ''}`
    : '0 uses';
  return `<div class="strings-usage-pool">${poolBits.join('')}<span class="muted">${escapeHtml(countLabel)}</span></div>${body}`;
}

async function loadAndShowStringUsages(stringIndex) {
  const host = document.getElementById('strings-detail-usages');
  const body = document.getElementById('strings-detail-usages-body');
  if (!host || !body) return;
  host.hidden = false;
  const dex = getActiveStringsDexBytes();
  if (!dex?.bytes?.length) {
    body.innerHTML = '<div class="muted">No DEX bytes loaded</div>';
    return;
  }
  const reqId = ++stringsUsageRequestId;
  body.innerHTML = '<div class="muted">Finding usages…</div>';
  try {
    const info = await fetchStringUsagesInfo(stringIndex);
    if (reqId !== stringsUsageRequestId || stringsSelectedIdx !== stringIndex) return;
    body.innerHTML = renderStringsUsagesHtml(info);
    // Keep bytecode string xrefs in sync when Strings tab already scanned this index.
    if (bytecodeListing?.querySelector(`.bytecode-string-xref[data-string-idx="${stringIndex}"]`)) {
      loadBytecodeStringXrefs(stringIndex);
    }
  } catch (e) {
    if (reqId !== stringsUsageRequestId) return;
    body.innerHTML = `<div class="muted">${escapeHtml(e?.message || String(e))}</div>`;
  }
}

function updateStringsDetail() {
  if (!stringsDetail) return;
  const usagesHost = document.getElementById('strings-detail-usages');
  const usagesBody = document.getElementById('strings-detail-usages-body');
  if (stringsSelectedIdx == null || !currentStringsArray.length) {
    stringsDetail.hidden = true;
    if (stringsDetailText) stringsDetailText.textContent = '';
    if (stringsDetailMeta) stringsDetailMeta.textContent = '';
    if (usagesHost) usagesHost.hidden = true;
    if (usagesBody) usagesBody.innerHTML = '';
    return;
  }
  const text = String(currentStringsArray[stringsSelectedIdx] ?? '');
  const kind = classifyStringKind(text);
  stringsDetail.hidden = false;
  if (stringsDetailMeta) {
    stringsDetailMeta.textContent = `#${stringsSelectedIdx} · ${text.length} chars${kind ? ` · ${kind}` : ''}`;
  }
  if (stringsDetailText) stringsDetailText.textContent = text;
  loadAndShowStringUsages(stringsSelectedIdx);
}

function updateStringsActionButtons() {
  const hasSel = stringsSelectedIdx != null;
  const hasFiltered = stringsFilteredIdx.length > 0;
  if (stringsCopyBtn) stringsCopyBtn.disabled = !hasSel && !hasFiltered;
  if (stringsJumpRawBtn) stringsJumpRawBtn.disabled = !hasSel;
  if (stringsExportBtn) stringsExportBtn.disabled = !hasFiltered;
}

async function copyTextToClipboard(text, okMsg) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    if (okMsg && typeof setSecurityStatus === 'function') {
      /* no-op — prefer subtle UI */
    }
    const btn = stringsCopyBtn;
    if (btn && okMsg) {
      const prev = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = prev; }, 900);
    }
  } catch (e) {
    warn('clipboard copy failed', e);
  }
}

function copySelectedOrFilteredStrings() {
  if (stringsSelectedIdx != null) {
    copyTextToClipboard(String(currentStringsArray[stringsSelectedIdx] ?? ''), 'String copied');
    return;
  }
  if (!stringsFilteredIdx.length) return;
  const text = stringsFilteredIdx.map((i) => String(currentStringsArray[i] ?? '')).join('\n');
  copyTextToClipboard(text, 'Copied');
}

function exportFilteredStrings() {
  if (!stringsFilteredIdx.length) return;
  const lines = stringsFilteredIdx.map((i) => String(currentStringsArray[i] ?? ''));
  const blob = new Blob([lines.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  const base = (currentFilename || 'strings').replace(/\.[^.]+$/, '');
  a.href = URL.createObjectURL(blob);
  a.download = `${base}-strings.txt`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/** Trigger a browser download for a Blob. */
function downloadBlobFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'download';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function crc32Table() {
  if (crc32Table._t) return crc32Table._t;
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c >>> 0;
  }
  crc32Table._t = t;
  return t;
}

function crc32Bytes(bytes) {
  const table = crc32Table();
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = table[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function u16le(n) {
  return [n & 0xff, (n >>> 8) & 0xff];
}

function u32le(n) {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

/** Build an uncompressed (store) ZIP from `{ path, content }` entries. */
function buildZipStore(files) {
  const enc = new TextEncoder();
  const locals = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = String(f.path || 'file.java').replace(/^\/+/, '').replace(/\\/g, '/');
    const nameBytes = enc.encode(name);
    const data = typeof f.content === 'string' ? enc.encode(f.content) : (f.content || new Uint8Array(0));
    const crc = crc32Bytes(data);
    const local = new Uint8Array([
      0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ...u32le(crc), ...u32le(data.length), ...u32le(data.length),
      ...u16le(nameBytes.length), ...u16le(0),
      ...nameBytes, ...data,
    ]);
    const cen = new Uint8Array([
      0x50, 0x4b, 0x01, 0x02, 0x14, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ...u32le(crc), ...u32le(data.length), ...u32le(data.length),
      ...u16le(nameBytes.length), ...u16le(0), ...u16le(0), ...u16le(0), ...u16le(0),
      ...u32le(0), ...u32le(offset),
      ...nameBytes,
    ]);
    locals.push(local);
    central.push(cen);
    offset += local.length;
  }
  const centralSize = central.reduce((n, b) => n + b.length, 0);
  const end = new Uint8Array([
    0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
    ...u16le(files.length), ...u16le(files.length),
    ...u32le(centralSize), ...u32le(offset),
    ...u16le(0),
  ]);
  const total = offset + centralSize + end.length;
  const out = new Uint8Array(total);
  let p = 0;
  for (const b of locals) { out.set(b, p); p += b.length; }
  for (const b of central) { out.set(b, p); p += b.length; }
  out.set(end, p);
  return out;
}

function sanitizeDownloadBase(name) {
  return String(name || 'source')
    .replace(/\.[^.]+$/, '')
    .replace(/[^\w.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 48) || 'source';
}

function javaFileNameFromClass(className) {
  const simple = String(className || 'Class').split('.').pop() || 'Class';
  return `${simple.replace(/[^\w$]+/g, '_')}.java`;
}

/** Decompile one class via WASM (full class Java). */
async function decompileClassSource(classIdx) {
  const ctx = getCodeViewContext();
  const bytes = ctx?.bytes;
  if (!bytes?.length) throw new Error('No DEX loaded');
  await ensureMainWasm();
  await ensureApkResourceMap();
  const raw = decompile_dex_class(bytes, classIdx, getDexRenamesObject());
  const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
  if (!result?.ok) throw new Error(result?.error || 'Decompile failed');
  let info = result.data || result;
  if (typeof normalizeWasmResult === 'function') info = normalizeWasmResult(info) || info;
  if (!info?.source) throw new Error('Empty decompilation');
  return {
    name: info.name || ctx.classes?.[classIdx]?.name || `class_${classIdx}`,
    relative_path: info.relative_path || info.relativePath || javaFileNameFromClass(info.name),
    source: info.source,
  };
}

function classIndicesForSourceExport(scope) {
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  if (!Array.isArray(classes) || !classes.length) return [];
  if (scope === 'class') {
    const idx = codeViewClassIdx;
    if (idx == null || !classes[idx]) return [];
    return [idx];
  }
  if (scope === 'package') {
    const pkg = codeViewPackage || getPackageFromClassName(classes[codeViewClassIdx]?.name || '');
    return getClassesInPackage(classes, pkg);
  }
  // entire current DEX (respect UI filter)
  const out = [];
  for (let i = 0; i < classes.length; i++) {
    if (shouldShowClassInUi(classes[i]?.name)) out.push(i);
  }
  return out;
}

let sourceExportBusy = false;

/** Export decompiled Java: one .java or a package/DEX .zip. */
async function exportDecompiledSource(scope) {
  if (sourceExportBusy) return;
  const indices = classIndicesForSourceExport(scope);
  if (!indices.length) {
    setUiActivity('export-src', 'Nothing to export', 'Select a class or package first');
    setTimeout(() => clearUiActivity('export-src'), 1800);
    return;
  }
  sourceExportBusy = true;
  const base = sanitizeDownloadBase(
    currentFilename
      || apkExtractedFile?.name
      || 'classes'
  );
  try {
    if (indices.length === 1 && scope === 'class') {
      setUiActivity('export-src', 'Exporting class', 'decompiling…');
      await yieldToUiFrame();
      const info = await decompileClassSource(indices[0]);
      const file = (info.relative_path || '').split('/').pop() || javaFileNameFromClass(info.name);
      downloadBlobFile(new Blob([info.source], { type: 'text/x-java-source;charset=utf-8' }), file);
      setUiActivity('export-src', 'Exported', file);
      setTimeout(() => clearUiActivity('export-src'), 1600);
      return;
    }
    const files = [];
    const usedPaths = new Set();
    for (let i = 0; i < indices.length; i++) {
      const classIdx = indices[i];
      const label = getCodeViewContext()?.classes?.[classIdx]?.name?.split('.').pop() || String(classIdx);
      setUiActivity('export-src', 'Exporting source', `${i + 1}/${indices.length} · ${label}`);
      await yieldToUiFrame();
      try {
        const info = await decompileClassSource(classIdx);
        let path = String(info.relative_path || javaFileNameFromClass(info.name)).replace(/^\/+/, '');
        if (usedPaths.has(path)) path = path.replace(/\.java$/i, `_${classIdx}.java`);
        usedPaths.add(path);
        files.push({ path, content: info.source });
      } catch (e) {
        warn('[export source] class failed', classIdx, e);
      }
    }
    if (!files.length) throw new Error('No classes decompiled');
    const zipName = scope === 'package'
      ? `${base}-${sanitizeDownloadBase(codeViewPackage || 'package')}.zip`
      : `${base}-src.zip`;
    downloadBlobFile(new Blob([buildZipStore(files)], { type: 'application/zip' }), zipName);
    setUiActivity('export-src', 'Exported', `${files.length} file(s) · ${zipName}`);
    setTimeout(() => clearUiActivity('export-src'), 2000);
  } catch (e) {
    warn('[export source]', e);
    setUiActivity('export-src', 'Export failed', e?.message || String(e));
    setTimeout(() => clearUiActivity('export-src'), 2500);
  } finally {
    sourceExportBusy = false;
  }
}

function openSourceExportMenu(clientX, clientY) {
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  if (!Array.isArray(classes) || !classes.length) {
    setUiActivity('export-src', 'Nothing to export', 'Load a DEX / APK first');
    setTimeout(() => clearUiActivity('export-src'), 1800);
    return;
  }
  const className = classes[codeViewClassIdx]?.name || '';
  const simple = className.split('.').pop() || 'class';
  const pkg = codeViewPackage || getPackageFromClassName(className) || '(default)';
  const pkgCount = classIndicesForSourceExport('package').length;
  const dexCount = classIndicesForSourceExport('dex').length;
  const items = [
    {
      label: `This class (.java) — ${simple}`,
      onChoose: () => exportDecompiledSource('class'),
    },
    {
      label: `This package (.zip) — ${pkg} (${pkgCount})`,
      onChoose: () => exportDecompiledSource('package'),
    },
    {
      label: `Entire DEX (.zip) — ${dexCount} classes`,
      onChoose: () => exportDecompiledSource('dex'),
    },
  ];
  showRenameContextMenuMultiple(clientX, clientY, items);
}

function jumpStringToHexEditor(str) {
  if (!rawHexEditor) return;
  const text = String(str ?? '');
  if (!text) return;
  // Prefer current hex buffer; if empty, load primary file bytes
  if (!rawHexEditor.getBytes()?.length && currentFileBytes?.length) {
    setHexEditorBytes(currentFileBytes, currentFilename || 'file');
  }
  if (!rawHexEditor.getBytes()?.length && currentDexBytes?.length) {
    setHexEditorBytes(currentDexBytes, currentFilename || 'classes.dex');
  }
  switchToCenterTab('raw-tab');
  const off = rawHexEditor.findString(text);
  if (off < 0) {
    // Try latin1 / truncated search for long strings
    const short = text.length > 64 ? text.slice(0, 64) : text;
    const off2 = short !== text ? rawHexEditor.findString(short) : -1;
    if (off2 < 0) {
      rawHexEditor.search(text, 'string');
    }
  }
}

function formatCount(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return '0';
  return v.toLocaleString();
}

function formatFileSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatFileSizeAlways(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return '0 B';
  if (n === 0) return '0 B';
  return formatFileSize(n) || '0 B';
}

/** Estimate retained file buffers + Chrome JS heap (when available). */
function getUiMemoryInfo() {
  let buffers = 0;
  const add = (u8) => {
    if (u8 && u8.byteLength) buffers += u8.byteLength;
    else if (u8 && u8.length) buffers += u8.length;
  };
  add(currentApkBytes);
  add(currentDexBytes);
  add(currentFileBytes);
  add(apkExtractedFileRawBytes);
  if (apkExtractedFile?.bytes && apkExtractedFile.bytes !== apkExtractedFileRawBytes) {
    add(apkExtractedFile.bytes);
  }
  for (const d of loadedDexFiles || []) add(d?.bytes);
  const seen = new Set();
  for (const cached of Object.values(apkFileCache || {})) {
    const b = cached?.bytes;
    if (!b || b === apkExtractedFile?.bytes || b === apkExtractedFileRawBytes) continue;
    if (seen.has(b)) continue;
    seen.add(b);
    add(b);
  }
  let heapUsed = 0;
  let heapLimit = 0;
  try {
    const mem = typeof performance !== 'undefined' ? performance.memory : null;
    if (mem) {
      heapUsed = mem.usedJSHeapSize || 0;
      heapLimit = mem.jsHeapSizeLimit || 0;
    }
  } catch (_) {}
  return { buffers, heapUsed, heapLimit };
}

function formatStatusMemory() {
  const { buffers, heapUsed, heapLimit } = getUiMemoryInfo();
  if (heapUsed > 0) {
    const tip = [
      `JS heap ${formatFileSizeAlways(heapUsed)}` + (heapLimit ? ` / ${formatFileSizeAlways(heapLimit)}` : ''),
      buffers ? `held file buffers ~${formatFileSizeAlways(buffers)}` : '',
    ].filter(Boolean).join(' · ');
    return {
      text: `Mem ${formatFileSizeAlways(heapUsed)}`,
      detail: buffers ? `bufs ${formatFileSizeAlways(buffers)}` : '',
      title: tip,
    };
  }
  if (buffers > 0) {
    return {
      text: `Bufs ${formatFileSizeAlways(buffers)}`,
      detail: '',
      title: `Approximate retained file buffers: ${formatFileSizeAlways(buffers)}`,
    };
  }
  return null;
}

function countDexClassesMethods(classes) {
  const list = Array.isArray(classes) ? classes : [];
  let methods = 0;
  for (const c of list) methods += Array.isArray(c?.methods) ? c.methods.length : 0;
  return { classes: list.length, methods };
}

function getLoadedFileByteSize() {
  if (currentType === 'apk' && currentApkBytes?.length) return currentApkBytes.length;
  if (loadedDexFiles.length > 1) {
    return loadedDexFiles.reduce((acc, d) => acc + (d.bytes?.length || 0), 0);
  }
  if (currentType === 'dex' && currentDexBytes?.length) return currentDexBytes.length;
  if (currentData?.file_info?.file_size) return currentData.file_info.file_size;
  return 0;
}

function computeContentStats() {
  const stats = {
    dexFiles: 0, classes: 0, methods: 0, strings: 0, files: 0, packages: 0,
    indexing: false, indexCurrent: 0, indexTotal: 0, indexName: '',
  };
  if (!currentType || !currentData) return stats;

  if (currentType === 'dex') {
    if (loadedDexFiles.length > 0) {
      const tot = loadedDexTotals();
      stats.dexFiles = tot.dexFiles;
      stats.classes = tot.classes;
      stats.methods = tot.methods;
      const active = loadedDexFiles[activeDexIndex];
      stats.strings = Array.isArray(active?.data?.strings)
        ? active.data.strings.length
        : (Array.isArray(currentData.strings) ? currentData.strings.length : 0);
      if (loadedDexFiles.length > 1 && active) {
        stats.focusDex = active.name || `dex-${activeDexIndex}`;
        stats.focusClasses = active.classCount || 0;
        stats.focusMethods = active.methodCount || 0;
      }
      return stats;
    }
    const classes = Array.isArray(currentData.classes) ? currentData.classes : [];
    const cm = countDexClassesMethods(classes);
    stats.classes = cm.classes;
    stats.methods = cm.methods;
    stats.strings = Array.isArray(currentData.strings) ? currentData.strings.length : 0;
    stats.dexFiles = 1;
    return stats;
  }

  if (currentType === 'apk') {
    const files = Array.isArray(currentData.files) ? currentData.files : [];
    stats.files = files.length;
    stats.dexFiles = files.filter((f) => (f.name || '').toLowerCase().endsWith('.dex')).length;
    if (apkDexStats.classes || apkDexStats.methods) {
      stats.classes = apkDexStats.classes;
      stats.methods = apkDexStats.methods;
    }
    if (!apkDexStats.ready && stats.dexFiles > 0) {
      stats.indexing = true;
      stats.indexCurrent = apkDexStats.current || apkDexStats.dexFiles || 0;
      stats.indexTotal = apkDexStats.totalDex || stats.dexFiles;
      stats.indexName = apkDexStats.currentName || '';
    }
    if (apkExtractedFile?.kind === 'dex' && Array.isArray(apkExtractedFile.data?.classes)) {
      const cm = countDexClassesMethods(apkExtractedFile.data.classes);
      stats.strings = Array.isArray(apkExtractedFile.data.strings) ? apkExtractedFile.data.strings.length : 0;
      stats.focusDex = apkExtractedFile.name || 'DEX';
      stats.focusClasses = cm.classes;
      stats.focusMethods = cm.methods;
    }
    return stats;
  }

  if (currentType === 'axml') {
    stats.files = 1;
    return stats;
  }

  if (currentType === 'arsc') {
    const pkgs = Array.isArray(currentData.packages) ? currentData.packages : [];
    stats.packages = pkgs.length;
    stats.files = 1;
    return stats;
  }

  return stats;
}

function collectStatusBarActivities() {
  const items = [];
  for (const [, task] of uiActivityTasks) {
    if (!task?.text) continue;
    items.push({
      text: task.text,
      detail: task.detail || '',
    });
  }
  try {
    if (typeof securityScanBusy !== 'undefined' && securityScanBusy && securityScanProgressText) {
      items.push({ text: securityScanProgressText, detail: '' });
    }
  } catch (_) {}
  return items;
}

function updateStatusBar() {
  if (!statusbarInner) return;
  const parts = [];
  const activities = collectStatusBarActivities();
  const busy = activities.length > 0;

  if (!currentType || !currentData) {
    const bits = [];
    if (busy) {
      for (const a of activities) {
        const label = a.detail ? `${a.text} — ${a.detail}` : a.text;
        bits.push(`<span class="statusbar-item statusbar-scanning"><strong>${escapeHtml(label)}</strong></span>`);
      }
    } else {
      bits.push('<span class="statusbar-item statusbar-muted">No file loaded</span>');
    }
    const mem = formatStatusMemory();
    if (mem) {
      bits.push(
        `<span class="statusbar-item statusbar-mem" title="${escapeAttr(mem.title)}"><strong>${escapeHtml(mem.text)}</strong>`
        + (mem.detail ? ` <span class="statusbar-muted">${escapeHtml(mem.detail)}</span>` : '')
        + `</span>`
      );
    }
    statusbarInner.innerHTML = bits.join('<span class="statusbar-sep">|</span>')
      + `<span class="statusbar-brand">droid2web ${APP_VERSION_LABEL} · WASM</span>`;
    statusbarInner.classList.toggle('is-busy', busy);
    return;
  }

  const name = loadedDexFiles.length > 1
    ? `${loadedDexFiles.length} DEX files`
    : (currentFilename || 'file');
  const typeLabel = loadedDexFiles.length > 1 ? 'DEXLIST' : String(currentType).toUpperCase();
  const size = formatFileSize(getLoadedFileByteSize());
  const nameTitle = loadedDexFiles.length > 1
    ? loadedDexFiles.map((d) => d.name).join(', ')
    : (currentFilename || '');
  parts.push(`<span class="statusbar-item" title="${escapeAttr(nameTitle)}"><strong>${escapeHtml(truncate(name, 48))}</strong> · ${escapeHtml(typeLabel)}${size ? ` · ${escapeHtml(size)}` : ''}</span>`);

  const content = computeContentStats();
  const contentBits = [];
  if (currentType === 'apk') {
    if (content.files) contentBits.push(`${formatCount(content.files)} files`);
    if (content.dexFiles) contentBits.push(`${formatCount(content.dexFiles)} DEX`);
    if (content.indexing) {
      const prog = content.indexTotal
        ? `${formatCount(content.indexCurrent)}/${formatCount(content.indexTotal)}`
        : '…';
      const dexBit = content.indexName ? ` ${shortDexLabel(content.indexName)}` : '';
      contentBits.push(`indexing ${prog}${dexBit}`);
      if (content.classes) contentBits.push(`${formatCount(content.classes)} classes so far`);
    } else if (content.classes || content.methods) {
      contentBits.push(`${formatCount(content.classes)} classes`);
      contentBits.push(`${formatCount(content.methods)} methods`);
    }
    if (content.focusDex) {
      contentBits.push(`${escapeHtml(truncate(shortDexLabel(content.focusDex), 24))}: ${formatCount(content.focusClasses)} cls / ${formatCount(content.focusMethods)} mtd`);
    }
  } else if (currentType === 'dex') {
    if (content.dexFiles > 1) contentBits.push(`${formatCount(content.dexFiles)} DEX`);
    contentBits.push(`${formatCount(content.classes)} classes`);
    contentBits.push(`${formatCount(content.methods)} methods`);
    if (content.strings) contentBits.push(`${formatCount(content.strings)} strings`);
    if (content.focusDex) {
      contentBits.push(`${escapeHtml(truncate(content.focusDex, 24))}: ${formatCount(content.focusClasses)} cls / ${formatCount(content.focusMethods)} mtd`);
    }
  } else if (currentType === 'arsc') {
    contentBits.push(`${formatCount(content.packages)} packages`);
  } else if (currentType === 'axml') {
    contentBits.push('AXML manifest');
  }
  if (contentBits.length) {
    parts.push(`<span class="statusbar-item statusbar-accent">${contentBits.join(' · ')}</span>`);
  }

  const vulnN = securityVulnFindings.length;
  const sgN = securitySemgrepFindings.length;
  const mtIssues = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0;
  const mtStats = securityMtReport?.stats;
  const hasSecurity = vulnN > 0 || sgN > 0 || securityMtReport || securityScanBusy;
  if (hasSecurity) {
    const secBits = [];
    if (vulnN) secBits.push(`${formatCount(vulnN)} vuln${vulnN === 1 ? '' : 's'}`);
    if (sgN) secBits.push(`${formatCount(sgN)} Semgrep`);
    if (securityMtReport) {
      secBits.push(`${formatCount(mtIssues)} MT`);
      if (mtStats?.methods_analyzed) {
        secBits.push(`${formatCount(mtStats.methods_analyzed)} analyzed`);
      }
      if (mtStats?.call_edges) secBits.push(`${formatCount(mtStats.call_edges)} edges`);
      if (mtStats?.iterations) secBits.push(`${formatCount(mtStats.iterations)} iters`);
    }
    const cls = securityFromCache ? 'statusbar-green' : 'statusbar-warn';
    parts.push(`<span class="statusbar-item ${cls}">${secBits.join(' · ')}</span>`);
  }

  for (const a of activities) {
    const label = a.detail ? `${a.text} — ${a.detail}` : a.text;
    const tip = `${label}\n\nHeavy work runs in this browser tab (WASM). The UI may pause briefly — that is expected, not a crash.`;
    parts.push(`<span class="statusbar-item statusbar-scanning" title="${escapeAttr(tip)}"><strong>${escapeHtml(truncate(label, 72))}</strong></span>`);
  }

  if (busy) {
    parts.push(
      `<span class="statusbar-item statusbar-hint" title="Parsing / indexing / decompiling run locally in WASM. Large APKs can stall clicks for a moment — watch this status bar for progress.">`
      + `<strong>Working</strong> · UI may pause briefly`
      + `</span>`
    );
  } else {
    const readyTip = isLargeApkWorkload()
      ? `Indexed ${formatCount(apkDexStats.classes || 0)} classes. Pick a package (or search) — listing every class at once is capped to keep the UI responsive.`
      : 'Idle — ready for the next action.';
    parts.push(`<span class="statusbar-item statusbar-ready" title="${escapeAttr(readyTip)}"><strong>Ready</strong></span>`);
  }

  const mem = formatStatusMemory();
  if (mem) {
    parts.push(
      `<span class="statusbar-item statusbar-mem" title="${escapeAttr(mem.title)}"><strong>${escapeHtml(mem.text)}</strong>`
      + (mem.detail ? ` <span class="statusbar-muted">${escapeHtml(mem.detail)}</span>` : '')
      + `</span>`
    );
  }

  const html = parts.map((p, i) => (i === 0 ? p : `<span class="statusbar-sep">|</span>${p}`)).join('');
  statusbarInner.innerHTML = html + `<span class="statusbar-brand">droid2web ${APP_VERSION_LABEL} · WASM</span>`;
  statusbarInner.classList.toggle('is-busy', busy);
  let scanBusy = false;
  try { scanBusy = !!securityScanBusy; } catch (_) {}
  ensureStatusBarMemoryTicker(busy || scanBusy || uiActivityTasks.size > 0);
}

let statusBarMemoryTicker = 0;
function ensureStatusBarMemoryTicker(want) {
  const scanBusy = (() => { try { return !!securityScanBusy; } catch (_) { return false; } })();
  if (want) {
    if (statusBarMemoryTicker) return;
    statusBarMemoryTicker = setInterval(() => {
      if (!statusbarInner) return;
      const busyScan = (() => { try { return !!securityScanBusy; } catch (_) { return false; } })();
      if (uiActivityTasks.size || busyScan || (typeof performance !== 'undefined' && performance.memory)) {
        updateStatusBar();
      }
      if (!uiActivityTasks.size && !busyScan) {
        clearInterval(statusBarMemoryTicker);
        statusBarMemoryTicker = 0;
      }
    }, 2000);
  } else if (statusBarMemoryTicker && !uiActivityTasks.size && !scanBusy) {
    clearInterval(statusBarMemoryTicker);
    statusBarMemoryTicker = 0;
  }
}

function render() {
  debug('[render] start type=', currentType);
  try {
    updatePermissionsTabVisibility();
    if (currentType === 'dex') {
      debug('[render] renderDex...');
      renderDex();
      debug('[render] renderDex done');
    } else if (currentType === 'apk') {
      debug('[render] renderApk...');
      renderApk();
      debug('[render] renderApk done');
    } else if (currentType === 'axml') {
      renderAxml();
    } else if (currentType === 'arsc') {
      renderArsc();
    } else {
      warn('render: unknown type', currentType);
    }
  } catch (e) {
    error('[render] threw', e);
    throw e;
  } finally {
    syncCfgPaneAvailability();
    updateStatusBar();
  }
}

/** Build Info panel HTML for DEX: file_info from dex-parser + class/string counts. */
function buildDexInfoHtml(classCount, stringCount) {
  const fi = currentData?.file_info;
  const rows = [];
  if (fi) {
    rows.push(`<div class="info-section">DEX header</div>`);
    rows.push(`<div class="info-row"><span class="info-label">Version:</span><span>${escapeHtml(fi.version || '-')}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">File size:</span><span>${fi.file_size ?? '-'} bytes</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Header size:</span><span>${fi.header_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Endian:</span><span>0x${(fi.endian_tag ?? 0).toString(16)}</span></div>`);
    rows.push(`<div class="info-section">Index sizes</div>`);
    rows.push(`<div class="info-row"><span class="info-label">Strings:</span><span>${fi.string_ids_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Types:</span><span>${fi.type_ids_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Protos:</span><span>${fi.proto_ids_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Fields:</span><span>${fi.field_ids_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Methods:</span><span>${fi.method_ids_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Class defs:</span><span>${fi.class_defs_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-section">Offsets</div>`);
    rows.push(`<div class="info-row"><span class="info-label">Map off:</span><span>0x${(fi.map_off ?? 0).toString(16)}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Data size:</span><span>${fi.data_size ?? '-'}</span></div>`);
    rows.push(`<div class="info-row"><span class="info-label">Data off:</span><span>0x${(fi.data_off ?? 0).toString(16)}</span></div>`);
    if ((fi.link_size ?? 0) > 0) {
      rows.push(`<div class="info-row"><span class="info-label">Link size/off:</span><span>${fi.link_size} / 0x${(fi.link_off ?? 0).toString(16)}</span></div>`);
    }
  }
  rows.push(`<div class="info-section">Contents</div>`);
  rows.push(`<div class="info-row"><span class="info-label">Classes:</span><span>${classCount}</span></div>`);
  rows.push(`<div class="info-row"><span class="info-label">Strings:</span><span>${stringCount}</span></div>`);
  return rows.join('');
}

/** Build search index for current DEX (one lowercased string per class, per method, and per string). */
function buildDexSearchIndex(classes, strings) {
  const classSearchable = [];
  const methodSearchable = [];
  for (let i = 0; i < classes.length; i++) {
    const c = classes[i];
    const methods = Array.isArray(c.methods) ? c.methods : [];
    const className = (c.name || '').toLowerCase();
    const methodStrings = [];
    let classAcc = className + ' ';
    for (let j = 0; j < methods.length; j++) {
      const m = methods[j];
      const part = [
        m.name || '',
        m.descriptor || '',
        m.decompilation || '',
        ...(Array.isArray(m.bytecode) ? m.bytecode.map(r => (r.mnemonic || '') + ' ' + (r.operands || '')) : []),
      ].join(' ').toLowerCase();
      methodStrings.push(part);
      classAcc += part + ' ';
    }
    classSearchable.push(classAcc);
    methodSearchable.push(methodStrings);
  }
  const stringsLower = (strings || []).map(s => (s || '').toLowerCase());
  return { classSearchable, methodSearchable, stringsLower };
}

/** Parse left-panel search: `tag:foo` / `#foo` filters by annotation tag; `method:` / `m:` matches method names only; `bookmark:` / `bm:` / `★` shows bookmarks. */
function parseListSearchQuery(raw) {
  const q = String(raw || '').trim();
  if (!q) return { tag: '', text: '', methodOnly: false, bookmarks: false };
  if (/^(?:★|☆|bookmark:|bm:|star:|bookmarks?:)\s*$/i.test(q) || /^(?:bookmark|bm|star)s?$/i.test(q)) {
    return { tag: '', text: '', methodOnly: false, bookmarks: true };
  }
  const bmM = q.match(/^(?:★|☆|bookmark:|bm:|star:)\s*(.+)$/i);
  if (bmM) return { tag: '', text: bmM[1].trim().toLowerCase(), methodOnly: false, bookmarks: true };
  const tagM = q.match(/^(?:#|tag:)\s*(.+)$/i);
  if (tagM) return { tag: tagM[1].trim().toLowerCase(), text: '', methodOnly: false, bookmarks: false };
  const methodM = q.match(/^(?:m:|method:)\s*(.+)$/i);
  if (methodM) return { tag: '', text: methodM[1].trim().toLowerCase(), methodOnly: true, bookmarks: false };
  return { tag: '', text: q.toLowerCase(), methodOnly: false, bookmarks: false };
}

function annotationHasTag(kind, key, tagLower) {
  const tags = getAnnotation(kind, key)?.tags;
  if (!tags?.length) return false;
  return tags.some((t) => String(t).toLowerCase() === tagLower);
}

/** Methods (and all methods of tagged classes) matching an annotation tag. */
function getMethodsMatchingTag(classes, tagLower) {
  const pairs = [];
  if (!tagLower) return pairs;
  for (let i = 0; i < classes.length; i++) {
    const className = classes[i]?.name || '';
    const classHas = annotationHasTag('class', className, tagLower);
    const methods = classes[i]?.methods || [];
    for (let j = 0; j < methods.length; j++) {
      const key = methodAnnotationKey(className, methods[j]?.name || '');
      if (classHas || annotationHasTag('method', key, tagLower)) {
        pairs.push({ classIdx: i, methodIdx: j });
      }
    }
  }
  return pairs;
}

/** Bookmarked classes (all methods) + bookmarked methods; optional name substring filter. */
function getBookmarkedSearchMatches(classes, textFilter = '') {
  const pairs = [];
  const seen = new Set();
  const text = String(textFilter || '').toLowerCase();
  const add = (ci, mi) => {
    const id = `${ci}:${mi}`;
    if (seen.has(id)) return;
    seen.add(id);
    pairs.push({ classIdx: ci, methodIdx: mi });
  };
  const classIndex = new Map();
  for (let i = 0; i < classes.length; i++) {
    if (classes[i]?.name) classIndex.set(classes[i].name, i);
  }
  for (const b of dexBookmarks.items) {
    if (b.kind === 'class') {
      const className = b.className || b.key;
      const ci = classIndex.get(className);
      if (ci == null) continue;
      if (text) {
        const hay = `${className} ${b.label || ''}`.toLowerCase();
        if (!hay.includes(text)) continue;
      }
      const methods = classes[ci].methods || [];
      if (!methods.length) add(ci, -1);
      else for (let j = 0; j < methods.length; j++) add(ci, j);
    } else if (b.kind === 'method') {
      const className = b.className || String(b.key).split('#')[0] || '';
      const methodName = b.methodName || String(b.key).split('#')[1] || '';
      const ci = classIndex.get(className);
      if (ci == null) continue;
      if (text) {
        const hay = `${className} ${methodName} ${b.label || ''}`.toLowerCase();
        if (!hay.includes(text)) continue;
      }
      const methods = classes[ci].methods || [];
      let found = false;
      for (let j = 0; j < methods.length; j++) {
        if ((methods[j]?.name || '') === methodName) {
          add(ci, j);
          found = true;
          break;
        }
      }
      if (!found) add(ci, -1);
    }
  }
  return pairs;
}

/** Get matching (classIdx, methodIdx) pairs; supports tag:# / tag:name, bookmark:, and method:/m: queries. */
function getDexSearchMatches(classes, query) {
  const { tag, text, methodOnly, bookmarks } = parseListSearchQuery(query);
  if (bookmarks) return getBookmarkedSearchMatches(classes, text);
  if (tag) return getMethodsMatchingTag(classes, tag);
  if (!text || !dexSearchIndex) return null;
  const { classSearchable, methodSearchable } = dexSearchIndex;
  if (classSearchable.length !== classes.length) return null;
  const pairs = [];
  for (let i = 0; i < classes.length; i++) {
    if (!methodOnly && !classSearchable[i].includes(text)) continue;
    const methods = classes[i]?.methods || [];
    for (let j = 0; j < methodSearchable[i].length; j++) {
      if (methodOnly) {
        const m = methods[j];
        const nameHay = `${m?.name || ''} ${m?.descriptor || ''}`.toLowerCase();
        if (nameHay.includes(text)) pairs.push({ classIdx: i, methodIdx: j });
      } else if (methodSearchable[i][j].includes(text)) {
        pairs.push({ classIdx: i, methodIdx: j });
      }
    }
  }
  return pairs;
}

function renderDex() {
  const classes = Array.isArray(currentData?.classes) ? currentData.classes : [];
  const totalMethods = classes.reduce((n, c) => n + (Array.isArray(c?.methods) ? c.methods.length : 0), 0);
  debug('renderDex', 'classes=', classes.length, 'methods total=', totalMethods, 'search=', searchQuery || '(none)');
  leftPanelTitle.textContent = loadedDexFiles.length > 1
    ? `Classes (${activeDexIndex + 1}/${loadedDexFiles.length})`
    : 'Classes';
  updateApkLeftModeButtons();
  updateDexFileSelector();
  treePlaceholder.style.display = 'none';
  treeContent.style.display = 'block';
  if (listSearchWrap) listSearchWrap.style.display = 'flex';
  if (dexPackageWrap) dexPackageWrap.style.display = 'block';

  if (classes.length === 0) {
    if (dexPackageWrap) dexPackageWrap.style.display = 'none';
    treeContent.innerHTML = '<div class="muted">No classes in this DEX.</div>';
    const sc = currentData?.strings_omitted
      ? (currentData.string_count || 0)
      : ((currentData?.strings?.length) ?? 0);
    infoContent.innerHTML = buildDexInfoHtml(0, sc);
    setStringsAndRender(currentData?.strings ?? []);
    scheduleEnsureDexStringsLoaded();
    setManifestPlaceholder('<span class="muted">DEX has no manifest.</span>');

    return;
  }


  // Build search index only when needed for text search (tag:# / tag:name skips the index).
  const strings = Array.isArray(currentData?.strings) ? currentData.strings : [];
  const stringCount = currentData?.strings_omitted
    ? (Number(currentData.string_count) || strings.length)
    : strings.length;
  const parsedSearch = parseListSearchQuery(searchQuery);
  const needIndex = parsedSearch.text && (!dexSearchIndex || dexSearchIndex.classSearchable.length !== classes.length || dexSearchIndex.stringsLower.length !== strings.length);
  if (needIndex) {
    const t0 = typeof performance !== 'undefined' ? performance.now() : 0;
    dexSearchIndex = buildDexSearchIndex(classes, strings);
    if (t0) debug('dex search index built', classes.length, 'classes', strings.length, 'strings in', (performance.now() - t0).toFixed(0), 'ms');
  }

  const packageMap = buildDexPackageMap(classes);
  renderClassTreeFromPackageMap(classes, packageMap, { isApk: false });

  const firstPkg = selectedDexPackage && packageMap[selectedDexPackage]?.[0]
    ? packageMap[selectedDexPackage][0]
    : (searchQuery ? Object.values(packageMap).flat()[0] : null);
  if (firstPkg) codeViewClassIdx = firstPkg.classIdx;
  else codeViewClassIdx = 0;
  codeViewMethodIdx = null;
  updateCodeView();

  // Info (reuse strings from earlier in renderDex): header + counts
  infoContent.innerHTML = buildDexInfoHtml(classes.length, stringCount);

  // Strings — pool may be omitted until Strings tab / lazy load
  setStringsAndRender(strings);
  scheduleEnsureDexStringsLoaded();

  // Raw hex editor for the DEX
  setHexEditorBytes(currentDexBytes, currentFilename || 'classes.dex');

  // Manifest tab: N/A for DEX
  setManifestPlaceholder('<span class="muted">DEX has no manifest. Load an APK for manifest.</span>');
}

function selectDexMethod(classIdx, methodIdx) {
  codeViewClassIdx = classIdx;
  codeViewMethodIdx = methodIdx;
  const method = currentData.classes[classIdx]?.methods?.[methodIdx];
  const needFetch = !method || !Array.isArray(method.bytecode) || method.bytecode.length === 0;
  if (needFetch && currentDexBytes && currentDexBytes.length > 0) {
    debug('selectDexMethod', 'fetching classIdx=', classIdx, 'methodIdx=', methodIdx, 'bytes=', currentDexBytes.length);
    bytecodeListing.innerHTML = '<div class="muted">Loading…</div>';
    setSourceContent(sourceCode, '');
    clearCfgGraph();
    if (cfgMeta) cfgMeta.textContent = 'Loading…';
    if (bytecodeColHeader) bytecodeColHeader.setAttribute('aria-hidden', 'true');
    if (bytecodeMeta) bytecodeMeta.textContent = '';
    const bytes = currentDexBytes;
    const wantClass = classIdx;
    const wantMethod = methodIdx;
    setTimeout(async () => {
      try {
        await ensureApkResourceMap();
        if (codeViewClassIdx !== wantClass || codeViewMethodIdx !== wantMethod) return;
        setUiActivity('decomp', 'Decompiling method', `${wantClass}:${wantMethod}`);
        const raw = await getDexMethodInWorker(bytes, wantClass, wantMethod);
        const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
        if (result && result.ok && result.data) {
          const data = typeof normalizeWasmResult === 'function'
            ? (normalizeWasmResult(result.data) || result.data)
            : result.data;
          currentData.classes[wantClass].methods[wantMethod] = data;
          if (codeViewClassIdx === wantClass && codeViewMethodIdx === wantMethod) {
            selectDexMethod(wantClass, wantMethod);
          }
        } else {
          if (codeViewClassIdx === wantClass && codeViewMethodIdx === wantMethod) {
            setBytecodeListingHtml(bytecodeEmptyHtml('Failed to load method', result?.error || 'Unknown error'), { empty: true });
            setSourceContent(sourceCode, result?.error || 'Error');
            clearCfgGraph();
          }
        }
      } catch (e) {
        if (codeViewClassIdx === wantClass && codeViewMethodIdx === wantMethod) {
          setBytecodeListingHtml(bytecodeEmptyHtml('Error loading method', String(e?.message || e)), { empty: true });
          setSourceContent(sourceCode, String(e?.message || e));
          clearCfgGraph();
        }
      } finally {
        clearUiActivity('decomp');
      }
    }, 0);
    return;
  }

  if (!method) {
    setBytecodeListingHtml(bytecodeEmptyHtml('No method data', 'Select another method'), { empty: true });
    setSourceContent(sourceCode, '');
    clearCfgGraph();
    if (methodSelect) methodSelect.value = String(methodIdx);
    return;
  }

  if (currentType === 'dex') currentDexSelection = { classIdx, methodIdx };
  const className = currentData.classes[classIdx]?.name ?? '?';
  const methodsInClass = currentData.classes[classIdx]?.methods?.length ?? 0;
  debug('selectDexMethod', 'classIdx=', classIdx, 'methodIdx=', methodIdx, 'class=', className, 'methodsInClass=', methodsInClass, 'method=', method.name, 'bytecode rows=', method.bytecode?.length);

  lastEmulatorRun = null;
  hideEmulatorResults();

  // Bytecode (offset, hex, mnemonic, operands) — data-offset for emulator step sync
  const rows = method.bytecode || [];
  const displayMethodName = getDisplayMethodName(className, method.name);
  const bytecodeHtml = wrapSingleMethodBytecodeHtml(renderBytecodeLines(rows), {
    classIdx,
    methodIdx,
    displayName: displayMethodName,
  });
  setBytecodeListingHtml(bytecodeHtml, {
    empty: rows.length === 0,
    insnCount: rows.length,
    sourceMeta: displayMethodName || '',
  });

  requestAnimationFrame(() => renderCfgGraph(method));

  // Source (decompiled) with syntax highlighting; apply method rename so decompiled text matches bytecode
  const decompilation = method.decompilation || '(no body)';
  currentSourceMethodMeta = { classIdx, methodIdx, name: displayMethodName };
  setSourceContent(sourceCode, applyMethodRenameToDecompilation(decompilation, method.name, displayMethodName) || decompilation);

  if (methodSelect) methodSelect.value = String(methodIdx);
  ensureCfgPaneExpanded();
  syncBackToClassButton();
  updateAnnotationPanel();
  loadAndShowMethodCallers(classIdx, methodIdx);
}

/** Get current code view context (classes, bytes, class index) for DEX or APK DEX. */
function getCodeViewContext() {
  if (currentType === 'dex' && currentData?.classes?.length && currentDexBytes?.length) {
    return { classes: currentData.classes, bytes: currentDexBytes, classIdx: codeViewClassIdx, isApk: false };
  }
  if (currentType === 'apk' && apkExtractedFile?.kind === 'dex' && apkExtractedFile?.data?.classes?.length && apkExtractedFile?.bytes?.length) {
    return { classes: apkExtractedFile.data.classes, bytes: apkExtractedFile.bytes, classIdx: apkExtractedDexSelection.classIdx, isApk: true };
  }
  return null;
}

/** Expand the CFG dock (if available) so selecting a method shows the graph. */
function ensureCfgPaneExpanded() {
  if (!cfgAppliesToCurrentFile()) return;
  const pane = document.getElementById('cfg-pane');
  if (!pane || pane.hidden) return;
  const wasCollapsed = pane.dataset.collapsed === 'true';
  if (wasCollapsed) {
    setDockCollapsed(pane, false, 'droid2web-cfg-open');
    updateWorkspaceResizers();
  }
  setTimeout(() => {
    try { cfgNetwork?.redraw(); } catch (_) {}
    fitCfgGraph();
  }, wasCollapsed ? 140 : 40);
}

/**
 * Resolve class/method from a click/contextmenu event on source or bytecode blocks,
 * falling back to the currently selected method.
 */
function resolveMethodFromEvent(event) {
  const ctx = getCodeViewContext();
  if (!ctx) return null;
  const { classes } = ctx;
  const block = event?.target?.closest?.(
    '.source-method-block, .bytecode-method-block, .source-method-view, .bytecode-method-view, .method-block-header'
  );
  let classIdx = codeViewClassIdx;
  let methodIdx = codeViewMethodIdx;
  let methodNameAttr = '';
  const host = block?.closest?.('.source-method-block, .bytecode-method-block, .source-method-view, .bytecode-method-view') || block;
  if (host && host.getAttribute) {
    const ci = parseInt(host.getAttribute('data-class-idx'), 10);
    const mi = parseInt(host.getAttribute('data-method-idx'), 10);
    if (!Number.isNaN(ci)) classIdx = ci;
    if (!Number.isNaN(mi)) methodIdx = mi;
    methodNameAttr = host.getAttribute('data-method-name') || '';
  }
  if ((methodIdx == null || Number.isNaN(methodIdx)) && currentSourceMethodMeta?.methodIdx != null) {
    classIdx = currentSourceMethodMeta.classIdx ?? classIdx;
    methodIdx = currentSourceMethodMeta.methodIdx;
    methodNameAttr = methodNameAttr || currentSourceMethodMeta.name || '';
  }
  const className = classes[classIdx]?.name ?? '';
  if (methodIdx == null || Number.isNaN(Number(methodIdx))) {
    return className
      ? { classIdx, methodIdx: null, className, methodName: '', methodKey: '', origName: '' }
      : null;
  }
  const mi = Number(methodIdx);
  const m = classes[classIdx]?.methods?.[mi];
  const origName = getDexMethodRawName(m) || m?.name || '';
  const methodName = methodNameAttr || getDisplayMethodName(className, m?.name || origName) || (m?.name || origName);
  const methodKey = methodRenameKey(className, m) || (className && origName ? `${className}#${origName}` : '');
  return { classIdx, methodIdx: mi, className, methodName, methodKey, origName };
}

/** Select a method in the Code view and optionally open the CFG dock. */
function selectCodeViewMethod(classIdx, methodIdx, opts = {}) {
  const expandCfg = opts.expandCfg !== false;
  const ci = Number(classIdx);
  const mi = methodIdx == null || methodIdx === 'all' ? null : Number(methodIdx);
  if (Number.isNaN(ci)) return;
  codeViewClassIdx = ci;
  codeViewMethodIdx = (mi == null || Number.isNaN(mi)) ? null : mi;
  const ctx = getCodeViewContext();
  const className = ctx?.classes?.[ci]?.name;
  if (className) codeViewPackage = getPackageFromClassName(className);
  if (currentType === 'apk' && apkExtractedFile?.kind === 'dex') {
    apkExtractedDexSelection = { classIdx: ci, methodIdx: codeViewMethodIdx ?? 0 };
  } else if (currentType === 'dex') {
    currentDexSelection = { classIdx: ci, methodIdx: codeViewMethodIdx ?? 0 };
  }
  if (expandCfg && codeViewMethodIdx != null) ensureCfgPaneExpanded();
  if (methodSelect) methodSelect.value = codeViewMethodIdx === null ? 'all' : String(codeViewMethodIdx);
  syncBackToClassButton();
  updateSourceNavBackBtn();
  updateCodeView();
}

/** HTML for sticky method chrome in source / bytecode. */
function renderMethodBlockHeader(name, { openCfg = true, hint = 'Open CFG', backToClass = false } = {}) {
  const actions = [];
  if (backToClass) {
    actions.push(`<button type="button" class="method-back-class" data-back-class title="Back to class (all methods)">← Class</button>`);
  }
  if (openCfg) {
    actions.push(`<button type="button" class="method-open-cfg" data-open-cfg title="Open method and control-flow graph">${escapeHtml(hint)}</button>`);
  }
  return `<div class="method-block-header" role="button" tabindex="0" title="${backToClass ? 'Method view' : 'Click to open this method (CFG + bytecode)'}">
    <span class="method-block-name">${escapeHtml(name || '(method)')}</span>
    <span class="method-block-actions">${actions.join('')}</span>
  </div>`;
}

/** Return to the class “All methods” view from a single method. */
function goBackToClassView() {
  if (codeViewMethodIdx == null) return;
  selectCodeViewMethod(codeViewClassIdx, null, { expandCfg: false });
}

function syncBackToClassButton() {
  const btn = document.getElementById('code-back-to-class');
  if (!btn) return;
  const show = codeViewMethodIdx != null && getCodeViewContext() != null;
  btn.hidden = !show;
  if (show) {
    const ctx = getCodeViewContext();
    const simple = (ctx?.classes?.[codeViewClassIdx]?.name || '').split('.').pop() || 'class';
    btn.title = `Back to ${simple} (all methods)`;
    btn.setAttribute('aria-label', `Back to class ${simple}`);
  }
}

/** Return package name for a class (e.g. "com.example.app" from "com.example.app.MainActivity"). */
function getPackageFromClassName(className) {
  if (!className || typeof className !== 'string') return '(default)';
  const parts = className.split('.');
  return parts.length > 1 ? parts.slice(0, -1).join('.') : '(default)';
}

/** android.* / androidx.* (and android.support.*) — hidden from class lists unless toggled on. */
function isAndroidOrAndroidxClass(className) {
  const n = String(className || '').trim();
  if (!n) return false;
  return n === 'android' || n.startsWith('android.')
    || n === 'androidx' || n.startsWith('androidx.');
}

function shouldShowClassInUi(className) {
  return showAndroidFrameworkClasses || !isAndroidOrAndroidxClass(className);
}

/** Return array of class indices that belong to the given package. */
function getClassesInPackage(classes, packageName) {
  if (!Array.isArray(classes) || !packageName) return [];
  const out = [];
  for (let i = 0; i < classes.length; i++) {
    const name = classes[i]?.name;
    if (!shouldShowClassInUi(name)) continue;
    if (getPackageFromClassName(name) === packageName) out.push(i);
  }
  return out;
}

/** Compact count for tree/dropdown badges (number only). */
function formatCountLabel(n) {
  return String(Number(n) || 0);
}

/** Map package name → class count for a DEX class list (respects android/androidx filter). */
function countClassesByPackage(classes) {
  const counts = Object.create(null);
  if (!Array.isArray(classes)) return counts;
  for (let i = 0; i < classes.length; i++) {
    const name = classes[i]?.name;
    if (!shouldShowClassInUi(name)) continue;
    const pkg = getPackageFromClassName(name);
    counts[pkg] = (counts[pkg] || 0) + 1;
  }
  return counts;
}

/** Load all methods of a class and set combined bytecode + source in the code view. */
let loadAllMethodsGeneration = 0;

function renderAllMethodsDeferredHtml(classIdx, methodCount) {
  const fieldsBanner = renderClassFieldsBannerHtml(classIdx) || '';
  const body = bytecodeEmptyHtml(
    `${methodCount} methods`,
    `This class is large — pick a method in the dropdown, or load all (slow on big DEXes).`
  );
  const actions = `<div class="all-methods-deferred-actions">
    <button type="button" class="btn btn-primary" id="load-all-methods-btn" data-class-idx="${classIdx}">Load all methods</button>
  </div>`;
  return (fieldsBanner || '') + body + actions;
}

function wireLoadAllMethodsButton() {
  const btn = document.getElementById('load-all-methods-btn');
  if (!btn || btn._wired) return;
  btn._wired = true;
  btn.addEventListener('click', () => {
    const classIdx = parseInt(btn.getAttribute('data-class-idx'), 10);
    if (Number.isNaN(classIdx)) return;
    const ctx = getCodeViewContext();
    if (!ctx?.bytes || !ctx.classes?.[classIdx]) return;
    const classesRef = ctx.isApk ? apkExtractedFile.data.classes : currentData.classes;
    const methods = Array.isArray(classesRef[classIdx]?.methods) ? classesRef[classIdx].methods : [];
    codeViewClassIdx = classIdx;
    codeViewMethodIdx = null;
    loadAllMethodsForClass(ctx.bytes, classIdx, methods, classesRef, { force: true });
  });
}

async function loadAllMethodsForClass(bytes, classIdx, methods, classesRef, { force = false } = {}) {
  const gen = ++loadAllMethodsGeneration;
  const stillCurrent = () =>
    gen === loadAllMethodsGeneration
    && codeViewMethodIdx === null
    && codeViewClassIdx === classIdx;

  if (methods.length === 0) {
    const fieldsBanner = renderClassFieldsBannerHtml(classIdx) || '';
    setBytecodeListingHtml(
      fieldsBanner || bytecodeEmptyHtml('No methods', 'This class has no methods'),
      { empty: !fieldsBanner, sourceMeta: '' }
    );
    setSourceContentAllMethods(sourceCode, classIdx, []);
    return;
  }

  // Huge classes (common in Facebook / apps with R / BuildConfig noise): don't decompile everything up front.
  if (!force && methods.length > ALL_METHODS_AUTO_LIMIT) {
    setBytecodeListingHtml(renderAllMethodsDeferredHtml(classIdx, methods.length), {
      empty: false,
      meta: `${methods.length} methods · select one or Load all`,
      sourceMeta: `${methods.length} methods`,
    });
    setSourceContentAllMethods(sourceCode, classIdx, []);
    clearCfgGraph();
    requestAnimationFrame(() => wireLoadAllMethodsButton());
    return;
  }

  await ensureApkResourceMap();
  if (!stillCurrent()) return;

  const bytecodeParts = [];
  const methodsWithSource = [];
  let totalInsn = 0;
  const fieldsBanner = renderClassFieldsBannerHtml(classIdx) || '';

  for (let methodIdx = 0; methodIdx < methods.length; methodIdx++) {
    if (!stillCurrent()) return;
    const m = methods[methodIdx];
    const needFetch = !Array.isArray(m.bytecode) || m.bytecode.length === 0;
    if (needFetch) {
      try {
        setUiActivity('decomp', 'Decompiling class', `${methodIdx + 1}/${methods.length}`);
        setBytecodeListingHtml(
          (fieldsBanner || '') +
            bytecodeEmptyHtml('Loading methods…', `${methodIdx + 1} / ${methods.length}`),
          { empty: true, meta: `Loading ${methodIdx + 1}/${methods.length}`, sourceMeta: '' }
        );
        await yieldToUiFrame();
        if (!stillCurrent()) return;
        const raw = await getDexMethodInWorker(bytes, classIdx, methodIdx);
        if (!stillCurrent()) return;
        const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
        if (result?.ok && result?.data) {
          const data = typeof normalizeWasmResult === 'function'
            ? (normalizeWasmResult(result.data) || result.data)
            : result.data;
          classesRef[classIdx].methods[methodIdx] = data;
        }
      } catch (e) {
        warn('[loadAllMethodsForClass]', classIdx, methodIdx, e);
      }
    }
    const method = classesRef[classIdx].methods[methodIdx];
    const rows = Array.isArray(method?.bytecode) ? method.bytecode : [];
    totalInsn += rows.length;
    const origName = method?.name || ('method ' + methodIdx);
    const className = classesRef[classIdx]?.name ?? '';
    const displayName = getDisplayMethodName(className, origName);
    const decompilation = applyMethodRenameToDecompilation(method?.decompilation ?? '', origName, displayName) || (method?.decompilation ?? '');
    methodsWithSource.push({ name: displayName, decompilation });
    bytecodeParts.push(`<div class="bytecode-method-block" data-class-idx="${classIdx}" data-method-idx="${methodIdx}" data-method-name="${escapeAttr(displayName)}">`);
    bytecodeParts.push(renderMethodBlockHeader(displayName, { openCfg: true, hint: 'CFG' }));
    bytecodeParts.push(rows.length ? renderBytecodeLines(rows) : '<div class="muted bytecode-empty-method">(no code)</div>');
    bytecodeParts.push('</div>');
  }

  if (!stillCurrent()) return;
  clearUiActivity('decomp');
  setBytecodeListingHtml(
    (fieldsBanner || '') +
      (bytecodeParts.join('') || bytecodeEmptyHtml('No bytecode', 'No instructions in this class')),
    {
      empty: totalInsn === 0 && !(classesRef[classIdx]?.fields?.length),
      meta: `${methods.length} methods · ${totalInsn} insn · click header for CFG`,
      sourceMeta: `${methods.length} methods · click header / Open CFG`,
    }
  );
  setSourceContentAllMethods(sourceCode, classIdx, methodsWithSource);
  clearCfgGraph();
}

/** Update code view: Package → Class → Method; Class dropdown shows only classes from selected package. */
function updateCodeView() {
  const ctx = getCodeViewContext();
  if (!ctx || !methodSelect || !bytecodeListing) return;
  const { classes, bytes, isApk } = ctx;
  const apkClassSelect = document.getElementById('apk-dex-class-toolbar');

  // Build unique packages and show Package + Class dropdowns for DEX (standalone and APK)
  const packages = [];
  const seen = new Set();
  const pkgClassCounts = countClassesByPackage(classes);
  for (let i = 0; i < classes.length; i++) {
    const name = classes[i]?.name;
    if (!shouldShowClassInUi(name)) continue;
    const pkg = getPackageFromClassName(name);
    if (!seen.has(pkg)) { seen.add(pkg); packages.push(pkg); }
  }
  packages.sort();
  // If current selection is a hidden android/androidx class, drop package so user picks again.
  if (codeViewPackage && !packages.includes(codeViewPackage)) {
    codeViewPackage = '';
  }
  if (classes[codeViewClassIdx] && !shouldShowClassInUi(classes[codeViewClassIdx]?.name)) {
    codeViewClassIdx = packages.length ? (getClassesInPackage(classes, packages[0])[0] ?? 0) : 0;
    codeViewMethodIdx = null;
  }
  const showPackageClassToolbar = classes.length > 0;
  if (codePackageWrap) codePackageWrap.style.display = showPackageClassToolbar ? '' : 'none';
  if (classSelectorWrap) classSelectorWrap.style.display = showPackageClassToolbar ? '' : 'none';
  updateCodeNavSeps();

  if (showPackageClassToolbar && codePackageSelect) {
    codePackageSelect.innerHTML = '<option value="">Select package…</option>' +
      packages.map((p) => {
        const n = pkgClassCounts[p] || 0;
        return `<option value="${escapeAttr(p)}"${p === codeViewPackage ? ' selected' : ''}>${escapeHtml(p)} (${formatCountLabel(n, 'class', 'classes')})</option>`;
      }).join('');
    codePackageSelect.value = codeViewPackage || '';
  }

  if (showPackageClassToolbar && apkClassSelect) {
    // Deep-links (Security / Info / tree) set classIdx but may leave package stale.
    // Prefer following the selected class over clobbering it with the first class in the old package.
    if (
      classes[codeViewClassIdx]?.name &&
      shouldShowClassInUi(classes[codeViewClassIdx].name)
    ) {
      const pkgOfClass = getPackageFromClassName(classes[codeViewClassIdx].name);
      if (pkgOfClass && pkgOfClass !== codeViewPackage) {
        codeViewPackage = pkgOfClass;
        if (codePackageSelect) codePackageSelect.value = codeViewPackage;
      }
    }
    if (!codeViewPackage) {
      // Sync package from current class when coming from tree click; otherwise require user to select package
      if (classes[codeViewClassIdx]?.name) {
        codeViewPackage = getPackageFromClassName(classes[codeViewClassIdx].name);
        if (codePackageSelect) codePackageSelect.value = codeViewPackage;
      }
      if (!codeViewPackage) {
        apkClassSelect.innerHTML = '<option value="">Select package first</option>';
        apkClassSelect.value = '';
        setBytecodeListingHtml(bytecodeEmptyHtml('Select a package', 'Choose a package above to browse classes'), { empty: true, sourceMeta: '' });
        setSourceContent(sourceCode, '');
        clearCfgGraph();
        methodSelect.innerHTML = '<option value="all">All methods</option>';
        updateAnnotationPanel();
        return;
      }
    }
    const inPackage = getClassesInPackage(classes, codeViewPackage);
    if (inPackage.length === 0) {
      apkClassSelect.innerHTML = '<option value="">No classes in this package</option>';
      apkClassSelect.value = '';
      setBytecodeListingHtml(bytecodeEmptyHtml('Empty package', `No classes in “${codeViewPackage}”`), { empty: true, sourceMeta: '' });
      setSourceContent(sourceCode, '');
      clearCfgGraph();
      methodSelect.innerHTML = '<option value="all">All methods</option>';
      updateAnnotationPanel();
      return;
    }
    apkClassSelect.innerHTML = inPackage.map((cIdx) => {
      const cl = classes[cIdx];
      const fullName = getDisplayClassName(cl?.name || '');
      const label = fullName.split('.').pop() || '?';
      const methodCount = Array.isArray(cl?.methods) ? cl.methods.length : 0;
      return `<option value="${cIdx}">${escapeHtml(label)} (${formatCountLabel(methodCount, 'method')})</option>`;
    }).join('');
    let classIdx = codeViewClassIdx;
    if (!inPackage.includes(classIdx) && inPackage.length > 0) {
      classIdx = inPackage[0];
      codeViewClassIdx = classIdx;
      codeViewMethodIdx = null;
      if (isApk) apkExtractedDexSelection = { classIdx, methodIdx: 0 };
    }
    apkClassSelect.value = String(classIdx);
    codeViewClassIdx = classIdx;
    if (isApk) apkExtractedDexSelection.classIdx = classIdx;
    filterClassDropdown();
  }

  const classIdx = codeViewClassIdx;
  const methods = Array.isArray(classes[classIdx]?.methods) ? classes[classIdx].methods : [];
  debug('updateCodeView', 'classes=', classes.length, 'classIdx=', classIdx, 'methods in class=', methods.length, 'codeViewMethodIdx=', codeViewMethodIdx, 'isApk=', isApk);

  const classDisplayName = classes[classIdx]?.name ?? '';
  refillMethodSelectOptions(methods, classDisplayName);
  methodSelect.value = codeViewMethodIdx === null ? 'all' : String(codeViewMethodIdx);
  if (![...methodSelect.options].some((o) => o.value === methodSelect.value && !o.hidden)) {
    // Keep selection even if filtered out; filterMethodDropdown already ran inside refill.
    methodSelect.value = codeViewMethodIdx === null ? 'all' : String(codeViewMethodIdx);
  }
  syncBackToClassButton();

  if (codeViewMethodIdx === null) {
    setBytecodeListingHtml(bytecodeEmptyHtml('Loading…', 'Fetching all methods for this class'), { empty: true });
    currentSourceMethodMeta = null;
    setSourceContent(sourceCode, '');
    clearCfgGraph();
    if (bytecodeMeta) bytecodeMeta.textContent = 'Loading…';
    const classesRef = isApk ? apkExtractedFile.data.classes : currentData.classes;
    const loadingClassIdx = classIdx;
    setTimeout(() => {
      if (codeViewMethodIdx !== null || codeViewClassIdx !== loadingClassIdx) return;
      loadAllMethodsForClass(bytes, classIdx, methods, classesRef);
    }, 0);
  } else {
    if (isApk) {
      apkExtractedDexSelection.methodIdx = codeViewMethodIdx;
      let method = classes[classIdx].methods[codeViewMethodIdx];
      const needFetch = !method || !Array.isArray(method.bytecode) || method.bytecode.length === 0;
      if (needFetch && apkExtractedFile?.bytes) {
        const bytes = apkExtractedFile.bytes;
        const wantClass = classIdx;
        const wantMethod = codeViewMethodIdx;
        setBytecodeListingHtml(bytecodeEmptyHtml('Loading…', 'Resolving resources + method'), {
          empty: true,
          sourceMeta: '',
        });
        setTimeout(async () => {
          try {
            await ensureApkResourceMap();
            if (codeViewClassIdx !== wantClass || codeViewMethodIdx !== wantMethod) return;
            setUiActivity('decomp', 'Decompiling method', `${wantClass}:${wantMethod}`);
            const raw = await getDexMethodInWorker(bytes, wantClass, wantMethod);
            const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
            if (result?.ok && result?.data && apkExtractedFile?.data?.classes?.[wantClass]) {
              const data = typeof normalizeWasmResult === 'function'
                ? (normalizeWasmResult(result.data) || result.data)
                : result.data;
              apkExtractedFile.data.classes[wantClass].methods[wantMethod] = data;
            }
          } catch (_) {}
          finally {
            clearUiActivity('decomp');
          }
          if (codeViewClassIdx === wantClass && codeViewMethodIdx === wantMethod) {
            updateCodeView();
          }
        }, 0);
        return;
      }
      const m = method;
      const rows = Array.isArray(m?.bytecode) ? m.bytecode : [];
      const bytecodeHtml = renderBytecodeLines(rows);
      const className = classes[classIdx]?.name ?? '';
      const decompilation = m?.decompilation || '(no body)';
      const displayMethodName = getDisplayMethodName(className, m?.name);
      const sourceToShow = applyMethodRenameToDecompilation(decompilation, m?.name, displayMethodName) || decompilation;
      if (needFetch && rows.length === 0) {
        setBytecodeListingHtml(bytecodeEmptyHtml('Failed to load method', 'Try selecting again or check the console'), {
          empty: true,
          sourceMeta: displayMethodName || '',
        });
        currentSourceMethodMeta = { classIdx, methodIdx: codeViewMethodIdx, name: displayMethodName };
        setSourceContent(sourceCode, sourceToShow);
        clearCfgGraph();
      } else {
        const wrappedBc = wrapSingleMethodBytecodeHtml(bytecodeHtml, {
          classIdx,
          methodIdx: codeViewMethodIdx,
          displayName: displayMethodName,
        });
        setBytecodeListingHtml(wrappedBc, {
          empty: rows.length === 0,
          insnCount: rows.length,
          sourceMeta: displayMethodName || '',
        });
        currentSourceMethodMeta = { classIdx, methodIdx: codeViewMethodIdx, name: displayMethodName };
        setSourceContent(sourceCode, sourceToShow);
        requestAnimationFrame(() => renderCfgGraph(m));
        ensureCfgPaneExpanded();
        loadAndShowMethodCallers(classIdx, codeViewMethodIdx);
      }
    } else {
      selectDexMethod(classIdx, codeViewMethodIdx);
    }
  }
  updateAnnotationPanel();
  syncLeftTreeToSelectedClass();
}

function truncate(s, len) {
  if (!s || s.length <= len) return s;
  return s.slice(0, len) + '…';
}

/**
 * Keep the left class tree aligned with the middle Package/Class/Method selection:
 * switch package if needed, expand the class node, highlight selection, scroll into view.
 * When the class changes, collapses the previously auto-expanded class.
 */
function collapseTreeClassNode(classIdx, opts = {}) {
  if (!treeContent || classIdx == null || Number.isNaN(Number(classIdx))) return;
  let el = null;
  if (opts.className) {
    el = treeContent.querySelector(
      `.tree-item.class[data-class-name="${CSS.escape(String(opts.className))}"]`
    );
  }
  if (!el && opts.dexFile) {
    el = treeContent.querySelector(
      `.tree-item.class[data-dex-file="${CSS.escape(String(opts.dexFile))}"][data-class="${CSS.escape(String(classIdx))}"]`
    );
  }
  if (!el) {
    el = treeContent.querySelector(
      `.tree-item.class[data-class="${CSS.escape(String(classIdx))}"]`
    );
  }
  if (!el) return;
  const ul = el.nextElementSibling;
  if (ul && ul.tagName === 'UL') {
    ul.style.display = 'none';
    const arrow = el.querySelector('.arrow');
    arrow?.classList.add('collapsed');
    arrow?.classList.remove('expanded');
  }
}

function syncLeftTreeToSelectedClass() {
  if (!treeContent) return;
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  const classIdx = codeViewClassIdx;
  if (!Array.isArray(classes) || classIdx == null || !classes[classIdx]) return;
  if (currentType === 'apk' && apkLeftMode !== 'classes') return;
  if (currentType !== 'dex' && currentType !== 'apk') return;

  const className = classes[classIdx].name || '';
  const pkg = getPackageFromClassName(className);
  const searchActive = !!(searchQuery && String(searchQuery).length);
  const openDex = currentType === 'apk' && apkExtractedFile?.kind === 'dex' ? apkExtractedFile.name : '';
  const classChanged = syncLeftTreeToSelectedClass._lastClassIdx !== classIdx
    || syncLeftTreeToSelectedClass._lastClassName !== className;
  const prevAuto = syncLeftTreeToSelectedClass._autoExpanded;

  // Close the previously auto-opened class when the middle UI switches class.
  if (classChanged && prevAuto && (prevAuto.classIdx !== classIdx || prevAuto.className !== className)) {
    collapseTreeClassNode(prevAuto.classIdx, prevAuto);
  }

  if (!searchActive && pkg && selectedDexPackage !== pkg) {
    selectedDexPackage = pkg;
    if (dexPackageSelect) dexPackageSelect.value = pkg;
    if (currentType === 'dex') {
      renderClassTreeFromPackageMap(classes, buildDexPackageMap(classes), { isApk: false });
    } else {
      renderApkClassTree();
    }
  }

  let classEl = null;
  if (currentType === 'apk' && !apkDexFilter && className) {
    classEl = treeContent.querySelector(
      `.tree-item.class[data-class-name="${CSS.escape(className)}"]`
    );
  }
  if (!classEl && openDex) {
    classEl = treeContent.querySelector(
      `.tree-item.class[data-dex-file="${CSS.escape(openDex)}"][data-class="${CSS.escape(String(classIdx))}"]`
    );
  }
  if (!classEl) {
    classEl = treeContent.querySelector(
      `.tree-item.class[data-class="${CSS.escape(String(classIdx))}"]`
    );
  }
  if (!classEl) {
    syncLeftTreeToSelectedClass._lastClassIdx = classIdx;
    syncLeftTreeToSelectedClass._lastClassName = className;
    syncLeftTreeToSelectedClass._lastMethodIdx = codeViewMethodIdx;
    return;
  }

  // Reveal ancestor lists (e.g. package groups while searching).
  let node = classEl.parentElement;
  while (node && node !== treeContent) {
    if (node.tagName === 'UL' && node.style.display === 'none') {
      node.style.display = '';
      const prev = node.previousElementSibling;
      if (prev?.classList?.contains('tree-item')) {
        const arrow = prev.querySelector('.arrow');
        arrow?.classList.remove('collapsed');
        arrow?.classList.add('expanded');
      }
    }
    node = node.parentElement;
  }

  const kids = classEl.nextElementSibling;
  const autoMeta = { classIdx, className, dexFile: openDex || classEl.dataset.dexFile || '' };
  if (classChanged && kids && kids.tagName === 'UL') {
    kids.style.display = '';
    const arrow = classEl.querySelector('.arrow');
    arrow?.classList.remove('collapsed');
    arrow?.classList.add('expanded');
    syncLeftTreeToSelectedClass._autoExpanded = autoMeta;
  } else if (codeViewMethodIdx != null && kids && kids.tagName === 'UL' && kids.style.display === 'none') {
    // Method selected while class was collapsed — reveal children.
    kids.style.display = '';
    const arrow = classEl.querySelector('.arrow');
    arrow?.classList.remove('collapsed');
    arrow?.classList.add('expanded');
    syncLeftTreeToSelectedClass._autoExpanded = autoMeta;
  }

  treeContent.querySelectorAll('.tree-item.selected').forEach((el) => el.classList.remove('selected'));
  let focusEl = classEl;
  if (codeViewMethodIdx != null) {
    const methodEl =
      (kids && kids.tagName === 'UL'
        ? kids.querySelector(
            `.tree-item.method[data-class="${CSS.escape(String(classIdx))}"][data-method="${CSS.escape(String(codeViewMethodIdx))}"]`
          )
        : null)
      || treeContent.querySelector(
        `.tree-item.method[data-class="${CSS.escape(String(classIdx))}"][data-method="${CSS.escape(String(codeViewMethodIdx))}"]`
      );
    if (methodEl) {
      methodEl.classList.add('selected');
      focusEl = methodEl;
    } else {
      classEl.classList.add('selected');
    }
  } else {
    classEl.classList.add('selected');
  }

  const methodChanged = syncLeftTreeToSelectedClass._lastMethodIdx !== codeViewMethodIdx;
  syncLeftTreeToSelectedClass._lastClassIdx = classIdx;
  syncLeftTreeToSelectedClass._lastClassName = className;
  syncLeftTreeToSelectedClass._lastMethodIdx = codeViewMethodIdx;
  if (classChanged || methodChanged) {
    requestAnimationFrame(() => {
      try {
        focusEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      } catch (_) {}
    });
  }
}

function escapeAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

/** Opcode category for coloring (Dalvik mnemonics). */
function bytecodeOpcodeClass(mnemonic) {
  const m = String(mnemonic || '').toLowerCase();
  if (m.startsWith('invoke') || m === 'filled-new-array' || m.startsWith('filled-new-array')) return 'bc-op-invoke';
  if (m.startsWith('if-') || m.startsWith('goto') || m.includes('switch') || m === 'throw') return 'bc-op-branch';
  if (m.startsWith('return')) return 'bc-op-return';
  if (m.startsWith('const') || m === 'fill-array-data') return 'bc-op-const';
  if (m.startsWith('move')) return 'bc-op-move';
  if (m.includes('get') || m.includes('put') || m.startsWith('iget') || m.startsWith('iput') || m.startsWith('sget') || m.startsWith('sput')) return 'bc-op-field';
  if (m.startsWith('new-') || m === 'check-cast' || m === 'instance-of' || m.startsWith('array-') || m.startsWith('monitor')) return 'bc-op-object';
  return '';
}

/** Stable palette index for a Dalvik register name (v0 / p1 → 0..11). */
function registerColorIndex(reg) {
  const m = String(reg || '').match(/^([vp])(\d+)$/i);
  if (!m) return 0;
  const n = parseInt(m[2], 10) >>> 0;
  // Offset param regs slightly so p0 ≠ v0 visually when both appear.
  const base = m[1].toLowerCase() === 'p' ? n + 7 : n;
  return base % 12;
}

/** Highlight registers, immediates, types, and string-like tokens in operands.
 *  When branchTargets is set, replace the trailing relative ±Xh with clickable absolute addresses. */
function highlightBytecodeOperands(operands, { branchTargets = null, offsetSet = null, stringIdx = null, fieldIdx = null } = {}) {
  if (!operands && !(branchTargets && branchTargets.length)) return '';
  let head = String(operands || '');
  let addrLinksHtml = '';
  if (branchTargets?.length) {
    const m = head.match(/^(.*?)([+-]?[0-9a-fA-F]+h)(\s*)$/i);
    if (m) {
      head = m[1].replace(/,\s*$/, '').trim();
    }
    addrLinksHtml = branchTargets.map((t) => {
      const hex = formatBytecodeOffset(t);
      const inView = !offsetSet || offsetSet.has(t);
      const cls = inView ? 'bc-addr-link' : 'bc-addr-link is-missing';
      return `<a href="#bc-${t}" class="${cls}" data-target-offset="${t}" title="Go to ${hex}">${hex}</a>`;
    }).join(', ');
  }
  const stringIdxAttr = stringIdx != null && Number.isFinite(Number(stringIdx))
    ? ` data-string-idx="${Number(stringIdx) >>> 0}" title="Find other uses of this string"`
    : '';
  let esc = escapeHtml(head);
  if (esc) {
    // Protect field refs so imm/type wraps do not break Class.field / field@N.
    if (fieldIdx != null && Number.isFinite(Number(fieldIdx))) {
      esc = esc.replace(/\bfield@\d+\b/i, (m) => `\u0001FIELD\u0001${m}\u0001/FIELD\u0001`);
      esc = esc.replace(/((?:[\w$]+\.)*[\w$]+\.[\w$]+)\s*$/, (m) => `\u0001FIELD\u0001${m}\u0001/FIELD\u0001`);
    }
    // Apply token wraps on plain escaped text first; registers last so attribute
    // digits (e.g. data-reg-hue="3") are not re-matched as immediates.
    esc = esc
      .replace(/\b(0x[0-9a-fA-F]+|\d+)\b/g, (m) => {
        const key = normalizeCrossConstKey(m);
        return key
          ? `<span class="bc-imm" data-const="${escapeAttr(key)}">${m}</span>`
          : `<span class="bc-imm">${m}</span>`;
      })
      .replace(/\b(L[\w/$]+;|\[[ZBSCIJFD]|[ZBSCIJFD])\b/g, (m) => {
        const kind = frameworkApiKind(m);
        if (kind) return formatBytecodeApiHtml(m, kind, { docName: m, isDescriptor: true });
        return `<span class="bc-type">${m}</span>`;
      })
      // Resolved Java names: android.app.Activity.onCreate / java.util.List
      .replace(/\b((?:androidx?|java|javax)(?:\.[\w$]+)+)\b/g, (m) => {
        const kind = frameworkApiKind(m);
        if (!kind) return m;
        return formatBytecodeApiHtml(m, kind, { docName: m, isDescriptor: false });
      })
      // Resource refs: R.id.foo / pkg.R.string.bar
      .replace(/\b((?:[\w$]+\.)*R\.[a-z][\w$]*\.[\w$]+)\b/g, (m) => {
        return `<span class="bc-api bc-api-r">${m}</span>`;
      })
      .replace(/(&quot;.*?&quot;|&apos;.*?&apos;)/g, (m) => {
        const key = normalizeCrossConstKey(m);
        const cls = stringIdxAttr ? 'bc-str bc-str-xref' : 'bc-str';
        return key
          ? `<span class="${cls}" data-const="${escapeAttr(key)}"${stringIdxAttr}>${m}</span>`
          : `<span class="${cls}"${stringIdxAttr}>${m}</span>`;
      })
      .replace(/\b([vp]\d+)\b/g, (m) => {
        const hue = registerColorIndex(m);
        return `<span class="bc-reg bc-reg-h${hue}" data-reg="${escapeAttr(m)}" data-reg-hue="${hue}">${m}</span>`;
      });
    if (fieldIdx != null && Number.isFinite(Number(fieldIdx))) {
      const fIdx = Number(fieldIdx) >>> 0;
      esc = esc.replace(/\u0001FIELD\u0001([\s\S]*?)\u0001\/FIELD\u0001/g, (_, inner) =>
        `<span class="bc-field-ref" role="link" tabindex="0" data-field-idx="${fIdx}" title="Show field usages">${inner}</span>`
      );
    }
  }
  if (addrLinksHtml) return esc ? `${esc}, ${addrLinksHtml}` : addrLinksHtml;
  return esc;
}

/** Parse trailing Dalvik relative branch units from operands (e.g. "+02h", "v0, +0004h"). */
function parseDalvikBranchUnits(operands) {
  const m = String(operands || '').trim().match(/([+-]?[0-9a-fA-F]+)h\s*$/i);
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return Number.isFinite(n) ? n : null;
}

/**
 * Official Dalvik: destination = instruction_address + signed_offset × 2
 * (offset is in 16-bit code units, relative to this instruction).
 */
function dalvikRelativeTarget(insnOffset, units) {
  if (units == null || !Number.isFinite(units)) return null;
  const t = (insnOffset >>> 0) + (units | 0) * 2;
  return t >= 0 ? (t >>> 0) : null;
}

function parseHexBytes(hex) {
  const parts = String(hex || '').trim().split(/\s+/).filter(Boolean);
  const out = new Uint8Array(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const v = parseInt(parts[i], 16);
    if (!Number.isFinite(v)) return null;
    out[i] = v & 0xff;
  }
  return out;
}

function readI32LE(bytes, off) {
  if (!bytes || off + 4 > bytes.length) return null;
  return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) | 0;
}

function readU16LE(bytes, off) {
  if (!bytes || off + 2 > bytes.length) return null;
  return bytes[off] | (bytes[off + 1] << 8);
}

function readI16LE(bytes, off) {
  const u = readU16LE(bytes, off);
  if (u == null) return null;
  return (u << 16) >> 16;
}

/** Decode signed branch offset (code units) from raw instruction hex when possible. */
function branchUnitsFromRow(row) {
  const bytes = parseHexBytes(row?.hex);
  if (bytes && bytes.length >= 2) {
    const op = bytes[0];
    // goto (10t)
    if (op === 0x28) return (bytes[1] << 24) >> 24;
    // goto/16 (20t)
    if (op === 0x29 && bytes.length >= 4) return readI16LE(bytes, 2);
    // goto/32 (30t)
    if (op === 0x2a && bytes.length >= 6) return readI32LE(bytes, 2);
    // if-test (22t) 0x32..0x37
    if (op >= 0x32 && op <= 0x37 && bytes.length >= 4) return readI16LE(bytes, 2);
    // if-testz (21t) 0x38..0x3d
    if (op >= 0x38 && op <= 0x3d && bytes.length >= 4) return readI16LE(bytes, 2);
    // packed-switch / sparse-switch (31t)
    if ((op === 0x2b || op === 0x2c) && bytes.length >= 6) return readI32LE(bytes, 2);
  }
  return parseDalvikBranchUnits(row?.operands);
}

/** Expand packed/sparse-switch case targets from the payload row hex. */
function switchCaseTargetsFromPayload(switchOffset, payloadRow) {
  const bytes = parseHexBytes(payloadRow?.hex);
  if (!bytes || bytes.length < 4) return [];
  const ident = readU16LE(bytes, 0);
  const size = readU16LE(bytes, 2);
  if (size == null || size <= 0) return [];
  const base = switchOffset | 0;
  const out = [];
  if (ident === 0x0100) {
    // packed-switch-payload: ident, size, first_key, then size×i32 targets
    for (let i = 0; i < size; i++) {
      const rel = readI32LE(bytes, 8 + i * 4);
      if (rel == null) break;
      const t = base + rel * 2;
      if (t >= 0) out.push(t >>> 0);
    }
  } else if (ident === 0x0200) {
    // sparse-switch-payload: ident, size, keys…, targets…
    const targetsBase = 4 + size * 4;
    for (let i = 0; i < size; i++) {
      const rel = readI32LE(bytes, targetsBase + i * 4);
      if (rel == null) break;
      const t = base + rel * 2;
      if (t >= 0) out.push(t >>> 0);
    }
  }
  return [...new Set(out)].sort((a, b) => a - b);
}

/**
 * Resolve control-flow jump targets for a bytecode row (goto / if-* / switch).
 * Returns absolute byte offsets within the method (Dalvik-correct).
 */
function resolveBytecodeJumpTargets(row, rowByOffset) {
  const mn = String(row?.mnemonic || '').toLowerCase();
  const off = Number(row?.offset) >>> 0;
  if (/^goto/.test(mn) || /^if-/.test(mn)) {
    const units = branchUnitsFromRow(row);
    const t = dalvikRelativeTarget(off, units);
    return t == null ? [] : [t];
  }
  if (mn === 'packed-switch' || mn === 'sparse-switch') {
    const units = branchUnitsFromRow(row);
    const payloadOff = dalvikRelativeTarget(off, units);
    if (payloadOff == null) return [];
    const payloadRow = rowByOffset.get(payloadOff);
    if (payloadRow) {
      const cases = switchCaseTargetsFromPayload(off, payloadRow);
      if (cases.length) return cases;
    }
    // Fallback: still link to the payload address
    return [payloadOff];
  }
  return [];
}

function formatBytecodeOffset(off) {
  return '0x' + (Number(off) >>> 0).toString(16).padStart(4, '0');
}

function jumpKindForMnemonic(mnemonic) {
  const m = String(mnemonic || '').toLowerCase();
  if (/^goto/.test(m)) return 'jmp';
  if (/^if-/.test(m)) return 'cond';
  if (m.includes('switch')) return 'switch';
  return 'jmp';
}

/** Build jump-target map and reverse XREF map for a method's bytecode rows. */
function buildBytecodeJumpMaps(rows) {
  const rowByOffset = new Map();
  const offsetSet = new Set();
  for (const r of rows) {
    const off = Number(r.offset) >>> 0;
    rowByOffset.set(off, r);
    offsetSet.add(off);
  }
  const jumpsByFrom = new Map();
  const xrefsTo = new Map();
  for (const r of rows) {
    const from = Number(r.offset) >>> 0;
    const targets = resolveBytecodeJumpTargets(r, rowByOffset);
    if (!targets.length) continue;
    jumpsByFrom.set(from, targets);
    const kind = jumpKindForMnemonic(r.mnemonic);
    for (const t of targets) {
      if (!xrefsTo.has(t)) xrefsTo.set(t, []);
      xrefsTo.get(t).push({ from, kind, mnemonic: r.mnemonic || '' });
    }
  }
  return { rowByOffset, offsetSet, jumpsByFrom, xrefsTo };
}

let bytecodeNavStack = [];
const bytecodeNavBackBtn = document.getElementById('bytecode-nav-back');

function updateBytecodeNavBackBtn() {
  if (!bytecodeNavBackBtn) return;
  bytecodeNavBackBtn.disabled = bytecodeNavStack.length === 0;
  bytecodeNavBackBtn.title = bytecodeNavStack.length
    ? `Back to ${formatBytecodeOffset(bytecodeNavStack[bytecodeNavStack.length - 1])} (Alt+←)`
    : 'Back to previous offset (Alt+←)';
}

function clearBytecodeNavStack() {
  bytecodeNavStack = [];
  updateBytecodeNavBackBtn();
}

function scrollBytecodeLineIntoView(line, { block = 'nearest', behavior = 'smooth' } = {}) {
  if (!line) return;
  const wrap = document.getElementById('bytecode-listing-wrap');
  if (!wrap) {
    line.scrollIntoView({ block, behavior });
    return;
  }
  const wrapRect = wrap.getBoundingClientRect();
  const lineRect = line.getBoundingClientRect();
  const style = getComputedStyle(wrap);
  const padTop = parseFloat(style.scrollPaddingTop) || 0;
  const padBottom = parseFloat(style.scrollPaddingBottom) || 0;
  const visibleTop = wrapRect.top + padTop;
  const visibleBottom = wrapRect.bottom - padBottom;
  let delta = 0;
  if (block === 'center') {
    const mid = (visibleTop + visibleBottom) / 2;
    delta = lineRect.top + lineRect.height / 2 - mid;
  } else if (lineRect.top < visibleTop) {
    delta = lineRect.top - visibleTop;
  } else if (lineRect.bottom > visibleBottom) {
    delta = lineRect.bottom - visibleBottom;
  }
  if (Math.abs(delta) < 1) return;
  wrap.scrollTo({ top: wrap.scrollTop + delta, behavior });
}

function flashBytecodeOffset(offset) {
  if (!bytecodeListing) return;
  bytecodeListing.querySelectorAll('.bytecode-line.bc-jump-flash').forEach((el) => el.classList.remove('bc-jump-flash'));
  const line = bytecodeListing.querySelector(`.bytecode-line[data-offset="${offset}"]`);
  if (!line) return;
  line.classList.add('bc-jump-flash');
  scrollBytecodeLineIntoView(line, { block: 'center', behavior: 'smooth' });
  window.setTimeout(() => line.classList.remove('bc-jump-flash'), 1200);
}

/** Jump within the current bytecode listing (elfbrowser-style). */
function jumpBytecodeToOffset(targetOffset, { fromOffset = null, push = true } = {}) {
  const target = Number(targetOffset) >>> 0;
  if (!bytecodeListing) return false;
  const line = bytecodeListing.querySelector(`.bytecode-line[data-offset="${target}"]`);
  if (!line) return false;
  if (push && fromOffset != null && Number.isFinite(Number(fromOffset))) {
    const from = Number(fromOffset) >>> 0;
    if (from !== target) {
      bytecodeNavStack.push(from);
      if (bytecodeNavStack.length > 64) bytecodeNavStack.shift();
      updateBytecodeNavBackBtn();
    }
  }
  // Expand bytecode dock if collapsed
  const pane = document.getElementById('bytecode-pane');
  if (pane?.dataset.collapsed === 'true') {
    setDockCollapsed(pane, false, 'droid2web-bytecode-open');
    updateWorkspaceResizers();
  }
  flashBytecodeOffset(target);
  return true;
}

function bytecodeNavBack() {
  if (!bytecodeNavStack.length) return;
  const prev = bytecodeNavStack.pop();
  updateBytecodeNavBackBtn();
  jumpBytecodeToOffset(prev, { push: false });
}

bytecodeNavBackBtn?.addEventListener('click', () => bytecodeNavBack());

/** Pool index for const-string / const-string/jumbo from insn hex (preferred) or operands. */
function stringIndexFromBytecodeRow(row) {
  const mn = String(row?.mnemonic || '').toLowerCase();
  if (mn !== 'const-string' && mn !== 'const-string/jumbo') return null;
  const bytes = parseHexBytes(row?.hex);
  if (bytes && bytes.length >= 4) {
    const op = bytes[0];
    // const-string (21c): AA|op, BBBB
    if (op === 0x1a) {
      const idx = readU16LE(bytes, 2);
      if (idx != null) return idx >>> 0;
    }
    // const-string/jumbo (31c): AA|op, BBBBbbbb
    if (op === 0x1b && bytes.length >= 6) {
      const lo = readU16LE(bytes, 2);
      const hi = readU16LE(bytes, 4);
      if (lo != null && hi != null) return ((hi << 16) | lo) >>> 0;
    }
  }
  const ops = String(row?.operands || '');
  const at = ops.match(/string@(\d+)/i);
  if (at) {
    const idx = parseInt(at[1], 10);
    if (Number.isFinite(idx) && idx >= 0) return idx >>> 0;
  }
  const qm = ops.match(/"((?:\\.|[^"\\])*)"/);
  if (qm && Array.isArray(currentStringsArray) && currentStringsArray.length) {
    const unescaped = unescapeJavaStringLiteral(qm[1]);
    const idx = currentStringsArray.indexOf(unescaped);
    if (idx >= 0) return idx >>> 0;
  }
  return null;
}

function unescapeJavaStringLiteral(s) {
  return String(s || '').replace(/\\([\\'"nrtbf]|u[0-9a-fA-F]{4}|[0-7]{1,3})/g, (_, esc) => {
    if (esc === '\\' || esc === "'" || esc === '"') return esc;
    if (esc === 'n') return '\n';
    if (esc === 'r') return '\r';
    if (esc === 't') return '\t';
    if (esc === 'b') return '\b';
    if (esc === 'f') return '\f';
    if (esc[0] === 'u') return String.fromCharCode(parseInt(esc.slice(1), 16));
    return String.fromCharCode(parseInt(esc, 8));
  });
}

function renderBytecodeStringXrefPlaceholder(stringIdx, offset) {
  const idx = Number(stringIdx) >>> 0;
  const off = Number(offset) >>> 0;
  return `<span class="bc-string-xref bytecode-string-xref is-pending" data-string-idx="${idx}" data-xref-for="${off}" role="button" tabindex="0" title="Find other const-string uses of this pool entry"><span class="bc-xref-label">; xref</span> <span class="bc-string-xref-hint muted">uses</span></span>`;
}

function renderBytecodeStringXrefHtml(info, { selfOffset = null, selfClass = '', selfMethod = '' } = {}) {
  const idx = info?.string_index ?? info?.stringIndex;
  const usages = Array.isArray(info?.usages) ? info.usages : [];
  const truncated = !!(info?.truncated);
  const labelIdx = idx != null ? Number(idx) >>> 0 : '?';
  if (!usages.length) {
    return `<span class="bc-xref-label">; xref[${labelIdx}]</span> <span class="muted">none</span>`;
  }
  const maxShow = 8;
  const refs = usages.slice(0, maxShow).map((u) => {
    const className = u.class_name || u.className || '';
    const methodName = u.method_name || u.methodName || '';
    const simple = className.split('.').pop() || className || '?';
    const off = u.offset;
    const hex = formatSecHexOffset(off);
    const here = selfOffset != null
      && (Number(off) >>> 0) === (Number(selfOffset) >>> 0)
      && (!selfClass || className === selfClass)
      && (!selfMethod || methodName === selfMethod);
    const cls = here ? 'bc-xref-ref string-xref-ref is-here' : 'bc-xref-ref string-xref-ref';
    const label = `${simple}.${methodName || '?'}`;
    return `<span class="${cls}" role="link" tabindex="0" data-class="${escapeAttr(className)}" data-method="${escapeAttr(methodName)}" data-offset="${off ?? ''}" title="${escapeAttr(`${label} @ ${hex}`)}">${escapeHtml(label)}${here ? ' ←' : ''}</span>`;
  }).join(' ');
  const more = usages.length > maxShow
    ? ` <span class="bc-xref-more">+${usages.length - maxShow}</span>`
    : (truncated ? ` <span class="bc-xref-more">…</span>` : '');
  return `<span class="bc-xref-label">; xref[${usages.length}${truncated ? '+' : ''}]</span> ${refs}${more}`;
}

function resolveBytecodeStringXrefSelf(slot) {
  const selfOffset = parseInt(slot?.getAttribute('data-xref-for') || '', 10);
  const block = slot?.closest?.('.bytecode-method-block, .bytecode-method-view');
  let selfClass = '';
  let selfMethod = '';
  if (block) {
    const classIdx = parseInt(block.getAttribute('data-class-idx'), 10);
    const methodIdx = parseInt(block.getAttribute('data-method-idx'), 10);
    const cls = Number.isFinite(classIdx) ? currentData?.classes?.[classIdx] : null;
    const method = cls?.methods?.[methodIdx];
    selfClass = cls?.name || '';
    selfMethod = (method?.dex_name || method?.dexName || method?.name || '').trim();
    if (selfMethod && selfMethod === (cls?.name || '').split('.').pop()) selfMethod = '<init>';
  }
  return {
    selfOffset: Number.isFinite(selfOffset) ? selfOffset : null,
    selfClass,
    selfMethod,
  };
}

async function fetchStringUsagesInfo(stringIndex) {
  const dex = getActiveStringsDexBytes();
  if (!dex?.bytes?.length) throw new Error('No DEX bytes loaded');
  const fp = stringsUsageCacheFingerprint(dex.bytes);
  if (fp !== stringsUsageCacheKey) {
    stringsUsageCache = new Map();
    stringsUsageCacheKey = fp;
  }
  if (stringsUsageCache.has(stringIndex)) {
    return stringsUsageCache.get(stringIndex);
  }
  const raw = await findStringUsagesInWorker(dex.bytes, stringIndex);
  const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
  if (!result?.ok) throw new Error(result?.error || 'Usage scan failed');
  let info = result.data || result;
  if (typeof normalizeWasmResult === 'function') info = normalizeWasmResult(info) || info;
  if (Array.isArray(info?.usages)) {
    info = {
      ...info,
      usages: info.usages.map((u) => (u && typeof u === 'object' ? (normalizeWasmResult(u) || u) : u)),
    };
  }
  stringsUsageCache.set(stringIndex, info);
  return info;
}

const bytecodeStringXrefInflight = new Map();

/** Fill all bytecode string-xref slots for a pool index (shared cache with Strings tab). */
async function loadBytecodeStringXrefs(stringIndex, { triggerSlot = null } = {}) {
  const idx = Number(stringIndex) >>> 0;
  if (!bytecodeListing) return;
  const slots = [...bytecodeListing.querySelectorAll(`.bytecode-string-xref[data-string-idx="${idx}"]`)];
  if (!slots.length) return;
  const reqId = (bytecodeStringXrefInflight.get(idx) || 0) + 1;
  bytecodeStringXrefInflight.set(idx, reqId);
  for (const slot of slots) {
    if (slot === triggerSlot || slot.classList.contains('is-pending') || slot.classList.contains('is-loading')) {
      slot.classList.add('is-loading');
      slot.classList.remove('is-pending');
      slot.innerHTML = `<span class="bc-xref-label">; xref</span> <span class="muted">…</span>`;
    }
  }
  try {
    const info = await fetchStringUsagesInfo(idx);
    if (bytecodeStringXrefInflight.get(idx) !== reqId) return;
    if (!bytecodeListing?.querySelector(`.bytecode-string-xref[data-string-idx="${idx}"]`)) return;
    for (const slot of bytecodeListing.querySelectorAll(`.bytecode-string-xref[data-string-idx="${idx}"]`)) {
      const self = resolveBytecodeStringXrefSelf(slot);
      slot.classList.remove('is-pending', 'is-loading');
      slot.classList.add('is-loaded');
      slot.removeAttribute('role');
      slot.innerHTML = renderBytecodeStringXrefHtml(info, self);
    }
  } catch (e) {
    if (bytecodeStringXrefInflight.get(idx) !== reqId) return;
    const msg = escapeHtml(e?.message || String(e));
    for (const slot of bytecodeListing.querySelectorAll(`.bytecode-string-xref[data-string-idx="${idx}"]`)) {
      slot.classList.remove('is-loading');
      slot.classList.add('is-pending');
      slot.setAttribute('role', 'button');
      slot.innerHTML = `<span class="bc-xref-label">; xref</span> <span class="muted">${msg}</span> <span class="bc-string-xref-hint muted">retry</span>`;
    }
  }
}

function navigateToStringXref(el) {
  if (!el) return;
  const className = el.getAttribute('data-class') || '';
  const methodName = el.getAttribute('data-method') || '';
  const offsetRaw = el.getAttribute('data-offset');
  const offset = offsetRaw !== '' && offsetRaw != null ? parseInt(offsetRaw, 10) : null;
  if (!className) return;
  navigateToSecurityFinding(className, methodName, '', {
    offset: Number.isFinite(offset) ? offset : undefined,
    hint: '',
  });
}

function renderBytecodeLine(row, { jumpTargets = [], offsetSet = null, stringIdx = null, fieldIdx = null } = {}) {
  const offsetHex = formatBytecodeOffset(row.offset);
  const opClass = bytecodeOpcodeClass(row.mnemonic);
  const hex = `<span class="bc-hex">${escapeHtml(row.hex || '')}</span>`;
  const mnemonic = `<span class="bc-mnemonic${opClass ? ' ' + opClass : ''}">${escapeHtml(row.mnemonic || '')}</span>`;
  const stringXrefHtml = stringIdx != null
    ? renderBytecodeStringXrefPlaceholder(stringIdx, row.offset)
    : '';
  const operands = `<span class="bc-operands">${highlightBytecodeOperands(row.operands || '', {
    branchTargets: jumpTargets.length ? jumpTargets : null,
    offsetSet,
    stringIdx,
    fieldIdx,
  })}${stringXrefHtml}</span>`;
  let jumpsHtml = '<span class="bc-jumps"></span>';
  if (jumpTargets.length) {
    const arrows = jumpTargets.map((t) => {
      const hexT = formatBytecodeOffset(t);
      const inView = !offsetSet || offsetSet.has(t);
      const cls = inView ? 'bc-jump-arrow bc-jump-inview' : 'bc-jump-arrow';
      return `<a href="#bc-${t}" class="${cls}" data-target-offset="${t}" title="Jump to ${hexT}">→ ${hexT}</a>`;
    }).join('');
    jumpsHtml = `<span class="bc-jumps">${arrows}</span>`;
  }
  const strAttr = stringIdx != null ? ` data-string-idx="${Number(stringIdx) >>> 0}"` : '';
  const fieldAttr = fieldIdx != null ? ` data-field-idx="${Number(fieldIdx) >>> 0}"` : '';
  return `<div class="bytecode-line" data-offset="${row.offset}"${strAttr}${fieldAttr} data-search="${escapeAttr((row.mnemonic || '') + ' ' + (row.operands || '') + ' ' + (row.hex || ''))}"><span class="bc-offset">${offsetHex}</span>${hex}${mnemonic}${operands}${jumpsHtml}</div>`;
}

function renderBytecodeXrefLine(offset, refs) {
  if (!refs?.length) return '';
  const maxShow = 5;
  const shown = refs.slice(0, maxShow);
  const refStrs = shown.map((x) => {
    const hex = formatBytecodeOffset(x.from);
    const icon = x.kind === 'cond' ? '↗' : x.kind === 'switch' ? '↳' : '→';
    return `<span class="bc-xref-ref" data-target-offset="${x.from}" title="${escapeAttr((x.mnemonic || '') + ' @ ' + hex)}">${icon}${hex}</span>`;
  }).join(', ');
  const more = refs.length > maxShow
    ? `<span class="bc-xref-more">+${refs.length - maxShow} more</span>`
    : '';
  return `<div class="bytecode-xref-line" data-xref-for="${offset}" title="Cross-references to this offset"><span class="bc-xref-label">; XREF[${refs.length}]:</span> ${refStrs}${more ? ' ' + more : ''}</div>`;
}

function renderBytecodeLines(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return '<div class="code-empty"><div class="code-empty-title">No bytecode</div><div class="code-empty-hint muted">This method has no code item</div></div>';
  }
  const { offsetSet, jumpsByFrom, xrefsTo } = buildBytecodeJumpMaps(rows);
  return rows.map((row) => {
    const off = Number(row.offset) >>> 0;
    const stringIdx = stringIndexFromBytecodeRow(row);
    const fieldIdx = fieldIndexFromBytecodeRow(row);
    const xrefHtml = renderBytecodeXrefLine(off, xrefsTo.get(off));
    const lineHtml = renderBytecodeLine(row, {
      jumpTargets: jumpsByFrom.get(off) || [],
      offsetSet,
      stringIdx,
      fieldIdx,
    });
    return xrefHtml + lineHtml;
  }).join('');
}

function bytecodeEmptyHtml(title, hint) {
  return `<div class="code-empty"><div class="code-empty-title">${escapeHtml(title)}</div><div class="code-empty-hint muted">${escapeHtml(hint)}</div></div>`;
}

/** Wrap single-method bytecode with sticky chrome (← Class + Open CFG), matching source. */
function wrapSingleMethodBytecodeHtml(rowsHtml, {
  classIdx,
  methodIdx,
  displayName,
} = {}) {
  const header = renderMethodBlockHeader(displayName || 'method', {
    openCfg: true,
    hint: 'Show CFG',
    backToClass: true,
  });
  const callersSlot = `<div class="method-callers-xrefs" data-class-idx="${classIdx ?? ''}" data-method-idx="${methodIdx ?? ''}" hidden></div>`;
  return `<div class="bytecode-method-view" data-class-idx="${classIdx ?? ''}" data-method-idx="${methodIdx ?? ''}" data-method-name="${escapeAttr(displayName || '')}">${header}${callersSlot}${rowsHtml || ''}</div>`;
}

let fieldXrefsRequestId = 0;
let fieldXrefsCacheKey = '';
const fieldXrefsCache = new Map();

function fieldXrefsCacheFingerprint(bytes) {
  return methodCallersCacheFingerprint(bytes);
}

function renderFieldXrefsHtml(info) {
  const xrefs = Array.isArray(info?.xrefs) ? info.xrefs : [];
  const truncated = !!(info?.truncated);
  const fClass = info?.field_class || info?.fieldClass || '';
  const fName = info?.field_name || info?.fieldName || '';
  const fType = info?.field_type || info?.fieldType || '';
  const simpleClass = fClass.split('.').pop() || fClass || '?';
  let initSuffix = '';
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  if (Array.isArray(classes)) {
    for (const cl of classes) {
      const hit = (cl?.fields || []).find((f) => Number(f.field_idx ?? f.fieldIdx) === Number(info?.field_idx ?? info?.fieldIdx));
      if (hit) {
        const init = hit.initial_value ?? hit.initialValue;
        if (init != null && String(init) !== '') initSuffix = ` = ${init}`;
        break;
      }
    }
  }
  const head = `<span class="bc-xref-label">; FIELD ${escapeHtml(shortJavaType(fType))} ${escapeHtml(simpleClass)}.${escapeHtml(fName)}${escapeHtml(initSuffix)}</span>`;
  if (!xrefs.length) {
    return `${head}<br><span class="bc-xref-label">; XREF[0]:</span> <span class="muted">none</span>`;
  }
  const maxShow = 16;
  const refs = xrefs.slice(0, maxShow).map((x) => {
    const className = x.class_name || x.className || '';
    const methodName = x.method_name || x.methodName || '';
    const simple = className.split('.').pop() || className || '?';
    const kind = x.access_kind || x.accessKind || 'field';
    const off = x.offset;
    const ci = x.class_idx ?? x.classIdx;
    const mi = x.method_idx_in_class ?? x.methodIdxInClass;
    const label = `${simple}.${methodName || '?'}`;
    const hex = formatSecHexOffset(off);
    return `<span class="bc-xref-ref field-xref-ref" role="link" tabindex="0" data-class-idx="${ci ?? ''}" data-method-idx="${mi ?? ''}" data-class="${escapeAttr(className)}" data-method="${escapeAttr(methodName)}" data-offset="${off ?? ''}" title="${escapeAttr(`${kind} @ ${hex}`)}">${escapeHtml(label)}</span>`;
  }).join(' ');
  const more = xrefs.length > maxShow
    ? ` <span class="bc-xref-more">+${xrefs.length - maxShow} more</span>`
    : (truncated ? ` <span class="bc-xref-more">…truncated</span>` : '');
  return `${head}<br><span class="bc-xref-label">; XREF[${xrefs.length}${truncated ? '+' : ''}]:</span> ${refs}${more}`;
}

function ensureFieldXrefsSlot() {
  if (!bytecodeListing) return null;
  let slot = bytecodeListing.querySelector('.field-xrefs-panel');
  if (!slot) {
    slot = document.createElement('div');
    slot.className = 'field-xrefs-panel method-callers-xrefs';
    bytecodeListing.prepend(slot);
  }
  return slot;
}

/** Show field signature + get/put xrefs (tree / bytecode / source click). */
async function openFieldXrefsPanel(fieldIdx, { classIdx = null } = {}) {
  const idx = Number(fieldIdx) >>> 0;
  const slot = ensureFieldXrefsSlot();
  if (!slot) return;
  const ctx = getCodeViewContext();
  const bytes = ctx?.bytes;
  if (!bytes?.length) {
    slot.hidden = true;
    slot.innerHTML = '';
    return;
  }
  const fp = fieldXrefsCacheFingerprint(bytes);
  if (fp !== fieldXrefsCacheKey) {
    fieldXrefsCache.clear();
    fieldXrefsCacheKey = fp;
  }
  const reqId = ++fieldXrefsRequestId;
  slot.hidden = false;
  slot.dataset.fieldIdx = String(idx);
  if (classIdx != null) slot.dataset.classIdx = String(classIdx);
  if (fieldXrefsCache.has(idx)) {
    slot.innerHTML = renderFieldXrefsHtml(fieldXrefsCache.get(idx));
    return;
  }
  slot.innerHTML = `<span class="bc-xref-label">; FIELD:</span> <span class="muted">finding usages…</span>`;
  try {
    const raw = await findFieldXrefsInWorker(bytes, idx);
    if (reqId !== fieldXrefsRequestId) return;
    const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
    if (!result?.ok) {
      slot.innerHTML = `<span class="bc-xref-label">; FIELD:</span> <span class="muted">${escapeHtml(result?.error || 'failed')}</span>`;
      return;
    }
    let info = result.data || result;
    if (typeof normalizeWasmResult === 'function') info = normalizeWasmResult(info) || info;
    if (Array.isArray(info?.xrefs)) {
      info = {
        ...info,
        xrefs: info.xrefs.map((u) => (u && typeof u === 'object' ? (normalizeWasmResult(u) || u) : u)),
      };
    }
    fieldXrefsCache.set(idx, info);
    if (slot.dataset.fieldIdx !== String(idx)) return;
    slot.innerHTML = renderFieldXrefsHtml(info);
  } catch (e) {
    if (reqId !== fieldXrefsRequestId) return;
    slot.innerHTML = `<span class="bc-xref-label">; FIELD:</span> <span class="muted">${escapeHtml(e?.message || String(e))}</span>`;
  }
}

function navigateToFieldXref(el) {
  if (!el) return;
  navigateToMethodCaller(el);
}

/** field_ids index from iget/iput/sget/sput insn hex. */
function fieldIndexFromBytecodeRow(row) {
  const mn = String(row?.mnemonic || '').toLowerCase();
  if (!/^(iget|iput|sget|sput)/.test(mn)) return null;
  const bytes = parseHexBytes(row?.hex);
  if (!bytes || bytes.length < 4) return null;
  const op = bytes[0];
  if (op < 0x52 || op > 0x6d) return null;
  const idx = readU16LE(bytes, 2);
  return idx != null ? idx >>> 0 : null;
}

function renderClassFieldsBannerHtml(classIdx) {
  const ctx = getCodeViewContext();
  const fields = ctx?.classes?.[classIdx]?.fields;
  if (!Array.isArray(fields) || !fields.length) return '';
  const className = ctx.classes[classIdx]?.name || '';
  const rows = fields.slice(0, 80).map((f) => {
    const name = getDisplayFieldName(f.class_name || f.className || className, f.name || '');
    const typ = shortJavaType(f.type || f.typ || '');
    const mods = String(f.modifiers || '').trim();
    const st = !mods && (f.is_static || f.isStatic) ? 'static ' : (mods ? mods + ' ' : '');
    const init = f.initial_value ?? f.initialValue;
    const fIdx = f.field_idx ?? f.fieldIdx ?? '';
    return `<button type="button" class="class-field-chip" data-field-idx="${fIdx}" title="${escapeAttr(formatFieldDeclaration(f, className))}"><span class="muted">${escapeHtml(st)}${escapeHtml(typ)}</span> ${escapeHtml(name)}${init != null && String(init) !== '' ? `<span class="class-field-init"> = ${escapeHtml(String(init))}</span>` : ''}</button>`;
  }).join('');
  const more = fields.length > 80 ? `<span class="muted">+${fields.length - 80} more</span>` : '';
  return `<div class="class-fields-banner" data-class-idx="${classIdx}"><div class="class-fields-banner-title">Fields (${fields.length})</div><div class="class-fields-banner-list">${rows}${more}</div></div>`;
}

let methodCallersRequestId = 0;
let methodCallersCacheKey = '';
const methodCallersCache = new Map();

function methodCallersCacheFingerprint(bytes) {
  if (!bytes || !bytes.length) return '0';
  const n = bytes.length;
  const a = bytes[0] | 0;
  const b = bytes[Math.min(n - 1, 100)] | 0;
  const c = bytes[Math.min(n - 1, Math.floor(n / 2))] | 0;
  return `${n}:${a}:${b}:${c}`;
}

function renderMethodCallersHtml(info) {
  const callers = Array.isArray(info?.callers) ? info.callers : [];
  const truncated = !!(info?.truncated);
  if (!callers.length) {
    return `<span class="bc-xref-label">; XREF callers[0]:</span> <span class="muted">none</span>`;
  }
  const maxShow = 12;
  const refs = callers.slice(0, maxShow).map((c) => {
    const className = c.class_name || c.className || '';
    const methodName = c.method_name || c.methodName || '';
    const simple = className.split('.').pop() || className || '?';
    const kind = c.invoke_kind || c.invokeKind || 'invoke';
    const off = c.offset;
    const ci = c.class_idx ?? c.classIdx;
    const mi = c.method_idx_in_class ?? c.methodIdxInClass;
    const label = `${simple}.${methodName || '?'}`;
    const hex = formatSecHexOffset(off);
    return `<span class="bc-xref-ref method-caller-ref" role="link" tabindex="0" data-class-idx="${ci ?? ''}" data-method-idx="${mi ?? ''}" data-class="${escapeAttr(className)}" data-method="${escapeAttr(methodName)}" data-offset="${off ?? ''}" title="${escapeAttr(`${kind} @ ${hex}`)}">${escapeHtml(label)}</span>`;
  }).join(' ');
  const more = callers.length > maxShow
    ? ` <span class="bc-xref-more">+${callers.length - maxShow} more</span>`
    : (truncated ? ` <span class="bc-xref-more">…truncated</span>` : '');
  return `<span class="bc-xref-label">; XREF callers[${callers.length}${truncated ? '+' : ''}]:</span> ${refs}${more}`;
}

function renderMethodCalleesHtml(info) {
  const callees = Array.isArray(info?.callees) ? info.callees : [];
  const truncated = !!(info?.truncated);
  if (!callees.length) {
    return `<span class="bc-xref-label">; XREF uses[0]:</span> <span class="muted">none</span>`;
  }
  const maxShow = 12;
  const refs = callees.slice(0, maxShow).map((c) => {
    const className = c.class_name || c.className || '';
    const methodName = c.method_name || c.methodName || '';
    const simple = className.split('.').pop() || className || '?';
    const kind = c.invoke_kind || c.invokeKind || 'invoke';
    const off = c.offset;
    const label = `${simple}.${methodName || '?'}`;
    const hex = formatSecHexOffset(off);
    return `<span class="bc-xref-ref method-callee-ref" role="link" tabindex="0" data-class="${escapeAttr(className)}" data-method="${escapeAttr(methodName)}" data-offset="${off ?? ''}" title="${escapeAttr(`${kind} @ ${hex}`)}">${escapeHtml(label)}</span>`;
  }).join(' ');
  const more = callees.length > maxShow
    ? ` <span class="bc-xref-more">+${callees.length - maxShow} more</span>`
    : (truncated ? ` <span class="bc-xref-more">…truncated</span>` : '');
  return `<span class="bc-xref-label">; XREF uses[${callees.length}${truncated ? '+' : ''}]:</span> ${refs}${more}`;
}

function renderMethodXrefsBundleHtml(callersInfo, calleesInfo) {
  return `${renderMethodCallersHtml(callersInfo)}<br>${renderMethodCalleesHtml(calleesInfo)}`;
}

/** Load method callers + callees and inject under the method header (async, worker). */
async function loadAndShowMethodCallers(classIdx, methodIdx) {
  const slot = bytecodeListing?.querySelector(
    `.method-callers-xrefs[data-class-idx="${CSS.escape(String(classIdx))}"][data-method-idx="${CSS.escape(String(methodIdx))}"]`
  );
  if (!slot) return;
  const ctx = getCodeViewContext();
  const bytes = ctx?.bytes;
  if (!bytes?.length) {
    slot.hidden = true;
    slot.innerHTML = '';
    return;
  }
  const fp = methodCallersCacheFingerprint(bytes);
  if (fp !== methodCallersCacheKey) {
    methodCallersCache.clear();
    methodCallersCacheKey = fp;
  }
  const cacheKey = `${classIdx}:${methodIdx}`;
  const reqId = ++methodCallersRequestId;
  slot.hidden = false;
  if (methodCallersCache.has(cacheKey)) {
    const cached = methodCallersCache.get(cacheKey);
    slot.innerHTML = renderMethodXrefsBundleHtml(cached.callers, cached.callees);
    return;
  }
  slot.innerHTML = `<span class="bc-xref-label">; XREF:</span> <span class="muted">finding usages…</span>`;
  try {
    const [rawCallers, rawCallees] = await Promise.all([
      findMethodCallersInWorker(bytes, classIdx, methodIdx),
      findMethodCalleesInWorker(bytes, classIdx, methodIdx),
    ]);
    if (reqId !== methodCallersRequestId) return;
    if (codeViewClassIdx !== classIdx || codeViewMethodIdx !== methodIdx) return;
    const still = bytecodeListing?.querySelector(
      `.method-callers-xrefs[data-class-idx="${CSS.escape(String(classIdx))}"][data-method-idx="${CSS.escape(String(methodIdx))}"]`
    );
    if (!still) return;
    const normalize = (raw) => {
      const result = typeof normalizeWasmResult === 'function' ? normalizeWasmResult(raw) : raw;
      if (!result?.ok) return { error: result?.error || 'failed' };
      let info = result.data || result;
      if (typeof normalizeWasmResult === 'function') info = normalizeWasmResult(info) || info;
      return info;
    };
    const callersInfo = normalize(rawCallers);
    const calleesInfo = normalize(rawCallees);
    if (callersInfo.error && calleesInfo.error) {
      still.innerHTML = `<span class="bc-xref-label">; XREF:</span> <span class="muted">${escapeHtml(callersInfo.error)}</span>`;
      return;
    }
    const bundle = {
      callers: callersInfo.error ? { callers: [], truncated: false } : callersInfo,
      callees: calleesInfo.error ? { callees: [], truncated: false } : calleesInfo,
    };
    methodCallersCache.set(cacheKey, bundle);
    still.innerHTML = renderMethodXrefsBundleHtml(bundle.callers, bundle.callees);
  } catch (e) {
    if (reqId !== methodCallersRequestId) return;
    const still = bytecodeListing?.querySelector(
      `.method-callers-xrefs[data-class-idx="${CSS.escape(String(classIdx))}"][data-method-idx="${CSS.escape(String(methodIdx))}"]`
    );
    if (!still) return;
    still.innerHTML = `<span class="bc-xref-label">; XREF:</span> <span class="muted">${escapeHtml(e?.message || String(e))}</span>`;
  }
}

function navigateToMethodCaller(el) {
  if (!el) return;
  const classIdx = parseInt(el.getAttribute('data-class-idx'), 10);
  const methodIdx = parseInt(el.getAttribute('data-method-idx'), 10);
  const offsetRaw = el.getAttribute('data-offset');
  const offset = offsetRaw !== '' && offsetRaw != null ? parseInt(offsetRaw, 10) : null;
  if (Number.isFinite(offset)) queueSecurityBytecodeHighlight(offset);
  if (!Number.isNaN(classIdx) && !Number.isNaN(methodIdx)) {
    selectCodeViewMethod(classIdx, methodIdx, { expandCfg: true });
    return;
  }
  const className = el.getAttribute('data-class') || '';
  const methodName = el.getAttribute('data-method') || '';
  if (className) {
    navigateToSecurityFinding(className, methodName, '', {
      offset: Number.isFinite(offset) ? offset : undefined,
      hint: '',
    });
  }
}

function setBytecodeListingHtml(html, opts = {}) {
  if (!bytecodeListing) return;
  const empty = !!opts.empty;
  bytecodeListing.innerHTML = html;
  clearBytecodeNavStack();
  if (bytecodeColHeader) bytecodeColHeader.setAttribute('aria-hidden', empty ? 'true' : 'false');
  if (bytecodeMeta) {
    if (typeof opts.meta === 'string') bytecodeMeta.textContent = opts.meta;
    else if (typeof opts.insnCount === 'number') bytecodeMeta.textContent = opts.insnCount ? `${opts.insnCount} insn` : '';
    else bytecodeMeta.textContent = '';
  }
  if (sourceMeta && typeof opts.sourceMeta === 'string') sourceMeta.textContent = opts.sourceMeta;
  applyBytecodeSearch();
  // Always start at the top so the first instruction isn't stuck under sticky chrome
  // from a previous method's scroll position (unless a highlight jump will run).
  if (!opts.keepScroll) {
    const wrap = document.getElementById('bytecode-listing-wrap');
    if (wrap) wrap.scrollTop = 0;
  }
  if (pendingSecurityBytecodeHighlight != null) {
    requestAnimationFrame(() => applySecurityBytecodeHighlight());
    setTimeout(() => applySecurityBytecodeHighlight(), 150);
  }
  requestAnimationFrame(() => fillCachedBytecodeStringXrefs());
}

/** Instantly fill string-xref rows already present in the Strings-tab usage cache. */
function fillCachedBytecodeStringXrefs() {
  if (!bytecodeListing || !stringsUsageCache?.size) return;
  const seen = new Set();
  for (const slot of bytecodeListing.querySelectorAll('.bytecode-string-xref.is-pending[data-string-idx]')) {
    const idx = parseInt(slot.getAttribute('data-string-idx'), 10);
    if (Number.isNaN(idx) || seen.has(idx) || !stringsUsageCache.has(idx)) continue;
    seen.add(idx);
    loadBytecodeStringXrefs(idx);
  }
}

function countInsnInHtml(html) {
  return (String(html).match(/class="bytecode-line"/g) || []).length;
}

function setDockCollapsed(pane, collapsed, storageKey) {
  if (!pane) return;
  // Collapsing a maximized pane restores the normal layout first
  const which = paneMaximizeKeyForId(pane.id);
  if (collapsed && which && getMaximizedPane() === which) {
    setPaneMaximized(null, { fit: false });
  }
  pane.dataset.collapsed = collapsed ? 'true' : 'false';
  const btn = pane.querySelector('.dock-toggle');
  if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  if (storageKey) {
    try { localStorage.setItem(storageKey, collapsed ? '0' : '1'); } catch (_) {}
  }
}

function updateWorkspaceResizers() {
  const workspace = document.getElementById('code-workspace');
  const cfg = document.getElementById('cfg-pane');
  const bc = document.getElementById('bytecode-pane');
  const src = document.getElementById('source-pane');
  const emu = document.getElementById('bytecode-emulator-area');
  const cfgRes = document.getElementById('resizer-source-cfg');
  const srcRes = document.getElementById('resizer-cfg-bytecode');
  const emuRes = document.getElementById('resizer-emulator');
  const maximized = !!getMaximizedPane();
  const cfgAvailable = cfg && !cfg.hidden && cfgAppliesToCurrentFile();
  if (cfgRes) cfgRes.hidden = maximized || !(cfgAvailable && cfg.dataset.collapsed === 'false' && bc && bc.dataset.collapsed === 'false');
  if (srcRes) srcRes.hidden = maximized || !(src && src.dataset.collapsed === 'false');
  if (emuRes) emuRes.hidden = maximized || !(emu && emu.dataset.collapsed === 'false');
}

const PANE_MAXIMIZE_STORAGE_KEY = 'droid2web-pane-maximized';
const PANE_MAXIMIZE_META = {
  cfg: {
    paneId: 'cfg-pane',
    btnId: 'cfg-maximize-btn',
    label: 'CFG',
    available: () => cfgAppliesToCurrentFile() && !document.getElementById('cfg-pane')?.hidden,
    openKey: 'droid2web-cfg-open',
  },
  bytecode: {
    paneId: 'bytecode-pane',
    btnId: 'bytecode-maximize-btn',
    label: 'bytecode',
    available: () => true,
    openKey: 'droid2web-bytecode-open',
  },
  source: {
    paneId: 'source-pane',
    btnId: 'source-maximize-btn',
    label: 'source',
    available: () => true,
    openKey: 'droid2web-source-open',
  },
};

function paneMaximizeKeyForId(paneId) {
  if (paneId === 'cfg-pane') return 'cfg';
  if (paneId === 'bytecode-pane') return 'bytecode';
  if (paneId === 'source-pane') return 'source';
  return null;
}

function getMaximizedPane() {
  const workspace = document.getElementById('code-workspace');
  if (!workspace) return null;
  if (workspace.classList.contains('pane-maximized-cfg')) return 'cfg';
  if (workspace.classList.contains('pane-maximized-bytecode')) return 'bytecode';
  if (workspace.classList.contains('pane-maximized-source')) return 'source';
  // Legacy class from earlier CFG-only maximize
  if (workspace.classList.contains('cfg-maximized')) return 'cfg';
  return null;
}

function isCfgMaximized() {
  return getMaximizedPane() === 'cfg';
}

function syncPaneMaximizeButtons() {
  const current = getMaximizedPane();
  const cfgFs = isCfgFullscreen();
  for (const [key, meta] of Object.entries(PANE_MAXIMIZE_META)) {
    const btn = document.getElementById(meta.btnId);
    if (!btn) continue;
    const on = key === 'cfg' ? cfgFs || current === 'cfg' : current === key;
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (key === 'cfg') {
      btn.title = on ? 'Exit CFG fullscreen (Esc)' : 'Fullscreen CFG (Esc to exit)';
      btn.setAttribute('aria-label', on ? 'Exit CFG fullscreen' : 'Fullscreen CFG');
    } else {
      btn.title = on
        ? `Restore ${meta.label} (Esc)`
        : `Maximize ${meta.label} (Esc to restore)`;
      btn.setAttribute('aria-label', on ? `Restore ${meta.label}` : `Maximize ${meta.label}`);
    }
  }
  const fsBtn = document.getElementById('cfg-fullscreen-btn');
  if (fsBtn) {
    fsBtn.setAttribute('aria-pressed', cfgFs ? 'true' : 'false');
    fsBtn.textContent = cfgFs ? 'Exit' : 'Fullscreen';
    fsBtn.title = cfgFs ? 'Exit CFG fullscreen (Esc)' : 'Fullscreen CFG (Esc to exit)';
  }
}

function isCfgFullscreen() {
  return document.body.classList.contains('cfg-fullscreen')
    || document.fullscreenElement === document.getElementById('cfg-pane')
    || document.webkitFullscreenElement === document.getElementById('cfg-pane');
}

function fitCfgAfterLayout() {
  if (!cfgNetwork || !cfgAppliesToCurrentFile()) return;
  setTimeout(() => {
    try { cfgNetwork.redraw(); } catch (_) {}
    fitCfgGraph();
  }, 160);
}

/** Enter/exit CFG fullscreen (hides app chrome; uses browser Fullscreen API when available). */
async function setCfgFullscreen(on, { persist = true } = {}) {
  const pane = document.getElementById('cfg-pane');
  const want = !!on;
  if (want) {
    if (pane?.dataset.collapsed === 'true') {
      setDockCollapsed(pane, false, 'droid2web-cfg-open');
    }
    setPaneMaximized('cfg', { persist, fit: false });
    document.body.classList.add('cfg-fullscreen');
    try {
      const req = pane?.requestFullscreen || pane?.webkitRequestFullscreen;
      if (pane && req && !document.fullscreenElement && !document.webkitFullscreenElement) {
        await Promise.resolve(req.call(pane));
      }
    } catch (_) {
      /* CSS fullscreen still applies */
    }
    syncPaneMaximizeButtons();
    fitCfgAfterLayout();
    return;
  }
  document.body.classList.remove('cfg-fullscreen');
  try {
    if (document.fullscreenElement || document.webkitFullscreenElement) {
      const exit = document.exitFullscreen || document.webkitExitFullscreen;
      if (exit) await Promise.resolve(exit.call(document));
    }
  } catch (_) { /* ignore */ }
  setPaneMaximized(null, { persist, fit: true });
  syncPaneMaximizeButtons();
}

function toggleCfgFullscreen() {
  setCfgFullscreen(!isCfgFullscreen());
}

/** Maximize one workspace pane (`cfg` | `bytecode` | `source`), or pass null to restore. */
function setPaneMaximized(which, { persist = true, fit = true } = {}) {
  const workspace = document.getElementById('code-workspace');
  if (!workspace) return;
  let want = which && PANE_MAXIMIZE_META[which] ? which : null;
  if (want && typeof PANE_MAXIMIZE_META[want].available === 'function' && !PANE_MAXIMIZE_META[want].available()) {
    want = null;
  }
  // Leaving CFG maximize also leaves app fullscreen chrome
  if (!want || want !== 'cfg') {
    document.body.classList.remove('cfg-fullscreen');
  }
  workspace.classList.remove(
    'pane-maximized',
    'pane-maximized-cfg',
    'pane-maximized-bytecode',
    'pane-maximized-source',
    'cfg-maximized'
  );
  if (want) {
    const meta = PANE_MAXIMIZE_META[want];
    const pane = document.getElementById(meta.paneId);
    if (pane?.dataset.collapsed === 'true') {
      setDockCollapsed(pane, false, meta.openKey);
    }
    workspace.classList.add('pane-maximized', `pane-maximized-${want}`);
    if (want === 'cfg') {
      document.body.classList.add('cfg-fullscreen');
    }
  }
  syncPaneMaximizeButtons();
  updateWorkspaceResizers();
  if (persist) {
    try { localStorage.setItem(PANE_MAXIMIZE_STORAGE_KEY, want || ''); } catch (_) {}
    try { localStorage.removeItem('droid2web-cfg-maximized'); } catch (_) {}
  }
  if (fit && (want === 'cfg' || (!want && cfgNetwork && cfgAppliesToCurrentFile()))) {
    fitCfgAfterLayout();
  }
}

function setCfgMaximized(maximized, opts) {
  if (maximized) setCfgFullscreen(true, opts);
  else setCfgFullscreen(false, opts);
}

function toggleCfgMaximized() {
  toggleCfgFullscreen();
}

function togglePaneMaximized(which) {
  if (which === 'cfg') {
    toggleCfgFullscreen();
    return;
  }
  // Exiting another pane's maximize shouldn't leave CFG fullscreen residue
  if (document.body.classList.contains('cfg-fullscreen')) {
    document.body.classList.remove('cfg-fullscreen');
  }
  setPaneMaximized(getMaximizedPane() === which ? null : which);
}

function restorePaneMaximizedPreference() {
  let saved = null;
  try { saved = localStorage.getItem(PANE_MAXIMIZE_STORAGE_KEY); } catch (_) {}
  if (!saved) {
    try {
      if (localStorage.getItem('droid2web-cfg-maximized') === '1') saved = 'cfg';
    } catch (_) {}
  }
  if (saved === 'cfg') {
    // Prefer immersive CFG on restore, without forcing browser Fullscreen API on load
    setPaneMaximized('cfg', { persist: false, fit: false });
    document.body.classList.add('cfg-fullscreen');
    syncPaneMaximizeButtons();
    return;
  }
  if (saved && PANE_MAXIMIZE_META[saved]) {
    setPaneMaximized(saved, { persist: false, fit: false });
    return;
  }
  syncPaneMaximizeButtons();
}
restorePaneMaximizedPreference();

function showEmulatorDock(expand = true) {
  const pane = document.getElementById('bytecode-emulator-area');
  if (!pane) return;
  pane.dataset.active = 'true';
  if (expand) {
    setDockCollapsed(pane, false, 'droid2web-emulator-open');
    updateWorkspaceResizers();
  }
}

function hideEmulatorResults() {
  const pane = document.getElementById('bytecode-emulator-area');
  if (pane) pane.dataset.active = 'false';
  if (bytecodeStepBar) bytecodeStepBar.innerHTML = '';
  if (bytecodeStatePanel) {
    bytecodeStatePanel.innerHTML = '<div class="code-empty"><div class="code-empty-title">Ready to emulate</div><div class="code-empty-hint muted">Select a method, then Step or Run</div></div>';
  }
}

function applyHexVisibility(show) {
  const workspace = document.getElementById('code-workspace');
  if (!workspace) return;
  workspace.classList.toggle('hide-hex', !show);
  try { localStorage.setItem('droid2web-show-hex', show ? '1' : '0'); } catch (_) {}
}

let bytecodeSearchQuery = '';
let bytecodeSearchMatchIndex = 0;
let bytecodeSearchMatches = [];

function applyBytecodeSearch() {
  if (!bytecodeListing) return;
  const q = (bytecodeSearchQuery || '').trim().toLowerCase();
  const lines = Array.from(bytecodeListing.querySelectorAll('.bytecode-line'));
  bytecodeSearchMatches = [];
  lines.forEach((line) => {
    line.classList.remove('bytecode-search-hit', 'current');
    if (!q) return;
    const hay = (line.getAttribute('data-search') || line.textContent || '').toLowerCase();
    if (hay.includes(q)) {
      line.classList.add('bytecode-search-hit');
      bytecodeSearchMatches.push(line);
    }
  });
  if (bytecodeSearchCount) {
    bytecodeSearchCount.textContent = q
      ? (bytecodeSearchMatches.length ? `${Math.min(bytecodeSearchMatchIndex + 1, bytecodeSearchMatches.length)} / ${bytecodeSearchMatches.length}` : '0 matches')
      : '';
  }
  if (bytecodeSearchMatches.length > 0) {
    bytecodeSearchMatchIndex = ((bytecodeSearchMatchIndex % bytecodeSearchMatches.length) + bytecodeSearchMatches.length) % bytecodeSearchMatches.length;
    bytecodeSearchMatches.forEach((el, i) => el.classList.toggle('current', i === bytecodeSearchMatchIndex));
    scrollBytecodeLineIntoView(bytecodeSearchMatches[bytecodeSearchMatchIndex], { block: 'nearest', behavior: 'smooth' });
  }
}

function updateCodeNavSeps() {
  const pkgVisible = codePackageWrap && codePackageWrap.style.display !== 'none';
  const classVisible = classSelectorWrap && classSelectorWrap.style.display !== 'none';
  const sepPkg = document.getElementById('code-nav-sep-pkg');
  const sepClass = document.getElementById('code-nav-sep-class');
  if (sepPkg) sepPkg.hidden = !pkgVisible;
  if (sepClass) sepClass.hidden = !(pkgVisible || classVisible);
}

/** Pretty-print XML with indentation; break long tags so attributes stack under the element. */
function formatXmlPretty(xml) {
  if (!xml || typeof xml !== 'string') return '';
  const trimmed = xml.trim();
  if (!trimmed) return '';

  // Attr-per-line reformatting is O(tags×attrs) and expands size a lot.
  // Use the fast path earlier — still readable, much cheaper to mount.
  if (trimmed.length >= 36000) {
    return formatXmlPrettyFast(trimmed);
  }

  const ATTR_BREAK_THRESHOLD = 72;

  function formatOpeningTag(tag, baseIndent) {
    const pad = '  '.repeat(baseIndent);
    const attrPad = '  '.repeat(baseIndent + 1);
    // <?xml ...?>, <!DOCTYPE ...>, comments, closing tags — keep as-is
    if (tag.startsWith('<?') || tag.startsWith('<!') || tag.startsWith('<!--') || tag.startsWith('</')) {
      return pad + tag;
    }
    const m = tag.match(/^<(\??)([\w.:-]+)(\s[\s\S]*?)?(\/?\s*)>$/);
    if (!m) return pad + tag;
    const bang = m[1] || '';
    const name = m[2];
    const attrBlob = (m[3] || '').trim();
    const selfClose = /\//.test(m[4] || '');
    if (!attrBlob) {
      return pad + `<${bang}${name}${selfClose ? ' /' : ''}>`;
    }
    const attrs = [];
    const attrRe = /([\w.:-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let am;
    while ((am = attrRe.exec(attrBlob)) !== null) {
      const q = am[2].startsWith("'") ? "'" : '"';
      const val = am[3] !== undefined ? am[3] : am[4];
      attrs.push(`${am[1]}=${q}${val}${q}`);
    }
    const oneLine = `<${bang}${name}${attrs.length ? ' ' + attrs.join(' ') : ''}${selfClose ? ' /' : ''}>`;
    if (attrs.length <= 1 && (pad.length + oneLine.length) <= ATTR_BREAK_THRESHOLD) {
      return pad + oneLine;
    }
    if (!attrs.length) return pad + oneLine;
    // Android Studio style: one attr per line, `>` / `/>` on the last attr line
    const lines = [`${pad}<${bang}${name}`];
    attrs.forEach((a, i) => {
      const isLast = i === attrs.length - 1;
      lines.push(`${attrPad}${a}${isLast ? (selfClose ? ' />' : '>') : ''}`);
    });
    return lines.join('\n');
  }

  let indent = 0;
  const parts = trimmed.split(/(<[^>]+>)/g).filter(Boolean);
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith('</')) {
      indent = Math.max(0, indent - 1);
      out.push('  '.repeat(indent) + p);
    } else if (p.startsWith('<?') || p.startsWith('<!') || p.startsWith('<!--')) {
      out.push(formatOpeningTag(p, indent));
    } else if (p.startsWith('<')) {
      const selfClosing = /\/\s*>$/.test(p);
      out.push(formatOpeningTag(p, indent));
      if (!selfClosing) indent++;
    } else {
      const line = p.trim();
      if (line) out.push('  '.repeat(indent) + line);
    }
  }
  return out.join('\n');
}

/** Cheap pretty-printer: indent tags, keep attrs on one line (no per-attr wrapping). */
function formatXmlPrettyFast(xml) {
  const s = String(xml || '').trim();
  if (!s) return '';
  const parts = s.split(/(<[^>]+>)/g).filter(Boolean);
  const out = [];
  const pads = ['', '  ', '    ', '      ', '        ', '          ', '            ', '              '];
  const pad = (n) => {
    const d = Math.max(0, n | 0);
    while (pads.length <= d) pads.push('  '.repeat(pads.length));
    return pads[d];
  };
  let indent = 0;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith('</')) {
      indent = Math.max(0, indent - 1);
      out.push(pad(indent), p, '\n');
    } else if (p.startsWith('<?') || p.startsWith('<!') || p.startsWith('<!--')) {
      out.push(pad(indent), p, '\n');
    } else if (p.startsWith('<')) {
      const selfClosing = /\/\s*>$/.test(p);
      out.push(pad(indent), p, '\n');
      if (!selfClosing) indent++;
    } else {
      const line = p.trim();
      if (line) out.push(pad(indent), line, '\n');
    }
  }
  // Drop trailing newline for stable line counts.
  if (out.length && out[out.length - 1] === '\n') out.pop();
  return out.join('');
}

function countXmlNewlines(s) {
  if (!s) return 0;
  let n = 1;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) === 10) n++;
  }
  return n;
}

function escapeXmlHighlight(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Highlight attribute values; mark resource refs / hex IDs. */
function highlightXmlAttrValue(val) {
  const esc = escapeXmlHighlight(val);
  if (/^@\+?[\w.]+:[\w./]+$/.test(val) || /^@[\w./]+$/.test(val) || /^0x[0-9a-fA-F]+$/.test(val) || /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(val)) {
    return '<span class="xml-value xml-res-ref">' + esc + '</span>';
  }
  if (/^[a-zA-Z_][\w.]*(\.[a-zA-Z_][\w.]*)+$/.test(val) || (val.startsWith('.') && val.length > 1)) {
    return '<span class="xml-value xml-class-ref">' + esc + '</span>';
  }
  return '<span class="xml-value">' + esc + '</span>';
}

/**
 * Return HTML string with XML syntax highlighting (safe: escapes content).
 * @param {{ lineNumbers?: boolean, preserveNewlines?: boolean }} [opts]
 *   lineNumbers: wrap each line in .xml-line (expensive DOM — avoid on large manifests)
 *   preserveNewlines: keep \n for mounting inside <pre> (light mode)
 */
function highlightXml(xml, opts = {}) {
  if (!xml || typeof xml !== 'string') return '';
  const lineNumbers = opts.lineNumbers !== false;
  const esc = escapeXmlHighlight;
  const tokens = xml.split(/(<!--[\s\S]*?-->|<[^>]+>)/g);
  const parts = [];
  for (let ti = 0; ti < tokens.length; ti++) {
    const t = tokens[ti];
    if (!t) continue;
    if (t.startsWith('<!--')) {
      parts.push('<span class="xml-comment">', esc(t), '</span>');
    } else if (t.startsWith('<')) {
      const tagMatch = t.match(/^<\/?(\??)([\w.:-]+)/);
      const rest = tagMatch ? t.slice(tagMatch[0].length) : t;
      if (tagMatch) {
        const optionalQ = tagMatch[1];
        const name = tagMatch[2];
        const isClose = t.startsWith('</');
        parts.push('&lt;', isClose ? '/' : '', optionalQ, '<span class="xml-tag">', esc(name), '</span>');
      } else {
        parts.push(esc(t));
        continue;
      }
      const attrRe = /([\w.:-]+)=("([^"]*)"|'([^']*)')/g;
      let lastIdx = 0;
      let m;
      while ((m = attrRe.exec(rest)) !== null) {
        if (m.index > lastIdx) parts.push(esc(rest.slice(lastIdx, m.index)));
        const val = m[3] !== undefined ? m[3] : m[4];
        const quote = m[3] !== undefined ? '"' : "'";
        const attrName = m[1];
        const attrCls = attrName.includes(':') ? 'xml-attr xml-attr-ns' : 'xml-attr';
        parts.push('<span class="', attrCls, '">', esc(attrName), '</span>=', quote, highlightXmlAttrValue(val), quote);
        lastIdx = attrRe.lastIndex;
      }
      if (lastIdx < rest.length) parts.push(esc(rest.slice(lastIdx)));
    } else {
      parts.push('<span class="xml-text">', esc(t), '</span>');
    }
  }
  const flat = parts.join('');
  if (!lineNumbers) {
    if (opts.preserveNewlines) return flat;
    return flat.replace(/\n/g, '<br>\n');
  }
  const lines = flat.split('\n');
  const width = Math.max(2, String(lines.length).length);
  const out = new Array(lines.length);
  const lnStyle = `width:${width}ch`;
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    out[i] = `<div class="xml-line" data-line="${n}" id="xml-line-${n}"><span class="xml-ln" style="${lnStyle}">${n}</span><span class="xml-lc">${lines[i] || ' '}</span></div>`;
  }
  return out.join('');
}

/** Outline entries from pretty-printed XML (opening tags only). */
function buildXmlOutline(pretty) {
  if (!pretty) return [];
  const lines = pretty.split('\n');
  const outline = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trimStart();
    if (!trimmed.startsWith('<') || trimmed.startsWith('</') || trimmed.startsWith('<?') || trimmed.startsWith('<!') || trimmed.startsWith('<!--')) continue;
    const m = raw.match(/^(\s*)<([\w.:-]+)/);
    if (!m) continue;
    const depth = Math.floor(m[1].length / 2);
    const name = m[2];
    // Peek ahead for attrs when the opening tag is split across lines
    let window = raw;
    for (let j = i + 1; j < Math.min(lines.length, i + 12); j++) {
      if (/>/.test(window)) break;
      window += '\n' + lines[j];
    }
    let hint = '';
    const nameAttr = window.match(/\b(?:android:)?name="([^"]*)"/);
    const pkgAttr = window.match(/\bpackage="([^"]*)"/);
    const typeAttr = window.match(/\btype="([^"]*)"/);
    if (nameAttr) hint = nameAttr[1];
    else if (pkgAttr) hint = pkgAttr[1];
    else if (typeAttr) hint = typeAttr[1];
    outline.push({ line: i + 1, depth, name, hint });
  }
  return outline;
}

/** Extract useful meta from AXML parse result and/or XML text. */
function extractAxmlMeta(xml, data) {
  const src = typeof xml === 'string' ? xml : '';
  const pkg = data?.package || (src.match(/\bpackage="([^"]+)"/) || [])[1] || null;
  const versionName = data?.version_name || (src.match(/\b(?:android:)?versionName="([^"]*)"/) || [])[1] || null;
  const versionCode = data?.version_code || (src.match(/\b(?:android:)?versionCode="([^"]*)"/) || [])[1] || null;
  let permissions = Array.isArray(data?.permissions) ? data.permissions.slice() : [];
  if (!permissions.length && src) {
    const re = /uses-permission[^>]*\b(?:android:)?name="([^"]+)"/g;
    let m;
    const set = new Set();
    while ((m = re.exec(src)) !== null) set.add(m[1]);
    permissions = [...set].sort();
  }
  const rootTag = data?.root_tag || (src.match(/<(manifest|[\w.:-]+)[\s>]/) || [])[1] || null;
  return {
    package: pkg,
    is_packed: !!data?.is_packed,
    version_name: versionName || null,
    version_code: versionCode || null,
    permissions,
    root_tag: rootTag,
  };
}

function buildArscOverviewXml(packages) {
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const pkgs = packages || [];
  let out = '<?xml version="1.0" encoding="utf-8"?>\n<!-- resources.arsc overview (package / type names) -->\n<resources>\n';
  for (const p of pkgs) {
    const name = typeof p === 'string' ? p : (p?.name ?? '');
    const types = Array.isArray(p?.types) ? [...p.types].sort() : [];
    out += `  <package name="${esc(name)}">\n`;
    for (const t of types) {
      out += `    <public type="${esc(t)}"/>\n`;
    }
    out += '  </package>\n';
  }
  out += '</resources>\n';
  return out;
}

function scrollXmlLineIntoView(container, line) {
  if (!container || !line) return;
  const el = container.querySelector(`.xml-line[data-line="${line}"]`);
  if (el) {
    container.querySelectorAll('.xml-line.xml-line-active').forEach((n) => n.classList.remove('xml-line-active'));
    el.classList.add('xml-line-active');
    el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    return;
  }
  // Plain / light mode: approximate scroll by line height.
  const cs = getComputedStyle(container);
  const lh = parseFloat(cs.lineHeight) || (parseFloat(cs.fontSize) || 12) * 1.35;
  const scroller = container.closest('.res-viewer-scroll') || container;
  scroller.scrollTop = Math.max(0, (line - 1) * lh - scroller.clientHeight * 0.35);
}

function filterXmlViewerLines(container, query) {
  if (!container) return { total: 0, matches: 0 };
  const q = (query || '').trim().toLowerCase();
  const lines = container.querySelectorAll('.xml-line');
  if (!lines.length) {
    const total = countXmlNewlines(container.textContent || '');
    return { total, matches: q ? 0 : total };
  }
  let matches = 0;
  lines.forEach((line) => {
    const text = (line.querySelector('.xml-lc')?.textContent || '').toLowerCase();
    const hit = !q || text.includes(q);
    line.classList.toggle('xml-line-hidden', !!q && !hit);
    line.classList.toggle('xml-line-match', !!q && hit);
    if (q && hit) matches++;
  });
  if (q && matches) {
    const first = container.querySelector('.xml-line-match:not(.xml-line-hidden)');
    if (first) first.scrollIntoView({ block: 'nearest' });
  }
  return { total: lines.length, matches: q ? matches : lines.length };
}

/** Cache last mounted XML so remounts (tab switches / refresh) stay cheap. */
let xmlViewerMountCache = null;

function xmlViewerCacheKey(xml) {
  const n = xml.length;
  if (!n) return '0';
  return `${n}:${xml.charCodeAt(0)}:${xml.charCodeAt(n >> 1)}:${xml.charCodeAt(n - 1)}:${xml.slice(0, 40)}:${xml.slice(-24)}`;
}

/**
 * Mount a rich XML viewer into `host` (or replace `codeEl` content).
 * options: { xml, meta, title, showOutlineTarget, onReady }
 *
 * Modes (picked by size):
 *   full  — highlighted + per-line DOM (filterable) — small XML only
 *   light — highlighted spans on the <pre> (indented; used for mid + Facebook-scale)
 *
 * Large manifests paint indented text first, then upgrade to light highlight idle.
 */
let xmlViewerMountGen = 0;
function mountXmlViewer(codeEl, toolbarEl, xml, options = {}) {
  const meta = options.meta || extractAxmlMeta(xml, options.data);
  if (!xml || xml === '(empty)' || (typeof xml === 'string' && (xml.startsWith('(') || xml.startsWith('No ')))) {
    if (toolbarEl) {
      toolbarEl.hidden = true;
      toolbarEl.innerHTML = '';
    }
    if (codeEl) codeEl.innerHTML = `<span class="muted">${escapeHtml(xml || '')}</span>`;
    return { pretty: '', meta };
  }
  const tAll = nowMs();
  const cacheKey = xmlViewerCacheKey(xml);
  const mountGen = ++xmlViewerMountGen;

  let pretty;
  let lineCount;
  let mode;
  let outline = [];
  let fromCache = false;
  let cachedHtml = '';

  if (xmlViewerMountCache && xmlViewerMountCache.key === cacheKey) {
    // Drop obsolete "plain" cache entries from older builds.
    if (xmlViewerMountCache.mode === 'plain') {
      xmlViewerMountCache = null;
    } else {
      pretty = xmlViewerMountCache.pretty;
      lineCount = xmlViewerMountCache.lineCount;
      mode = xmlViewerMountCache.mode;
      outline = xmlViewerMountCache.outline || [];
      cachedHtml = xmlViewerMountCache.html || '';
      fromCache = true;
    }
  }
  if (!fromCache) {
    pretty = measureSync(
      'formatXmlPretty',
      () => formatXmlPretty(xml),
      `${formatCount(xml.length)} chars`
    );
    lineCount = countXmlNewlines(pretty);
    // Always keep indentation; only drop per-line DOM on larger XML.
    mode = (pretty.length >= 24000 || lineCount >= 700) ? 'light' : 'full';
  }

  const light = mode === 'light';
  // Defer highlight for big manifests so first paint shows indented structure.
  const deferHighlight = light && !cachedHtml && pretty.length >= 48000;

  function applyLightHtml(html) {
    if (!codeEl || xmlViewerMountGen !== mountGen) return;
    codeEl.classList.add('res-xml', 'manifest-xml', 'xml-light-mode');
    codeEl.classList.remove('xml-plain-mode');
    codeEl.innerHTML = html;
    const chip = toolbarEl?.querySelector('.res-chip-xml-mode');
    if (chip) {
      chip.textContent = 'formatted';
      chip.classList.remove('res-chip-warn');
      chip.title = 'Indented + syntax highlighted (fast path for large manifests)';
    }
    const countEl = toolbarEl?.querySelector('.res-xml-search-count');
    if (countEl) countEl.textContent = `${lineCount} lines`;
  }

  if (codeEl) {
    codeEl.classList.add('res-xml', 'manifest-xml');
    codeEl.classList.toggle('xml-light-mode', light && !deferHighlight);
    codeEl.classList.toggle('xml-plain-mode', deferHighlight);
    if (light) {
      if (cachedHtml) {
        measureSync('highlightXml+DOM-light-cache', () => applyLightHtml(cachedHtml), `${formatCount(lineCount)} lines`);
      } else if (deferHighlight) {
        // Immediate: indented plain text (looks structured like other manifests).
        measureSync('mountXmlViewer-indent', () => {
          codeEl.textContent = pretty;
        }, `${formatCount(lineCount)} lines`);
        const schedule = typeof requestIdleCallback === 'function'
          ? (fn) => requestIdleCallback(fn, { timeout: 900 })
          : (fn) => setTimeout(fn, 32);
        schedule(() => {
          if (xmlViewerMountGen !== mountGen) return;
          let html = '';
          try {
            html = measureSync(
              'highlightXml-deferred',
              () => highlightXml(pretty, { lineNumbers: false, preserveNewlines: true }),
              `${formatCount(pretty.length)} chars`
            );
          } catch (e) {
            warn('[mountXmlViewer] deferred highlight failed', e);
            return;
          }
          applyLightHtml(html);
          if (xmlViewerMountCache && xmlViewerMountCache.key === cacheKey) {
            xmlViewerMountCache.html = html;
          }
        });
      } else {
        measureSync('highlightXml+DOM-light', () => {
          const html = highlightXml(pretty, { lineNumbers: false, preserveNewlines: true });
          codeEl._pendingLightHtml = html;
          applyLightHtml(html);
        }, `${formatCount(lineCount)} lines`);
      }
    } else {
      codeEl.classList.remove('xml-plain-mode', 'xml-light-mode');
      measureSync('highlightXml+DOM', () => {
        const html = cachedHtml || highlightXml(pretty, { lineNumbers: true });
        if (!cachedHtml) codeEl._pendingFullHtml = html;
        codeEl.innerHTML = html;
      }, `${formatCount(lineCount)} lines`);
    }
  }
  if (toolbarEl) {
    toolbarEl.hidden = false;
    const chips = [];
    if (options.title) chips.push(`<span class="res-chip res-chip-title">${escapeHtml(options.title)}</span>`);
    if (meta.package) chips.push(`<span class="res-chip" title="Package"><span class="res-chip-k">pkg</span> ${escapeHtml(meta.package)}</span>`);
    if (meta.version_name || meta.version_code) {
      const v = [meta.version_name, meta.version_code ? `(${meta.version_code})` : ''].filter(Boolean).join(' ');
      chips.push(`<span class="res-chip" title="Version"><span class="res-chip-k">ver</span> ${escapeHtml(v)}</span>`);
    }
    if (meta.is_packed) chips.push(`<span class="res-chip res-chip-warn" title="Possible packer / obfuscation">packed</span>`);
    if (meta.root_tag) chips.push(`<span class="res-chip"><span class="res-chip-k">root</span> ${escapeHtml(meta.root_tag)}</span>`);
    if (meta.permissions?.length) chips.push(`<span class="res-chip" title="${escapeAttr(meta.permissions.join('\n'))}"><span class="res-chip-k">perms</span> ${meta.permissions.length}</span>`);
    chips.push(`<span class="res-chip muted"><span class="res-chip-k">lines</span> ${lineCount}</span>`);
    if (deferHighlight) {
      chips.push(`<span class="res-chip res-chip-warn res-chip-xml-mode" title="Indenting now; colors apply in a moment">formatting…</span>`);
    } else if (light) {
      chips.push(`<span class="res-chip res-chip-xml-mode" title="Indented + syntax highlighted (fast path for large manifests)">formatted</span>`);
    }
    toolbarEl.innerHTML = `
      <div class="res-viewer-meta">${chips.join('')}</div>
      <div class="res-viewer-actions">
        <input type="search" class="pane-search-input res-xml-search" placeholder="Filter lines…" aria-label="Filter XML lines" autocomplete="off">
        <span class="pane-search-count muted res-xml-search-count"></span>
        <button type="button" class="btn btn-small res-xml-copy" title="Copy XML">Copy</button>
      </div>`;
    const search = toolbarEl.querySelector('.res-xml-search');
    const countEl = toolbarEl.querySelector('.res-xml-search-count');
    const copyBtn = toolbarEl.querySelector('.res-xml-copy');
    const updateCount = () => {
      if (light) {
        if (countEl) countEl.textContent = deferHighlight ? `${lineCount} lines (indenting…)` : `${lineCount} lines`;
        return;
      }
      const r = filterXmlViewerLines(codeEl, search?.value || '');
      if (countEl) countEl.textContent = search?.value ? `${r.matches}/${r.total}` : `${r.total} lines`;
    };
    search?.addEventListener('input', updateCount);
    if (light && search) {
      search.disabled = true;
      search.placeholder = 'Filter disabled (large manifest)';
    }
    copyBtn?.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(pretty);
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
      } catch (_) {
        copyBtn.textContent = 'Failed';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
      }
    });
    updateCount();
  }
  recordPerf('mountXmlViewer', nowMs() - tAll, fromCache ? `cache-${mode}` : (deferHighlight ? 'light-deferred' : mode));

  if (!fromCache) {
    if (mode === 'full') {
      outline = measureSync('buildXmlOutline', () => buildXmlOutline(pretty), `${formatCount(lineCount)} lines`);
    } else if (mode === 'light' && lineCount <= 2500) {
      outline = measureSync('buildXmlOutline', () => buildXmlOutline(pretty), `${formatCount(lineCount)} lines`);
    }
    const html = codeEl?._pendingLightHtml || codeEl?._pendingFullHtml || cachedHtml || '';
    if (codeEl) {
      delete codeEl._pendingLightHtml;
      delete codeEl._pendingFullHtml;
    }
    xmlViewerMountCache = {
      key: cacheKey,
      pretty,
      html,
      mode,
      outline,
      lineCount,
      meta,
    };
  }

  return { pretty, meta, outline, plain: false, mode, deferred: deferHighlight };
}

function renderXmlOutlineTree(outline, { selectedLine } = {}) {
  if (!outline?.length) return '<div class="muted center-text">No tags</div>';
  let html = '<ul class="tree xml-outline-tree">';
  for (const item of outline) {
    const pad = Math.min(item.depth, 8);
    const hint = item.hint ? ` <span class="muted xml-outline-hint">${escapeHtml(item.hint.length > 40 ? item.hint.slice(0, 37) + '…' : item.hint)}</span>` : '';
    const sel = selectedLine === item.line ? ' selected' : '';
    html += `<li><div class="tree-item xml-outline-item${sel}" data-line="${item.line}" style="padding-left:${0.35 + pad * 0.55}rem" title="Line ${item.line}"><span class="xml-outline-tag">&lt;${escapeHtml(item.name)}&gt;</span>${hint}</div></li>`;
  }
  html += '</ul>';
  return html;
}

function bindXmlOutlineClicks(container, codeEl) {
  if (!container) return;
  container.querySelectorAll('.xml-outline-item').forEach((el) => {
    el.addEventListener('click', () => {
      container.querySelectorAll('.xml-outline-item.selected').forEach((n) => n.classList.remove('selected'));
      el.classList.add('selected');
      const line = Number(el.dataset.line);
      scrollXmlLineIntoView(codeEl, line);
      switchToCenterTab('manifest-tab');
    });
  });
}

function mountArscViewer(host, packages, options = {}) {
  const pkgs = (packages || []).map((p, pi) => {
    const name = typeof p === 'string' ? p : (p?.name ?? '');
    const types = Array.isArray(p?.types) ? [...p.types].sort((a, b) => String(a).localeCompare(String(b))) : [];
    return { pi, name, types };
  });
  const overviewXml = options.overviewXml || buildArscOverviewXml(packages || []);
  const totalTypes = pkgs.reduce((n, p) => n + p.types.length, 0);
  const initialPkg = pkgs[0]?.pi ?? 0;

  const pkgRows = pkgs.map((p) => `
    <button type="button" class="arsc-pkg-row${p.pi === initialPkg ? ' selected' : ''}" data-pkg="${p.pi}" data-pkg-name="${escapeAttr(p.name)}" id="arsc-pkg-${p.pi}" title="${escapeAttr(p.name)}">
      <span class="arsc-pkg-row-name">${escapeHtml(p.name || '(unnamed)')}</span>
      <span class="arsc-pkg-row-count muted">${p.types.length}</span>
    </button>`).join('');

  host.innerHTML = `
    <div class="res-viewer arsc-viewer">
      <div class="res-viewer-toolbar">
        <div class="res-viewer-meta">
          <span class="res-chip res-chip-title">${escapeHtml(options.title || 'resources.arsc')}</span>
          <span class="res-chip"><span class="res-chip-k">packages</span> ${pkgs.length}</span>
          <span class="res-chip"><span class="res-chip-k">types</span> ${totalTypes}</span>
        </div>
        <div class="res-viewer-actions">
          <input type="search" class="pane-search-input arsc-type-search" placeholder="Filter packages / types…" aria-label="Filter ARSC" autocomplete="off">
          <button type="button" class="btn btn-small arsc-copy-xml" title="Copy overview XML">Copy XML</button>
        </div>
      </div>
      <div class="arsc-browser">
        <aside class="arsc-pkg-pane" aria-label="Resource packages">
          <div class="arsc-pane-label">Packages</div>
          <div class="arsc-pkg-list">${pkgRows || '<div class="muted arsc-empty">No packages</div>'}</div>
        </aside>
        <section class="arsc-type-pane" aria-label="Resource types">
          <div class="arsc-pane-label arsc-type-pane-head">
            <span>Types</span>
            <span class="arsc-selected-pkg muted"></span>
            <span class="arsc-type-count muted"></span>
          </div>
          <div class="arsc-type-table-wrap">
            <table class="arsc-type-table">
              <thead><tr><th class="arsc-type-col-name">Type</th><th class="arsc-type-col-id">#</th></tr></thead>
              <tbody class="arsc-type-tbody"></tbody>
            </table>
            <div class="arsc-type-empty muted" hidden>No types in this package</div>
          </div>
        </section>
      </div>
      <details class="arsc-xml-details">
        <summary>Raw overview XML</summary>
        <div class="res-viewer-scroll">
          <pre class="manifest-xml res-xml arsc-overview-xml"></pre>
        </div>
      </details>
    </div>`;

  const search = host.querySelector('.arsc-type-search');
  const copyBtn = host.querySelector('.arsc-copy-xml');
  const tbody = host.querySelector('.arsc-type-tbody');
  const emptyEl = host.querySelector('.arsc-type-empty');
  const selectedPkgEl = host.querySelector('.arsc-selected-pkg');
  const typeCountEl = host.querySelector('.arsc-type-count');
  const xmlDetails = host.querySelector('.arsc-xml-details');
  const xmlEl = host.querySelector('.arsc-overview-xml');
  let selectedPkg = initialPkg;
  let selectedType = '';
  let xmlRendered = false;

  const pkgByIdx = (pi) => pkgs.find((p) => p.pi === Number(pi)) || null;

  const renderTypes = () => {
    const pkg = pkgByIdx(selectedPkg);
    const q = (search?.value || '').trim().toLowerCase();
    const types = pkg?.types || [];
    const filtered = q
      ? types.filter((t) => String(t).toLowerCase().includes(q) || (pkg?.name || '').toLowerCase().includes(q))
      : types;
    if (selectedPkgEl) selectedPkgEl.textContent = pkg?.name ? pkg.name : '';
    if (typeCountEl) {
      typeCountEl.textContent = filtered.length === types.length
        ? `${types.length} type${types.length === 1 ? '' : 's'}`
        : `${filtered.length} / ${types.length}`;
    }
    if (!tbody) return;
    if (!filtered.length) {
      tbody.innerHTML = '';
      if (emptyEl) emptyEl.hidden = false;
      return;
    }
    if (emptyEl) emptyEl.hidden = true;
    tbody.innerHTML = filtered.map((t, i) => {
      const sel = t === selectedType ? ' selected' : '';
      return `<tr class="arsc-type-row${sel}" data-type="${escapeAttr(t)}" tabindex="0">
        <td class="arsc-type-col-name"><code>${escapeHtml(t)}</code></td>
        <td class="arsc-type-col-id muted">${i + 1}</td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('.arsc-type-row').forEach((row) => {
      const activate = () => {
        selectedType = row.getAttribute('data-type') || '';
        tbody.querySelectorAll('.arsc-type-row.selected').forEach((n) => n.classList.remove('selected'));
        row.classList.add('selected');
      };
      row.addEventListener('click', activate);
      row.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          activate();
        }
      });
    });
  };

  const selectPackage = (pi, opts = {}) => {
    selectedPkg = Number(pi);
    if (!opts.keepType) selectedType = '';
    host.querySelectorAll('.arsc-pkg-row').forEach((row) => {
      row.classList.toggle('selected', Number(row.dataset.pkg) === selectedPkg);
    });
    const card = host.querySelector(`.arsc-pkg-row[data-pkg="${selectedPkg}"]`);
    if (opts.scroll && card) card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    renderTypes();
  };

  const applyFilter = () => {
    const q = (search?.value || '').trim().toLowerCase();
    host.querySelectorAll('.arsc-pkg-row').forEach((row) => {
      const pkg = pkgByIdx(row.dataset.pkg);
      const name = (pkg?.name || '').toLowerCase();
      const hit = !q || name.includes(q) || (pkg?.types || []).some((t) => String(t).toLowerCase().includes(q));
      row.classList.toggle('arsc-pkg-hidden', !hit);
    });
    renderTypes();
  };

  const ensureXml = () => {
    if (xmlRendered || !xmlEl) return;
    // Overview XML is already pretty-printed — highlight only (avoid re-format churn).
    xmlEl.innerHTML = highlightXml(overviewXml, { lineNumbers: true });
    xmlRendered = true;
  };

  host.querySelectorAll('.arsc-pkg-row').forEach((row) => {
    row.addEventListener('click', () => selectPackage(row.dataset.pkg));
  });
  search?.addEventListener('input', applyFilter);
  copyBtn?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(overviewXml);
      copyBtn.textContent = 'Copied';
      setTimeout(() => { copyBtn.textContent = 'Copy XML'; }, 1200);
    } catch (_) { /* ignore */ }
  });
  xmlDetails?.addEventListener('toggle', () => {
    if (xmlDetails.open) ensureXml();
  });

  selectPackage(initialPkg);
  // Keep legacy hooks used by the left outline tree.
  host._arscSelectPackage = (pkgName) => {
    const pkg = pkgs.find((p) => p.name === pkgName);
    if (pkg) selectPackage(pkg.pi, { scroll: true });
  };
  host._arscSelectType = (pkgName, type) => {
    const pkg = pkgs.find((p) => p.name === pkgName);
    if (!pkg) return;
    selectedType = type || '';
    selectPackage(pkg.pi, { scroll: true, keepType: true });
    const row = [...(tbody?.querySelectorAll('.arsc-type-row') || [])]
      .find((r) => r.getAttribute('data-type') === type);
    row?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    row?.classList.add('selected');
  };
  return { overviewXml, totalTypes };
}

function renderArscOutlineTree(packages) {
  const pkgs = packages || [];
  if (!pkgs.length) return '<div class="muted center-text">No packages</div>';
  let html = '<ul class="tree arsc-outline-tree">';
  pkgs.forEach((p, pi) => {
    const name = typeof p === 'string' ? p : (p?.name ?? '');
    const types = Array.isArray(p?.types) ? [...p.types].sort() : [];
    html += `<li><div class="tree-item arsc-outline-pkg" data-pkg="${pi}" data-pkg-name="${escapeAttr(name)}"><span class="arrow expanded"></span>${escapeHtml(name || '(unnamed)')} <span class="muted">(${types.length})</span></div><ul class="tree">`;
    for (const t of types) {
      html += `<li><div class="tree-item arsc-outline-type" data-pkg="${pi}" data-pkg-name="${escapeAttr(name)}" data-type="${escapeAttr(t)}">${escapeHtml(t)}</div></li>`;
    }
    html += '</ul></li>';
  });
  html += '</ul>';
  return html;
}

function setManifestPlaceholder(html) {
  const { toolbar, code } = ensureManifestViewerStructure();
  if (toolbar) { toolbar.hidden = true; toolbar.innerHTML = ''; }
  if (code) code.innerHTML = html;
}

const SEMGREP_YAML_KEYS = new Set([
  'rules', 'id', 'message', 'severity', 'languages', 'pattern', 'patterns', 'pattern-either',
  'pattern-regex', 'pattern-not', 'pattern-inside', 'pattern-not-inside', 'pattern-sources',
  'pattern-sinks', 'metadata', 'native', 'kind', 'methods', 'mode', 'options', 'fix',
  'paths', 'include', 'exclude', 'vuln_class', 'chain_tag', 'summary', 'references', 'cwe',
  'owasp', 'masvs', 'technology', 'source', 'sink',
]);
const SEMGREP_SEVERITIES = new Set(['ERROR', 'WARNING', 'INFO', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const SEMGREP_LANGS = new Set(['java', 'kotlin', 'xml', 'generic', 'javascript', 'python']);

function semgrepYamlKeyClass(key) {
  if (SEMGREP_YAML_KEYS.has(key)) return 'yaml-key';
  if (key.startsWith('pattern')) return 'yaml-key-pattern';
  return 'yaml-key-other';
}

function highlightSemgrepYamlTail(tail) {
  let out = '';
  let i = 0;
  while (i < tail.length) {
    const ch = tail[i];
    if (/\s/.test(ch)) {
      let j = i + 1;
      while (j < tail.length && /\s/.test(tail[j])) j++;
      out += escapeHtml(tail.slice(i, j));
      i = j;
      continue;
    }
    if (ch === '#') {
      out += `<span class="yaml-cm">${escapeHtml(tail.slice(i))}</span>`;
      break;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < tail.length) {
        if (tail[j] === '\\' && j + 1 < tail.length) { j += 2; continue; }
        if (tail[j] === '"') { j++; break; }
        j++;
      }
      out += `<span class="yaml-str">${escapeHtml(tail.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (ch === "'") {
      let j = i + 1;
      while (j < tail.length && tail[j] !== "'") j++;
      if (j < tail.length) j++;
      out += `<span class="yaml-str">${escapeHtml(tail.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (ch === '[' || ch === ']' || ch === ',' || ch === ';' || ch === ':' || ch === '|' || ch === '>') {
      out += `<span class="yaml-punct">${escapeHtml(ch)}</span>`;
      i++;
      continue;
    }
    if (ch === '$') {
      const m = tail.slice(i).match(/^\$(?:\.\.\.)?[\w]+/);
      if (m) {
        out += `<span class="yaml-meta">${escapeHtml(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
    }
    const m = tail.slice(i).match(/^[\w./$-]+/);
    if (m) {
      const word = m[0];
      let cls = 'yaml-plain';
      if (SEMGREP_SEVERITIES.has(word)) cls = 'yaml-sev yaml-sev-' + word.toLowerCase();
      else if (SEMGREP_LANGS.has(word)) cls = 'yaml-lang';
      else if (/^L[\w/$]+;$/.test(word)) cls = 'yaml-type';
      else if (/^\d+$/.test(word)) cls = 'yaml-num';
      else if (word === 'invoke' || word === 'native') cls = 'yaml-native';
      out += `<span class="${cls}">${escapeHtml(word)}</span>`;
      i += word.length;
      continue;
    }
    out += escapeHtml(ch);
    i++;
  }
  return out;
}

function highlightSemgrepYamlLine(line) {
  if (!line) return '';
  if (line.trimStart().startsWith('#')) {
    return `<span class="yaml-cm">${escapeHtml(line)}</span>`;
  }
  let out = '';
  let i = 0;
  const listMatch = line.match(/^(\s*)(-\s)?/);
  if (listMatch) {
    out += escapeHtml(listMatch[1]);
    if (listMatch[2]) out += `<span class="yaml-punct">${escapeHtml(listMatch[2])}</span>`;
    i = listMatch[0].length;
  }
  const rest = line.slice(i);
  const kvMatch = rest.match(/^([\w.-]+)(\s*:\s*)([\s\S]*)$/);
  if (kvMatch) {
    out += `<span class="${semgrepYamlKeyClass(kvMatch[1])}">${escapeHtml(kvMatch[1])}</span>`;
    out += `<span class="yaml-punct">${escapeHtml(kvMatch[2])}</span>`;
    out += highlightSemgrepYamlTail(kvMatch[3]);
    return out;
  }
  return out + highlightSemgrepYamlTail(rest);
}

function highlightSemgrepYaml(text) {
  if (!text) return '';
  return text.split('\n').map(highlightSemgrepYamlLine).join('\n');
}

function syncSemgrepRulesEditorScroll() {
  if (!securityRulesEditor || !securityRulesHighlight) return;
  securityRulesHighlight.scrollTop = securityRulesEditor.scrollTop;
  securityRulesHighlight.scrollLeft = securityRulesEditor.scrollLeft;
}

function refreshSemgrepRulesHighlight() {
  if (!securityRulesEditor || !securityRulesHighlight) return;
  const text = securityRulesEditor.value || '';
  securityRulesHighlight.innerHTML = highlightSemgrepYaml(text) + '\n';
  syncSemgrepRulesEditorScroll();
}

function setSemgrepRulesEditorValue(yaml) {
  if (!securityRulesEditor) return;
  securityRulesEditor.value = yaml;
  refreshSemgrepRulesHighlight();
}

/** Set element content to pretty, highlighted XML (uses innerHTML). */
function setXmlContent(el, xml, options = {}) {
  let target = el;
  let toolbar = options.toolbarEl;
  if (!target || target.id === 'manifest-xml' || options.useManifestHost) {
    const struct = ensureManifestViewerStructure();
    target = options.useManifestHost || !el || el.id === 'manifest-xml' ? struct.code : el;
    if (!toolbar && (target?.id === 'manifest-xml' || options.useManifestHost)) toolbar = struct.toolbar;
  }
  if (!target) return null;
  if (toolbar || options.rich || target.id === 'manifest-xml') {
    return mountXmlViewer(target, toolbar || (target.id === 'manifest-xml' ? document.getElementById('manifest-toolbar') : null), xml, options);
  }
  if (!xml || xml === '(empty)' || (typeof xml === 'string' && xml.startsWith('('))) {
    target.textContent = xml || '';
    return null;
  }
  const pretty = formatXmlPretty(xml);
  target.classList.add('res-xml');
  target.innerHTML = highlightXml(pretty, { lineNumbers: options.lineNumbers !== false });
  return { pretty };
}

/** Java keywords for syntax highlighting. */
const JAVA_KEYWORDS = new Set([
  'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class', 'const', 'continue',
  'default', 'do', 'double', 'else', 'enum', 'extends', 'final', 'finally', 'float', 'for', 'goto', 'if',
  'implements', 'import', 'instanceof', 'int', 'interface', 'long', 'native', 'new', 'package', 'private',
  'protected', 'public', 'return', 'short', 'static', 'strictfp', 'super', 'switch', 'synchronized', 'this',
  'throw', 'throws', 'transient', 'try', 'void', 'volatile', 'while', 'true', 'false', 'null'
]);

/**
 * Improve fill-array-data into a single Java array initializer,
 * fold assign+return, and normalize over-indented blocks to 4-space levels.
 */
function improveDecompiledJava(source) {
  if (!source || typeof source !== 'string') return source || '';
  const lines = source.split('\n');
  const out = [];
  const newArrRe = /^(\s*)(?:((?:[\w.$]+(?:\[\])+))\s+)?([\w$]+)\s*=\s*new\s+[\w.$]+(?:\[[^\]]*\])+\s*;\s*$/;
  const fillCommentRe = /^(\s*)\/\*\s*([\w$]+)\s*=\s*(\{[\s\S]*\})\s*\*\/\s*$/;
  const fillAssignRe = /^(\s*)([\w$]+)\s*=\s*(\{[\s\S]*\})\s*;\s*$/;
  const assignRe = /^(\s*)(?:(?:[\w.$]+(?:\[\])*)\s+)?([\w$]+)\s*=\s*(.+?)\s*;\s*$/;
  const returnIdentRe = /^(\s*)return\s+([\w$]+)\s*;\s*$/;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const next = lines[i + 1];
    const mNew = line.match(newArrRe);
    const mFill = next
      ? (next.match(fillCommentRe) || next.match(fillAssignRe))
      : null;
    if (mNew && mFill && mNew[3] === mFill[2]) {
      const indent = mNew[1];
      const typePart = mNew[2] ? mNew[2] + ' ' : '';
      out.push(`${indent}${typePart}${mNew[3]} = ${mFill[3]};`);
      i++;
      continue;
    }
    const alone = line.match(fillCommentRe);
    if (alone) {
      out.push(`${alone[1]}${alone[2]} = ${alone[3]};`);
      continue;
    }
    const mAssign = line.match(assignRe);
    const mRet = next ? next.match(returnIdentRe) : null;
    if (mAssign && mRet && mAssign[2] === mRet[2] && mAssign[3] !== '<result>') {
      out.push(`${mAssign[1]}return ${mAssign[3]};`);
      i++;
      continue;
    }
    out.push(line);
  }
  return normalizeJavaIndent(out.join('\n'));
}

/** Re-indent Java-like source to 4 spaces per brace nesting level. */
function normalizeJavaIndent(body) {
  if (!body) return body || '';
  const IND = '    ';
  const lines = body.split('\n');
  let baseLevels = 0;
  for (const line of lines) {
    if (line.trim()) {
      const spaces = line.match(/^ */)[0].length;
      baseLevels = Math.floor(spaces / 4);
      if (baseLevels > 2 && spaces >= 16 && spaces % 8 === 0) baseLevels = 2;
      break;
    }
  }
  let depth = baseLevels;
  const out = [];
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const trimmed = line.trim();
    if (!trimmed) {
      out.push('');
      continue;
    }
    const startsWithClose = trimmed.startsWith('}');
    if (startsWithClose) depth = Math.max(0, depth - 1);
    out.push(IND.repeat(depth) + trimmed);
    let inStr = null;
    let inLineComment = false;
    let inBlockComment = false;
    for (let i = 0; i < trimmed.length; i++) {
      const c = trimmed[i];
      const next = trimmed[i + 1];
      if (inLineComment) break;
      if (inBlockComment) {
        if (c === '*' && next === '/') { inBlockComment = false; i++; }
        continue;
      }
      if (inStr) {
        if (c === '\\') { i++; continue; }
        if (c === inStr) inStr = null;
        continue;
      }
      if (c === '/' && next === '/') { inLineComment = true; continue; }
      if (c === '/' && next === '*') { inBlockComment = true; i++; continue; }
      if (c === '"' || c === "'") { inStr = c; continue; }
      if (c === '{') depth++;
      else if (c === '}') {
        if (!(startsWithClose && i === 0)) depth = Math.max(0, depth - 1);
      }
    }
  }
  let result = out.join('\n');
  if (!body.endsWith('\n') && result.endsWith('\n')) result = result.slice(0, -1);
  if (body.endsWith('\n') && !result.endsWith('\n')) result += '\n';
  return result;
}

/** Escape HTML for source highlighting. */
function escHtmlSrc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Return HTML with Java syntax highlighting (comments, strings, keywords, types, numbers, annotations). Keeps newlines. */
function highlightJava(source) {
  if (!source || typeof source !== 'string') return '';
  let html = '';
  let i = 0;
  const n = source.length;
  while (i < n) {
    if (source.slice(i, i + 2) === '/*') {
      let end = source.indexOf('*/', i + 2);
      if (end === -1) end = n;
      html += '<span class="src-comment">' + escHtmlSrc(source.slice(i, end + 2)) + '</span>';
      i = end + 2;
      continue;
    }
    if (source.slice(i, i + 2) === '//') {
      let end = source.indexOf('\n', i + 2);
      if (end === -1) end = n;
      html += '<span class="src-comment">' + escHtmlSrc(source.slice(i, end)) + '</span>';
      i = end;
      continue;
    }
    if (source[i] === '"') {
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\') j += 2;
        else if (source[j] === '"') { j++; break; }
        else j++;
      }
      const lit = source.slice(i, j);
      const key = normalizeCrossConstKey(lit);
      html += key
        ? `<span class="src-string" data-const="${escapeAttr(key)}">${escHtmlSrc(lit)}</span>`
        : `<span class="src-string">${escHtmlSrc(lit)}</span>`;
      i = j;
      continue;
    }
    if (source[i] === "'") {
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\') j += 2;
        else if (source[j] === "'") { j++; break; }
        else j++;
      }
      const lit = source.slice(i, j);
      const key = normalizeCrossConstKey(lit);
      html += key
        ? `<span class="src-string" data-const="${escapeAttr(key)}">${escHtmlSrc(lit)}</span>`
        : `<span class="src-string">${escHtmlSrc(lit)}</span>`;
      i = j;
      continue;
    }
    if (source[i] === '@' && /^@[a-zA-Z_][\w.]*/.test(source.slice(i))) {
      const m = source.slice(i).match(/^@[a-zA-Z_][\w.]*/);
      const ann = m[0];
      const kind = frameworkApiKind(ann.replace(/^@/, '')) || (FRAMEWORK_SHORT_FQCN[ann.replace(/^@/, '')] ? shortFrameworkTypeKind(ann.replace(/^@/, '')) : '');
      if (kind || FRAMEWORK_SHORT_FQCN[ann.replace(/^@/, '')]) {
        const k = kind || shortFrameworkTypeKind(ann.replace(/^@/, '')) || 'java';
        html += formatFrameworkApiHtml(ann, k, { extraClass: 'src-annotation', docName: ann.replace(/^@/, '') });
      } else {
        html += '<span class="src-annotation">' + escHtmlSrc(ann) + '</span>';
      }
      i += ann.length;
      continue;
    }
    // Android resource refs first (incl. android.R.id.foo — before FQCN eat)
    const rMatch = source.slice(i).match(/^(?:[\w$]+\.)*R\.[a-z][\w$]*\.[\w$]+/);
    if (rMatch) {
      html += '<span class="src-api src-api-r" title="Android resource">' + escHtmlSrc(rMatch[0]) + '</span>';
      i += rMatch[0].length;
      continue;
    }
    // Fully-qualified platform types: android.*, androidx.*, java.*, javax.*
    const fqMatch = source.slice(i).match(/^(?:androidx?|java|javax)(?:\.[\w$]+)+/);
    if (fqMatch) {
      const fq = fqMatch[0];
      const kind = frameworkApiKind(fq);
      if (kind) {
        html += formatFrameworkApiHtml(fq, kind);
        i += fq.length;
        continue;
      }
    }
    const wordMatch = source.slice(i).match(/^[a-zA-Z_][\w]*/);
    if (wordMatch) {
      const word = wordMatch[0];
      if (JAVA_KEYWORDS.has(word)) {
        html += '<span class="src-keyword">' + escHtmlSrc(word) + '</span>';
      } else if (/^[A-Z]/.test(word)) {
        const kind = shortFrameworkTypeKind(word);
        if (kind) {
          html += formatFrameworkApiHtml(word, kind, { extraClass: 'src-type', docName: word });
        } else {
          html += '<span class="src-type">' + escHtmlSrc(word) + '</span>';
        }
      } else {
        let k = i + word.length;
        while (k < n && (source[k] === ' ' || source[k] === '\t')) k++;
        if (source[k] === '(') {
          html += '<span class="src-call">' + escHtmlSrc(word) + '</span>';
        } else {
          html += escHtmlSrc(word);
        }
      }
      i += word.length;
      continue;
    }
    const hexMatch = source.slice(i).match(/^0[xX][0-9a-fA-F]+[lL]?/);
    if (hexMatch) {
      const lit = hexMatch[0];
      const key = normalizeCrossConstKey(lit);
      html += key
        ? `<span class="src-number" data-const="${escapeAttr(key)}">${escHtmlSrc(lit)}</span>`
        : `<span class="src-number">${escHtmlSrc(lit)}</span>`;
      i += lit.length;
      continue;
    }
    const numMatch = source.slice(i).match(/^\d+\.?\d*([eE][+-]?\d+)?[fFdDlL]?/);
    if (numMatch) {
      const lit = numMatch[0];
      const key = normalizeCrossConstKey(lit);
      html += key
        ? `<span class="src-number" data-const="${escapeAttr(key)}">${escHtmlSrc(lit)}</span>`
        : `<span class="src-number">${escHtmlSrc(lit)}</span>`;
      i += lit.length;
      continue;
    }
    html += escHtmlSrc(source[i]);
    i++;
  }
  return html;
}

// Use control characters that won't appear in source and survive Prism/HTML (avoid \uFFFF - browsers show ￿)
const MARK_START = '\x01';
const MARK_END = '\x02';

/** Folded brace ranges: Set of start line indices (0-based) within the current source string. */
let sourceFoldedStarts = new Set();
/** Auto-fold long single-line array initializers (element count threshold). */
const LONG_ARRAY_FOLD_THRESHOLD = 12;

/** Find brace-block fold ranges: [{ start, end }] where start has `{` and end has matching `}`. */
function findBraceFoldRanges(lines) {
  const ranges = [];
  const stack = []; // { line, depthAtOpen }
  let depth = 0;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = null; // '"' | "'"
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    inLineComment = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      const next = line[i + 1];
      if (inBlockComment) {
        if (c === '*' && next === '/') { inBlockComment = false; i++; }
        continue;
      }
      if (inLineComment) continue;
      if (inString) {
        if (c === '\\') { i++; continue; }
        if (c === inString) inString = null;
        continue;
      }
      if (c === '/' && next === '/') { inLineComment = true; continue; }
      if (c === '/' && next === '*') { inBlockComment = true; i++; continue; }
      if (c === '"' || c === "'") { inString = c; continue; }
      if (c === '{') {
        stack.push({ line: li, depth });
        depth++;
      } else if (c === '}') {
        depth = Math.max(0, depth - 1);
        const open = stack.pop();
        if (open && open.line < li) {
          ranges.push({ start: open.line, end: li });
        }
      }
    }
  }
  // Prefer outermost-ish useful folds: keep all multi-line ranges; sort by start then end desc
  ranges.sort((a, b) => a.start - b.start || b.end - a.end);
  return ranges;
}

/** Detect long single-line array initializers for fold-in-place. */
function findLongArrayLineFolds(lines) {
  const folds = [];
  const re = /^(\s*)((?:[\w.$]+(?:\[\])+\s+)?[\w$]+\s*=\s*)(\{)([\s\S]*)(\}\s*;)\s*$/;
  for (let li = 0; li < lines.length; li++) {
    const m = lines[li].match(re);
    if (!m) continue;
    const inner = m[4];
    // Count top-level commas (rough element count)
    let elems = 1;
    let depth = 0;
    let inStr = null;
    for (let i = 0; i < inner.length; i++) {
      const c = inner[i];
      if (inStr) {
        if (c === '\\') { i++; continue; }
        if (c === inStr) inStr = null;
        continue;
      }
      if (c === '"' || c === "'") { inStr = c; continue; }
      if (c === '{' || c === '(') depth++;
      else if (c === '}' || c === ')') depth = Math.max(0, depth - 1);
      else if (c === ',' && depth === 0) elems++;
    }
    if (elems >= LONG_ARRAY_FOLD_THRESHOLD && inner.trim().length > 40) {
      folds.push({
        start: li,
        end: li,
        kind: 'array',
        prefix: m[1] + m[2] + '{',
        suffix: m[5], // `};` or `} ;`
        count: elems,
      });
    }
  }
  return folds;
}

/** Highlight a single line (no trailing newline).
 *  Always uses the custom highlighter so R.id / android.* / java.* API colors apply.
 *  (Prism has no tokens for those and was masking them.) */
function highlightJavaLine(line, searchTerm) {
  let s = line;
  const hasSearch = searchTerm && (searchTerm = searchTerm.trim()).length > 0;
  if (hasSearch) {
    const escaped = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(escaped, 'gi');
    s = s.replace(re, (match) => MARK_START + match + MARK_END);
  }
  let html = highlightJava(s);
  if (hasSearch) {
    html = html
      .split(MARK_START).join('<mark class="source-search-hit">')
      .split(MARK_END).join('</mark>');
  }
  return html;
}

/* ===== Source call links (click callee → open method / CFG) ===== */

const SOURCE_CALL_SKIP = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'throw',
  'assert', 'new', 'typeof', 'instanceof', 'case', 'else',
]);

const JAVA_SHORT_TYPE_PREFIXES = [
  'java.lang.', 'java.util.', 'java.io.', 'java.net.', 'java.nio.',
  'android.content.', 'android.os.', 'android.app.', 'android.view.',
  'android.widget.', 'android.net.', 'android.graphics.',
];

/** Parse resolved invoke operand tail: `…, pkg.Clz.method(params)`. */
function parseResolvedMethodRef(operands) {
  const s = String(operands || '').trim();
  if (!s) return null;
  const m = s.match(/([\w.$]+)\.([\w$]+|<init>)\(([^)]*)\)\s*$/);
  if (!m) return null;
  return {
    className: m[1],
    methodName: m[2] === '<init>' ? '<init>' : m[2],
    params: m[3] || '',
    hint: `${m[1]}.${m[2]}(${m[3] || ''})`,
  };
}

function collectInvokesFromBytecode(rows) {
  const out = [];
  if (!Array.isArray(rows)) return out;
  for (const row of rows) {
    const mn = String(row?.mnemonic || '').toLowerCase();
    if (!mn.startsWith('invoke')) continue;
    const ref = parseResolvedMethodRef(row.operands);
    if (ref) out.push(ref);
  }
  return out;
}

function createInvokeMatcher(rows) {
  const queues = new Map();
  for (const inv of collectInvokesFromBytecode(rows)) {
    const key = inv.methodName;
    if (!queues.has(key)) queues.set(key, []);
    queues.get(key).push(inv);
  }
  return {
    take(methodName, classHint) {
      const list = queues.get(methodName);
      if (!list || !list.length) return null;
      if (classHint) {
        const want = expandShortJavaType(classHint);
        const simple = want.split('.').pop();
        const idx = list.findIndex((inv) => {
          const c = inv.className;
          return classNamesEquivalent(c, want)
            || c === want
            || c.endsWith('.' + simple)
            || c.split('.').pop() === simple
            || c.split('$').pop() === simple;
        });
        if (idx >= 0) return list.splice(idx, 1)[0];
      }
      return list.shift();
    },
  };
}

function parseResolvedFieldRef(operands) {
  const parts = String(operands || '').split(',').map((s) => s.trim()).filter(Boolean);
  const last = parts[parts.length - 1] || '';
  const m = last.match(/^((?:[\w$]+\.)*[\w$]+)\.([\w$]+)$/);
  if (!m) return null;
  return { className: m[1], fieldName: m[2] };
}

function collectFieldsFromBytecode(rows) {
  const out = [];
  if (!Array.isArray(rows)) return out;
  for (const row of rows) {
    const mn = String(row?.mnemonic || '').toLowerCase();
    if (!/^(iget|iput|sget|sput)/.test(mn)) continue;
    const fieldIdx = fieldIndexFromBytecodeRow(row);
    const ref = parseResolvedFieldRef(row.operands);
    if (!ref && fieldIdx == null) continue;
    out.push({
      className: ref?.className || '',
      fieldName: ref?.fieldName || '',
      fieldIdx: fieldIdx != null ? fieldIdx : null,
    });
  }
  return out;
}

function createFieldMatcher(rows) {
  const queues = new Map();
  for (const f of collectFieldsFromBytecode(rows)) {
    const key = f.fieldName || '';
    if (!key) continue;
    if (!queues.has(key)) queues.set(key, []);
    queues.get(key).push(f);
  }
  return {
    take(fieldName, classHint) {
      const list = queues.get(fieldName);
      if (!list || !list.length) return null;
      if (classHint) {
        const want = expandShortJavaType(classHint);
        const simple = want.split('.').pop();
        const idx = list.findIndex((f) => {
          const c = f.className;
          return !c
            || classNamesEquivalent(c, want)
            || c === want
            || c.endsWith('.' + simple)
            || c.split('.').pop() === simple
            || c.split('$').pop() === simple;
        });
        if (idx >= 0) return list.splice(idx, 1)[0];
      }
      return list.shift();
    },
  };
}

/** Resolve field_ids index from class field lists (when bytecode matcher misses). */
function lookupFieldIdx(className, fieldName) {
  if (!fieldName) return null;
  const ctx = getCodeViewContext();
  const classes = ctx?.classes;
  if (!Array.isArray(classes)) return null;
  const want = className ? expandShortJavaType(className) : '';
  const simpleWant = want ? want.split('.').pop() : '';
  for (const cl of classes) {
    const fields = cl?.fields;
    if (!Array.isArray(fields)) continue;
    const cn = cl?.name || '';
    if (want) {
      const ok = classNamesEquivalent(cn, want)
        || cn === want
        || cn.endsWith('.' + simpleWant)
        || cn.split('.').pop() === simpleWant;
      if (!ok) continue;
    }
    for (const f of fields) {
      if ((f?.name || '') !== fieldName) continue;
      const idx = f.field_idx ?? f.fieldIdx;
      if (idx != null && Number.isFinite(Number(idx))) return Number(idx) >>> 0;
    }
  }
  if (!want && codeViewClassIdx != null) {
    const fields = classes[codeViewClassIdx]?.fields;
    if (Array.isArray(fields)) {
      for (const f of fields) {
        if ((f?.name || '') !== fieldName) continue;
        const idx = f.field_idx ?? f.fieldIdx;
        if (idx != null && Number.isFinite(Number(idx))) return Number(idx) >>> 0;
      }
    }
  }
  return null;
}

function classExistsInLoadedDex(className) {
  if (!className) return false;
  if (apkClassToDex && (apkClassToDex[className] || lookupApkClass(className))) return true;
  const ctx = getCodeViewContext();
  if (ctx?.classes && findClassIndexInDex(ctx.classes, className) >= 0) return true;
  if (Array.isArray(currentData?.classes) && findClassIndexInDex(currentData.classes, className) >= 0) return true;
  return false;
}

function expandShortJavaType(name) {
  const n = String(name || '').trim();
  if (!n) return n;
  if (n.includes('.')) return n;
  if (classExistsInLoadedDex(n)) return n;
  for (const p of JAVA_SHORT_TYPE_PREFIXES) {
    const full = p + n;
    if (classExistsInLoadedDex(full)) return full;
  }
  // Prefer java.lang for common simple types even if SDK not in APK
  const langCommon = new Set([
    'String', 'Object', 'Class', 'Throwable', 'Exception', 'RuntimeException',
    'Integer', 'Long', 'Boolean', 'Double', 'Float', 'Short', 'Byte', 'Character',
    'Void', 'System', 'Math', 'Thread',
  ]);
  if (langCommon.has(n)) return 'java.lang.' + n;
  for (const p of JAVA_SHORT_TYPE_PREFIXES) {
    // Fall back to first plausible FQN for navigation attempt
    if (p.startsWith('java.util.') && ['List', 'Map', 'Set', 'Collections', 'Arrays', 'HashMap', 'ArrayList'].includes(n)) {
      return p + n;
    }
  }
  const ctx = getCodeViewContext();
  const pkg = codeViewPackage || (ctx?.classes?.[codeViewClassIdx]?.name
    ? getPackageFromClassName(ctx.classes[codeViewClassIdx].name)
    : '');
  if (pkg && pkg !== '(default)') {
    const samePkg = pkg + '.' + n;
    if (classExistsInLoadedDex(samePkg)) return samePkg;
  }
  return n;
}

function receiverLooksLikeType(receiver) {
  const r = String(receiver || '');
  if (!r || r === 'this' || r === 'super') return false;
  if (r.includes('.')) {
    const last = r.split('.').pop();
    return /^[A-Z]/.test(last || '');
  }
  return /^[A-Z]/.test(r);
}

/** Find call / `new` sites on a source line (plain text). */
function findSourceCallSites(line) {
  const sites = [];
  const newRe = /\bnew\s+((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\s*\(/g;
  let m;
  while ((m = newRe.exec(line))) {
    sites.push({
      start: m.index + m[0].indexOf(m[1]),
      end: m.index + m[0].length - 1,
      kind: 'new',
      receiver: m[1],
      methodName: '<init>',
      display: m[1],
    });
  }
  const callRe = /((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\.([A-Za-z_][\w]*)\s*\(/g;
  while ((m = callRe.exec(line))) {
    if (SOURCE_CALL_SKIP.has(m[2])) continue;
    // Avoid matching the Type in `new Type(` already covered
    const before = line.slice(Math.max(0, m.index - 4), m.index);
    if (/\bnew\s*$/.test(before)) continue;
    sites.push({
      start: m.index,
      end: m.index + m[1].length + 1 + m[2].length,
      kind: 'call',
      receiver: m[1],
      methodName: m[2],
      display: `${m[1]}.${m[2]}`,
    });
  }
  sites.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const s of sites) {
    if (s.start < lastEnd) continue;
    out.push(s);
    lastEnd = s.end;
  }
  return out;
}

/** Field reads/writes: `obj.field` / `Type.field` not followed by `(`. */
function findSourceFieldSites(line) {
  const sites = [];
  const re = /((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\.([A-Za-z_][\w]*)(?!\s*\()/g;
  let m;
  while ((m = re.exec(line))) {
    const receiver = m[1];
    const fieldName = m[2];
    if (SOURCE_CALL_SKIP.has(fieldName)) continue;
    // Skip package-looking chains that end mid-FQCN (e.g. com.example inside import)
    if (/^(?:import|package)\b/.test(line.trim())) continue;
    sites.push({
      start: m.index,
      end: m.index + m[0].length,
      kind: 'field',
      receiver,
      fieldName,
      display: `${receiver}.${fieldName}`,
    });
  }
  sites.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const s of sites) {
    if (s.start < lastEnd) continue;
    out.push(s);
    lastEnd = s.end;
  }
  return out;
}

function resolveSourceFieldSite(site, fieldMatcher) {
  const fieldName = site.fieldName;
  if (receiverLooksLikeType(site.receiver)) {
    const className = expandShortJavaType(site.receiver);
    const fromBc = fieldMatcher?.take(fieldName, className);
    if (fromBc?.fieldIdx != null) {
      return { className: fromBc.className || className, fieldName, fieldIdx: fromBc.fieldIdx };
    }
    const idx = lookupFieldIdx(className, fieldName);
    if (idx != null) return { className, fieldName, fieldIdx: idx };
    return null;
  }
  const fromBc = fieldMatcher?.take(fieldName, null);
  if (fromBc?.fieldIdx != null) {
    return {
      className: fromBc.className || '',
      fieldName,
      fieldIdx: fromBc.fieldIdx,
    };
  }
  const idx = lookupFieldIdx('', fieldName);
  if (idx != null) return { className: '', fieldName, fieldIdx: idx };
  return null;
}

function resolveSourceCallSite(site, invokeMatcher) {
  if (site.kind === 'new') {
    const className = expandShortJavaType(site.receiver);
    const fromBc = invokeMatcher?.take('<init>', className);
    return fromBc || { className, methodName: '<init>', hint: className + '.<init>()' };
  }
  const methodName = site.methodName;
  if (receiverLooksLikeType(site.receiver)) {
    const className = expandShortJavaType(site.receiver);
    const fromBc = invokeMatcher?.take(methodName, className);
    return fromBc || { className, methodName, hint: `${className}.${methodName}` };
  }
  // Instance / this / super — consume matching invoke from bytecode order
  const fromBc = invokeMatcher?.take(methodName, null);
  return fromBc || null;
}

function isFrameworkOrSdkClass(className) {
  const c = String(className || '');
  if (!c) return true;
  return /^(java\.|javax\.|android\.|androidx\.|kotlin\.|kotlinx\.|dalvik\.|org\.json\.|org\.xml\.|org\.xmlpull\.|org\.w3c\.|org\.apache\.http\.|com\.android\.|sun\.|jdk\.)/.test(c);
}

/** Classify platform FQCN / descriptor for syntax colors: android | androidx | java | ''. */
function frameworkApiKind(name) {
  let n = String(name || '').trim();
  if (!n) return '';
  // Descriptor: [Lfoo/bar; or Lfoo/bar;
  n = n.replace(/^\[+/, '');
  if (n.startsWith('L') && n.endsWith(';')) {
    n = n.slice(1, -1);
  }
  n = n.replace(/\//g, '.');
  // Strip trailing method: pkg.Clz.method → pkg.Clz (keep package root for kind)
  if (n.startsWith('androidx.') || n === 'androidx') return 'androidx';
  if (n.startsWith('android.') || n === 'android') return 'android';
  if (n.startsWith('javax.') || n === 'javax') return 'java';
  if (n.startsWith('java.') || n === 'java') return 'java';
  return '';
}

/** Short type → preferred FQCN for developer.android.com / Java reference links. */
const FRAMEWORK_SHORT_FQCN = {
  String: 'java.lang.String', Object: 'java.lang.Object', Class: 'java.lang.Class',
  Throwable: 'java.lang.Throwable', Exception: 'java.lang.Exception',
  RuntimeException: 'java.lang.RuntimeException', Error: 'java.lang.Error',
  Integer: 'java.lang.Integer', Long: 'java.lang.Long', Boolean: 'java.lang.Boolean',
  Double: 'java.lang.Double', Float: 'java.lang.Float', Short: 'java.lang.Short',
  Byte: 'java.lang.Byte', Character: 'java.lang.Character', Void: 'java.lang.Void',
  System: 'java.lang.System', Math: 'java.lang.Math', Thread: 'java.lang.Thread',
  Runnable: 'java.lang.Runnable', Comparable: 'java.lang.Comparable',
  Iterable: 'java.lang.Iterable', Iterator: 'java.util.Iterator',
  List: 'java.util.List', Map: 'java.util.Map', Set: 'java.util.Set',
  Collection: 'java.util.Collection', Collections: 'java.util.Collections',
  Arrays: 'java.util.Arrays', HashMap: 'java.util.HashMap', ArrayList: 'java.util.ArrayList',
  LinkedList: 'java.util.LinkedList', HashSet: 'java.util.HashSet', TreeMap: 'java.util.TreeMap',
  Optional: 'java.util.Optional', Objects: 'java.util.Objects',
  StringBuilder: 'java.lang.StringBuilder', StringBuffer: 'java.lang.StringBuffer',
  CharSequence: 'java.lang.CharSequence', Enum: 'java.lang.Enum', Annotation: 'java.lang.annotation.Annotation',
  Activity: 'android.app.Activity', Service: 'android.app.Service', Intent: 'android.content.Intent',
  Context: 'android.content.Context', Application: 'android.app.Application',
  Bundle: 'android.os.Bundle', Handler: 'android.os.Handler', Looper: 'android.os.Looper',
  Message: 'android.os.Message', Parcelable: 'android.os.Parcelable',
  View: 'android.view.View', ViewGroup: 'android.view.ViewGroup',
  TextView: 'android.widget.TextView', EditText: 'android.widget.EditText',
  Button: 'android.widget.Button', ImageView: 'android.widget.ImageView',
  ImageButton: 'android.widget.ImageButton', LinearLayout: 'android.widget.LinearLayout',
  RelativeLayout: 'android.widget.RelativeLayout', FrameLayout: 'android.widget.FrameLayout',
  ListView: 'android.widget.ListView', ScrollView: 'android.widget.ScrollView',
  WebView: 'android.webkit.WebView', WebSettings: 'android.webkit.WebSettings',
  WebViewClient: 'android.webkit.WebViewClient', WebChromeClient: 'android.webkit.WebChromeClient',
  Toast: 'android.widget.Toast', Dialog: 'android.app.Dialog', AlertDialog: 'android.app.AlertDialog',
  SharedPreferences: 'android.content.SharedPreferences', ContentResolver: 'android.content.ContentResolver',
  Uri: 'android.net.Uri', Bitmap: 'android.graphics.Bitmap', Canvas: 'android.graphics.Canvas',
  Paint: 'android.graphics.Paint', Drawable: 'android.graphics.drawable.Drawable',
  Color: 'android.graphics.Color', Menu: 'android.view.Menu', MenuItem: 'android.view.MenuItem',
  Toolbar: 'android.widget.Toolbar', Notification: 'android.app.Notification',
  NotificationManager: 'android.app.NotificationManager', PendingIntent: 'android.app.PendingIntent',
  BroadcastReceiver: 'android.content.BroadcastReceiver', ContentProvider: 'android.content.ContentProvider',
  Cursor: 'android.database.Cursor', SQLiteDatabase: 'android.database.sqlite.SQLiteDatabase',
  FileProvider: 'androidx.core.content.FileProvider', PackageManager: 'android.content.pm.PackageManager',
  Window: 'android.view.Window', WindowManager: 'android.view.WindowManager',
  LayoutInflater: 'android.view.LayoutInflater', MotionEvent: 'android.view.MotionEvent',
  KeyEvent: 'android.view.KeyEvent', TypedArray: 'android.content.res.TypedArray',
  Resources: 'android.content.res.Resources', AssetManager: 'android.content.res.AssetManager',
  SparseArray: 'android.util.SparseArray', Log: 'android.util.Log', Build: 'android.os.Build',
  Os: 'android.system.Os', Process: 'android.os.Process',
  ClipboardManager: 'android.content.ClipboardManager',
  ConnectivityManager: 'android.net.ConnectivityManager', WifiManager: 'android.net.wifi.WifiManager',
  LocationManager: 'android.location.LocationManager', MediaPlayer: 'android.media.MediaPlayer',
  MediaRecorder: 'android.media.MediaRecorder', Camera: 'android.hardware.Camera',
  SurfaceView: 'android.view.SurfaceView', TextureView: 'android.view.TextureView',
  Spannable: 'android.text.Spannable', SpannableString: 'android.text.SpannableString',
  Html: 'android.text.Html', TextUtils: 'android.text.TextUtils', Patterns: 'android.util.Patterns',
  AppCompatActivity: 'androidx.appcompat.app.AppCompatActivity',
  Fragment: 'androidx.fragment.app.Fragment', FragmentActivity: 'androidx.fragment.app.FragmentActivity',
  RecyclerView: 'androidx.recyclerview.widget.RecyclerView',
  ConstraintLayout: 'androidx.constraintlayout.widget.ConstraintLayout',
  ViewPager: 'androidx.viewpager.widget.ViewPager', ViewPager2: 'androidx.viewpager2.widget.ViewPager2',
  NavController: 'androidx.navigation.NavController', LiveData: 'androidx.lifecycle.LiveData',
  ViewModel: 'androidx.lifecycle.ViewModel', MutableLiveData: 'androidx.lifecycle.MutableLiveData',
  CoordinatorLayout: 'androidx.coordinatorlayout.widget.CoordinatorLayout',
  SwipeRefreshLayout: 'androidx.swiperefreshlayout.widget.SwipeRefreshLayout',
  Snackbar: 'com.google.android.material.snackbar.Snackbar',
  Override: 'java.lang.Override', Deprecated: 'java.lang.Deprecated',
  Nullable: 'androidx.annotation.Nullable', NonNull: 'androidx.annotation.NonNull',
};

/**
 * Resolve a type / descriptor / short name to { fqcn, method } for docs.
 * Links go to developer.android.com (covers android.*, androidx.*, java.*, javax.*).
 */
function resolveFrameworkDocTarget(name, methodName = null) {
  let n = String(name || '').trim().replace(/^@/, '');
  if (!n) return null;
  n = n.replace(/^\[+/, '');
  if (n.startsWith('L') && n.endsWith(';')) n = n.slice(1, -1);
  n = n.replace(/\//g, '.');
  let method = methodName && methodName !== '<init>' ? String(methodName) : '';
  if (!method && n.includes('.')) {
    const parts = n.split('.');
    if (parts.length >= 3) {
      const last = parts[parts.length - 1];
      const prev = parts[parts.length - 2];
      if (/^[a-z_$]/.test(last) && /^[A-Z]/.test(prev) && !last.includes('$')) {
        method = last;
        n = parts.slice(0, -1).join('.');
      }
    }
  }
  if (!n.includes('.')) {
    n = FRAMEWORK_SHORT_FQCN[n] || expandShortJavaType(n) || n;
  }
  // Documented on developer.android.com (SDK + AndroidX + java.* mirrors + Material)
  const ok = frameworkApiKind(n)
    || n.startsWith('com.google.android.material.')
    || !!FRAMEWORK_SHORT_FQCN[String(name || '').replace(/^@/, '')];
  if (!ok) return null;
  if (/(^|\.)R$/.test(n) || /\.R\./.test(n)) return null;
  return { fqcn: n, method };
}

/** Official reference URL (opens in a new tab). */
function frameworkApiDocUrl(name, methodName = null) {
  const target = resolveFrameworkDocTarget(name, methodName);
  if (!target?.fqcn) return '';
  let url = `https://developer.android.com/reference/${target.fqcn.replace(/\./g, '/')}`;
  if (target.method) url += `#${encodeURIComponent(target.method)}`;
  return url;
}

/** Render colored API text; wrap in docs link when a reference URL exists. */
function formatFrameworkApiHtml(text, kind, {
  extraClass = '',
  methodName = null,
  docName = null,
  titlePrefix = 'Open documentation',
} = {}) {
  const display = escHtmlSrc(text);
  const k = kind || frameworkApiKind(docName || text) || '';
  const cls = ['src-api', k ? `src-api-${k}` : '', extraClass].filter(Boolean).join(' ');
  const url = frameworkApiDocUrl(docName || text, methodName);
  if (!url) {
    return `<span class="${cls}">${display}</span>`;
  }
  const tip = `${titlePrefix}: ${resolveFrameworkDocTarget(docName || text, methodName)?.fqcn || text}`;
  return `<a href="${escapeAttr(url)}" class="${cls} src-api-doc" target="_blank" rel="noopener noreferrer" title="${escapeAttr(tip)}">${display}</a>`;
}

function formatBytecodeApiHtml(text, kind, { methodName = null, docName = null, isDescriptor = false } = {}) {
  const display = text; // already escaped in bytecode path
  const k = kind || frameworkApiKind(docName || text) || '';
  const cls = [isDescriptor ? 'bc-type' : '', 'bc-api', k ? `bc-api-${k}` : '', 'bc-api-doc'].filter(Boolean).join(' ');
  const url = frameworkApiDocUrl(docName || text, methodName);
  if (!url) {
    const spanCls = [isDescriptor ? 'bc-type' : '', 'bc-api', k ? `bc-api-${k}` : ''].filter(Boolean).join(' ');
    return `<span class="${spanCls}">${display}</span>`;
  }
  const tip = `Open documentation: ${resolveFrameworkDocTarget(docName || text, methodName)?.fqcn || text}`;
  return `<a href="${escapeAttr(url)}" class="${cls}" target="_blank" rel="noopener noreferrer" title="${escapeAttr(tip)}">${display}</a>`;
}

/** Common short type names (no package) → api color kind when decompiler omits FQCN. */
const FRAMEWORK_SHORT_TYPE_KIND = (() => {
  const m = Object.create(null);
  const add = (kind, names) => { for (const n of names) m[n] = kind; };
  add('java', [
    'String', 'Object', 'Class', 'Throwable', 'Exception', 'RuntimeException', 'Error',
    'Integer', 'Long', 'Boolean', 'Double', 'Float', 'Short', 'Byte', 'Character', 'Void',
    'System', 'Math', 'Thread', 'Runnable', 'Comparable', 'Iterable', 'Iterator',
    'List', 'Map', 'Set', 'Collection', 'Collections', 'Arrays', 'HashMap', 'ArrayList',
    'LinkedList', 'HashSet', 'TreeMap', 'Optional', 'Objects', 'StringBuilder', 'StringBuffer',
    'CharSequence', 'Enum', 'Annotation',
  ]);
  add('android', [
    'Activity', 'AppCompatActivity', 'Fragment', 'FragmentActivity', 'Service', 'Intent',
    'Context', 'Application', 'Bundle', 'Handler', 'Looper', 'Message', 'Parcelable',
    'View', 'ViewGroup', 'TextView', 'EditText', 'Button', 'ImageView', 'ImageButton',
    'LinearLayout', 'RelativeLayout', 'FrameLayout', 'ConstraintLayout', 'RecyclerView',
    'ListView', 'ScrollView', 'WebView', 'WebSettings', 'WebViewClient', 'WebChromeClient',
    'Toast', 'Dialog', 'AlertDialog', 'SharedPreferences', 'ContentResolver', 'Uri',
    'Bitmap', 'Canvas', 'Paint', 'Drawable', 'Color', 'Menu', 'MenuItem', 'Toolbar',
    'Notification', 'NotificationManager', 'PendingIntent', 'BroadcastReceiver',
    'ContentProvider', 'Cursor', 'SQLiteDatabase', 'FileProvider', 'PackageManager',
    'Window', 'WindowManager', 'LayoutInflater', 'MotionEvent', 'KeyEvent', 'TypedArray',
    'Resources', 'AssetManager', 'SparseArray', 'Log', 'Build', 'Os', 'Process',
    'ClipboardManager', 'ConnectivityManager', 'WifiManager', 'LocationManager',
    'MediaPlayer', 'MediaRecorder', 'Camera', 'SurfaceView', 'TextureView',
    'Spannable', 'SpannableString', 'Html', 'TextUtils', 'Patterns',
  ]);
  add('androidx', [
    'AppCompatActivity', 'Fragment', 'FragmentActivity', 'RecyclerView', 'ViewPager',
    'ViewPager2', 'NavController', 'LiveData', 'ViewModel', 'MutableLiveData',
    'ConstraintLayout', 'CoordinatorLayout', 'SwipeRefreshLayout', 'Snackbar',
  ]);
  return m;
})();

function shortFrameworkTypeKind(simpleName) {
  const n = String(simpleName || '');
  if (!n) return '';
  if (FRAMEWORK_SHORT_TYPE_KIND[n]) return FRAMEWORK_SHORT_TYPE_KIND[n];
  // Prefer androidx when both maps could apply (AppCompatActivity listed under both)
  const expanded = expandShortJavaType(n);
  return frameworkApiKind(expanded);
}

function frameworkApiClassName(kind, prefix) {
  if (!kind) return '';
  return `${prefix}-api ${prefix}-api-${kind}`;
}

/** Highlight a line and wrap in-app callees / fields as links (never Android/Java SDK). */
function highlightJavaLineWithCalls(line, searchTerm, invokeMatcher, fieldMatcher = null) {
  if (!invokeMatcher && !fieldMatcher && !/[.(]/.test(line)) return highlightJavaLine(line, searchTerm);
  const callSites = findSourceCallSites(line);
  const fieldSites = findSourceFieldSites(line);
  // Prefer calls over fields when ranges overlap (Foo.bar(…).
  const occupied = [];
  for (const s of callSites) occupied.push([s.start, s.end]);
  const fieldsOnly = fieldSites.filter((fs) => !occupied.some(([a, b]) => fs.start < b && fs.end > a));
  const sites = [
    ...callSites.map((s) => ({ ...s, _kind: s.kind === 'new' ? 'new' : 'call' })),
    ...fieldsOnly.map((s) => ({ ...s, _kind: 'field' })),
  ].sort((a, b) => a.start - b.start || b.end - a.end);
  if (!sites.length) return highlightJavaLine(line, searchTerm);
  let html = '';
  let pos = 0;
  for (const site of sites) {
    if (site.start < pos) continue;
    if (site.start > pos) {
      html += highlightJavaLine(line.slice(pos, site.start), searchTerm);
    }
    if (site._kind === 'field') {
      const resolved = resolveSourceFieldSite(site, fieldMatcher);
      const fieldStart = site.start + String(site.receiver || '').length + 1;
      const recvHtml = highlightJavaLine(line.slice(site.start, fieldStart), searchTerm);
      const fieldInner = highlightJavaLine(line.slice(fieldStart, site.end), searchTerm);
      if (resolved?.fieldIdx != null) {
        const title = `Field usages: ${resolved.className ? resolved.className + '.' : ''}${resolved.fieldName}`;
        html += `${recvHtml}<a href="#" class="src-field-link" data-field-idx="${resolved.fieldIdx}" title="${escapeAttr(title)}">${fieldInner}</a>`;
      } else {
        html += recvHtml + fieldInner;
      }
      pos = site.end;
      continue;
    }
    const resolved = resolveSourceCallSite(site, invokeMatcher);
    const cls = resolved?.className || '';
    const expanded = cls ? expandShortJavaType(cls) : '';
    const inApp = !!(
      cls
      && !isFrameworkOrSdkClass(cls)
      && !isFrameworkOrSdkClass(expanded)
      && (classExistsInLoadedDex(cls) || classExistsInLoadedDex(expanded))
    );
    // Instance receivers (sb0.append): keep receiver outside `.src-api` so overlay
    // can wrap/highlight `sb0`. Type receivers (String.valueOf) stay fully wrapped.
    const splitReceiver = site.kind === 'call' && !receiverLooksLikeType(site.receiver);
    const recvLen = splitReceiver ? String(site.receiver || '').length : 0;
    let callHtml = '';
    if (splitReceiver && recvLen > 0) {
      callHtml += highlightJavaLine(line.slice(site.start, site.start + recvLen), searchTerm);
      const afterRecv = line.slice(site.start + recvLen, site.end);
      if (afterRecv.startsWith('.')) callHtml += '.';
      const methodStart = site.start + recvLen + (afterRecv.startsWith('.') ? 1 : 0);
      const methodInner = highlightJavaLine(line.slice(methodStart, site.end), searchTerm);
      if (inApp) {
        const title = `Go to ${cls}#${resolved.methodName}`;
        callHtml += `<a href="#" class="src-call-link" data-class="${escapeAttr(cls)}" data-method="${escapeAttr(resolved.methodName)}" data-hint="${escapeAttr(resolved.hint || '')}" title="${escapeAttr(title)}">${methodInner}</a>`;
      } else {
        const kind = frameworkApiKind(expanded || cls);
        if (kind) {
          const url = frameworkApiDocUrl(expanded || cls, resolved?.methodName || site.methodName);
          if (url) {
            const tip = `Open documentation: ${resolveFrameworkDocTarget(expanded || cls, resolved?.methodName || site.methodName)?.fqcn || expanded || cls}`;
            callHtml += `<a href="${escapeAttr(url)}" class="src-call src-api src-api-${kind} src-api-doc" target="_blank" rel="noopener noreferrer" title="${escapeAttr(tip)}">${methodInner}</a>`;
          } else {
            callHtml += `<span class="src-call src-api src-api-${kind}">${methodInner}</span>`;
          }
        } else {
          callHtml += `<span class="src-call">${methodInner}</span>`;
        }
      }
    } else {
      const text = line.slice(site.start, site.end);
      const inner = highlightJavaLine(text, searchTerm);
      if (inApp) {
        const title = `Go to ${cls}#${resolved.methodName}`;
        callHtml = `<a href="#" class="src-call-link" data-class="${escapeAttr(cls)}" data-method="${escapeAttr(resolved.methodName)}" data-hint="${escapeAttr(resolved.hint || '')}" title="${escapeAttr(title)}">${inner}</a>`;
      } else {
        const kind = frameworkApiKind(expanded || cls);
        if (kind) {
          const url = frameworkApiDocUrl(expanded || cls, resolved?.methodName || site.methodName);
          if (url) {
            const tip = `Open documentation: ${resolveFrameworkDocTarget(expanded || cls, resolved?.methodName || site.methodName)?.fqcn || expanded || cls}`;
            callHtml = `<a href="${escapeAttr(url)}" class="src-call src-api src-api-${kind} src-api-doc" target="_blank" rel="noopener noreferrer" title="${escapeAttr(tip)}">${inner}</a>`;
          } else {
            callHtml = `<span class="src-call src-api src-api-${kind}">${inner}</span>`;
          }
        } else {
          callHtml = `<span class="src-call">${inner}</span>`;
        }
      }
    }
    html += callHtml;
    pos = site.end;
  }
  if (pos < line.length) html += highlightJavaLine(line.slice(pos), searchTerm);
  return html;
}

let sourceNavStack = [];
const sourceNavBackBtn = document.getElementById('source-nav-back');

function updateSourceNavBackBtn() {
  if (!sourceNavBackBtn) return;
  const canClass = sourceNavStack.length === 0 && codeViewMethodIdx != null;
  sourceNavBackBtn.disabled = sourceNavStack.length === 0 && !canClass;
  if (sourceNavStack.length) {
    sourceNavBackBtn.title = `Back to previous method (Alt+←) · ${sourceNavStack.length} in stack`;
  } else if (canClass) {
    sourceNavBackBtn.title = 'Back to class — all methods (Alt+←)';
  } else {
    sourceNavBackBtn.title = 'Back to previous method (Alt+←)';
  }
}

function clearSourceNavStack() {
  sourceNavStack = [];
  updateSourceNavBackBtn();
}

function pushSourceNavState() {
  const ctx = getCodeViewContext();
  if (!ctx || codeViewMethodIdx == null) return;
  const wrap = document.getElementById('source-code-wrap');
  const className = ctx.classes?.[codeViewClassIdx]?.name || '';
  const methodName = ctx.classes?.[codeViewClassIdx]?.methods?.[codeViewMethodIdx]?.name || '';
  sourceNavStack.push({
    classIdx: codeViewClassIdx,
    methodIdx: codeViewMethodIdx,
    package: codeViewPackage,
    className,
    methodName,
    dexName: currentType === 'apk'
      ? (apkExtractedFile?.name || '')
      : (loadedDexFiles[activeDexIndex]?.name || currentFilename || ''),
    scrollTop: wrap?.scrollTop || 0,
  });
  if (sourceNavStack.length > 64) sourceNavStack.shift();
  updateSourceNavBackBtn();
}

async function sourceNavBack() {
  if (sourceNavStack.length) {
    const prev = sourceNavStack.pop();
    updateSourceNavBackBtn();
    if (!prev) return;
    if (currentType === 'apk' && prev.dexName) {
      await showApkFile(prev.dexName);
    } else if (currentType === 'dex' && prev.dexName && loadedDexFiles.length > 1) {
      const idx = loadedDexFiles.findIndex((d) => (d.name || '') === prev.dexName);
      if (idx >= 0 && idx !== activeDexIndex) switchActiveDex(idx);
    }
    if (prev.package) codeViewPackage = prev.package;
    selectCodeViewMethod(prev.classIdx, prev.methodIdx, { expandCfg: true });
    const wrap = document.getElementById('source-code-wrap');
    if (wrap) requestAnimationFrame(() => { wrap.scrollTop = prev.scrollTop || 0; });
    return;
  }
  if (codeViewMethodIdx != null) {
    goBackToClassView();
  }
}

sourceNavBackBtn?.addEventListener('click', () => { sourceNavBack(); });

async function navigateToSourceCall(className, methodName, hint = '') {
  if (!className) return;
  const expanded = expandShortJavaType(className);
  if (isFrameworkOrSdkClass(className) || isFrameworkOrSdkClass(expanded)) {
    if (sourceMeta) sourceMeta.textContent = `${expanded} is Android/Java API (not linked)`;
    return;
  }
  if (currentType === 'apk') await ensureApkClassIndex();
  const inApp = classExistsInLoadedDex(expanded) || classExistsInLoadedDex(className);
  if (!inApp) {
    if (sourceMeta) sourceMeta.textContent = `${expanded} not in loaded DEX (SDK / missing)`;
    return;
  }
  pushSourceNavState();
  await navigateToSecurityFinding(expanded, methodName || '<init>', '', { hint: hint || '' });
  ensureCfgPaneExpanded();
  if (sourceMeta) {
    sourceMeta.textContent = `→ ${expanded}#${methodName || '<init>'}`;
  }
}

/** Apply syntax highlighting (legacy flat HTML with <br>) — used for non-foldable panes. */
function applySourceHighlight(sourceRaw, searchTerm) {
  if (!sourceRaw || typeof sourceRaw !== 'string') return '';
  const improved = improveDecompiledJava(sourceRaw);
  const lines = improved.split('\n');
  return lines.map((ln) => highlightJavaLine(ln, searchTerm)).join('<br>');
}

/**
 * Render foldable Java source HTML.
 * @param {string} sourceRaw
 * @param {string} searchTerm
 * @param {string} foldKeyPrefix - prefix for fold ids (e.g. method index) so multi-method views don't clash
 * @param {{ classIdx?: number, methodIdx?: number }} [methodRef] - for call-link invoke matching
 */
function renderFoldableJavaSource(sourceRaw, searchTerm, foldKeyPrefix, methodRef = null) {
  const improved = improveDecompiledJava(sourceRaw);
  const lines = improved.split('\n');
  const braceRanges = findBraceFoldRanges(lines);
  const arrayFolds = findLongArrayLineFolds(lines);
  // Map start line → best fold end (prefer largest block for that start)
  const foldAt = new Map();
  for (const r of braceRanges) {
    const prev = foldAt.get(r.start);
    if (!prev || r.end > prev.end) foldAt.set(r.start, { ...r, kind: 'brace' });
  }
  for (const r of arrayFolds) {
    if (!foldAt.has(r.start)) foldAt.set(r.start, r);
  }

  const prefix = foldKeyPrefix || '0';
  const isFolded = (start) => sourceFoldedStarts.has(prefix + ':' + start);
  const commentMethodKey = resolveSourceCommentMethodKey(methodRef);

  // Keep long arrays expanded by default (user can still collapse via the fold button).
  for (const r of arrayFolds) {
    const key = prefix + ':' + r.start;
    if (!sourceFoldedStarts.has('__seen__' + key)) {
      sourceFoldedStarts.add('__seen__' + key);
    }
  }

  let invokeMatcher = null;
  let fieldMatcher = null;
  if (methodRef && methodRef.classIdx != null && methodRef.methodIdx != null) {
    const ctx = getCodeViewContext();
    const rows = ctx?.classes?.[methodRef.classIdx]?.methods?.[methodRef.methodIdx]?.bytecode;
    invokeMatcher = createInvokeMatcher(rows);
    fieldMatcher = createFieldMatcher(rows);
  }

  let html = '<div class="src-foldable">';
  let li = 0;
  while (li < lines.length) {
    const fold = foldAt.get(li);
    const folded = fold && isFolded(li);
    const lineNo = `<span class="src-line-no" aria-hidden="true" title="Double-click to comment">${li + 1}</span>`;
    const paint = (text) => highlightJavaLineWithCalls(text, searchTerm, invokeMatcher, fieldMatcher);
    const cmt = srcLineCommentChrome(commentMethodKey, li);
    if (fold && fold.kind === 'array') {
      const btn = `<button type="button" class="src-fold-btn" data-fold-key="${escapeAttr(prefix + ':' + li)}" aria-expanded="${folded ? 'false' : 'true'}" title="${folded ? 'Expand' : 'Collapse'}">${folded ? '▶' : '▼'}</button>`;
      if (folded) {
        const stub = `${fold.prefix} /* ${fold.count} values */ ${fold.suffix}`;
        html += `<div class="src-line src-line-foldable is-folded" data-line="${li}">${lineNo}${btn}<span class="src-line-code">${paint(stub)}</span>${cmt}</div>`;
      } else {
        html += `<div class="src-line src-line-foldable" data-line="${li}">${lineNo}${btn}<span class="src-line-code">${paint(lines[li])}</span>${cmt}</div>`;
      }
      li++;
      continue;
    }
    if (fold && fold.kind === 'brace') {
      const btn = `<button type="button" class="src-fold-btn" data-fold-key="${escapeAttr(prefix + ':' + li)}" aria-expanded="${folded ? 'false' : 'true'}" title="${folded ? 'Expand block' : 'Collapse block'}">${folded ? '▶' : '▼'}</button>`;
      const openLine = lines[li];
      const braceIdx = openLine.lastIndexOf('{');
      if (folded) {
        const closeLine = lines[fold.end];
        const endTrim = closeLine.trimStart();
        const stubLine = braceIdx >= 0
          ? openLine.slice(0, braceIdx + 1) + ' … ' + endTrim
          : openLine + ' …';
        // Keep invoke-matcher order in sync with hidden body lines (don't paint twice).
        for (const site of findSourceCallSites(openLine)) {
          resolveSourceCallSite(site, invokeMatcher);
        }
        for (const site of findSourceFieldSites(openLine)) {
          resolveSourceFieldSite(site, fieldMatcher);
        }
        for (let k = li + 1; k <= fold.end; k++) {
          for (const site of findSourceCallSites(lines[k])) {
            resolveSourceCallSite(site, invokeMatcher);
          }
          for (const site of findSourceFieldSites(lines[k])) {
            resolveSourceFieldSite(site, fieldMatcher);
          }
        }
        html += `<div class="src-line src-line-foldable is-folded" data-line="${li}">${lineNo}${btn}<span class="src-line-code">${highlightJavaLine(stubLine, searchTerm)}</span>${cmt}</div>`;
        li = fold.end + 1;
        continue;
      }
      html += `<div class="src-line src-line-foldable" data-line="${li}">${lineNo}${btn}<span class="src-line-code">${paint(lines[li])}</span>${cmt}</div>`;
      li++;
      continue;
    }
    html += `<div class="src-line" data-line="${li}">${lineNo}<span class="src-fold-spacer"></span><span class="src-line-code">${paint(lines[li])}</span>${cmt}</div>`;
    li++;
  }
  html += '</div>';
  return html;
}

function openMethodFromUiEvent(e) {
  const block = e.target.closest('.source-method-block, .bytecode-method-block, .source-method-view, .bytecode-method-view');
  if (!block || block.classList.contains('source-fields-block')) return false;
  const classIdx = parseInt(block.getAttribute('data-class-idx'), 10);
  const methodIdx = parseInt(block.getAttribute('data-method-idx'), 10);
  if (Number.isNaN(classIdx) || Number.isNaN(methodIdx)) return false;
  // Already on this method — still expand CFG / focus graph.
  if (codeViewClassIdx === classIdx && codeViewMethodIdx === methodIdx) {
    ensureCfgPaneExpanded();
    const ctx = getCodeViewContext();
    const method = ctx?.classes?.[classIdx]?.methods?.[methodIdx];
    if (method) requestAnimationFrame(() => renderCfgGraph(method));
    return true;
  }
  selectCodeViewMethod(classIdx, methodIdx, { expandCfg: true });
  return true;
}

function wireSourceFoldClicks() {
  if (!sourceCode || sourceCode._foldWired) return;
  sourceCode._foldWired = true;
  sourceCode.addEventListener('click', (e) => {
    // Official API docs (new tab) — don't treat as in-app navigation / ident pin
    if (e.target.closest('a.src-api-doc')) return;
    const backClass = e.target.closest('[data-back-class]');
    if (backClass && sourceCode.contains(backClass)) {
      e.preventDefault();
      e.stopPropagation();
      goBackToClassView();
      return;
    }
    const callLink = e.target.closest('a.src-call-link');
    if (callLink && sourceCode.contains(callLink)) {
      e.preventDefault();
      e.stopPropagation();
      const cls = callLink.getAttribute('data-class') || '';
      const method = callLink.getAttribute('data-method') || '';
      const hint = callLink.getAttribute('data-hint') || '';
      navigateToSourceCall(cls, method, hint);
      return;
    }
    const fieldLink = e.target.closest('a.src-field-link');
    if (fieldLink && sourceCode.contains(fieldLink)) {
      e.preventDefault();
      e.stopPropagation();
      const idx = parseInt(fieldLink.getAttribute('data-field-idx'), 10);
      if (!Number.isNaN(idx)) openFieldXrefsPanel(idx);
      return;
    }
    const commentHit = e.target.closest('[data-src-comment], [data-src-comment-add]');
    if (commentHit && sourceCode.contains(commentHit)) {
      e.preventDefault();
      e.stopPropagation();
      editSourceLineComment(
        commentHit.getAttribute('data-method-key') || '',
        Number(commentHit.getAttribute('data-line'))
      );
      return;
    }
    const btn = e.target.closest('.src-fold-btn');
    if (btn && sourceCode.contains(btn)) {
      e.preventDefault();
      e.stopPropagation();
      const key = btn.getAttribute('data-fold-key');
      if (!key) return;
      if (sourceFoldedStarts.has(key)) sourceFoldedStarts.delete(key);
      else sourceFoldedStarts.add(key);
      renderSourceWithSearch();
      return;
    }
    const openCfg = e.target.closest('[data-open-cfg], .method-block-header');
    if (openCfg && sourceCode.contains(openCfg) && !e.target.closest('[data-back-class]')) {
      // In single-method view, header click should not re-select; only Open CFG / back.
      if (openCfg.closest('.source-method-view') && !e.target.closest('[data-open-cfg]')) return;
      e.preventDefault();
      e.stopPropagation();
      openMethodFromUiEvent(e);
      return;
    }
  });

  // Hover an identifier (e.g. `email`) → highlight every usage in this method.
  // Click to pin; click again or Esc to clear.
  let hoverRaf = 0;
  sourceCode.addEventListener('mousemove', (e) => {
    if (hoverRaf) cancelAnimationFrame(hoverRaf);
    hoverRaf = requestAnimationFrame(() => {
      hoverRaf = 0;
      if (!sourceCode.contains(e.target)) return;
      if (e.target.closest('.src-fold-btn, .method-block-header, .src-line-no, .src-line-comment, .src-line-comment-add, [data-open-cfg], [data-back-class]')) {
        return;
      }
      const scope =
        e.target.closest('.source-method-block, .source-method-view') ||
        sourceCode.querySelector('.src-foldable') ||
        sourceCode;
      const identEl = e.target.closest('.src-ident');
      if (identEl && scope.contains(identEl)) {
        setSourceIdentHover(identEl.dataset.ident, scope, identEl);
        return;
      }
      // Fallback when pointer is on punctuation between tokens
      if (e.target.closest('.src-line-code')) {
        const word = getWordAtPoint(sourceCode, e.clientX, e.clientY);
        if (word && isValidJavaSimpleName(word) && !JAVA_KEYWORDS.has(word)) {
          let primary;
          try {
            primary = scope.querySelector(`.src-ident[data-ident="${CSS.escape(word)}"]`);
          } catch (_) {
            primary = scope.querySelector(`.src-ident[data-ident="${word.replace(/"/g, '\\"')}"]`);
          }
          setSourceIdentHover(word, scope, primary);
          return;
        }
      }
      if (sourceIdentHighlight && !sourceIdentPinned) {
        clearSourceIdentHighlights(scope);
        sourceIdentHighlight = null;
        sourceIdentHoverScope = null;
      }
    });
  });
  sourceCode.addEventListener('mouseleave', () => {
    if (hoverRaf) cancelAnimationFrame(hoverRaf);
    hoverRaf = 0;
    if (sourceIdentPinned) return; // keep pinned highlight
    clearSourceIdentHighlights(sourceCode);
    sourceIdentHighlight = null;
    sourceIdentHoverScope = null;
  });
  sourceCode.addEventListener('click', (e) => {
    if (e.target.closest('.src-fold-btn, .method-block-header, .src-line-no, .src-line-comment, .src-line-comment-add, [data-open-cfg], [data-back-class], a.src-call-link, a.src-field-link')) {
      return;
    }
    const scope =
      e.target.closest('.source-method-block, .source-method-view') ||
      sourceCode.querySelector('.src-foldable') ||
      sourceCode;
    const identEl = e.target.closest('.src-ident');
    if (identEl && scope.contains(identEl) && identEl.dataset.ident) {
      e.preventDefault();
      pinSourceIdent(identEl.dataset.ident, scope, identEl);
      return;
    }
    // Click empty background clears pin
    if (sourceIdentPinned && !e.target.closest('.src-ident')) {
      clearPinnedSourceIdent();
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sourceIdentPinned && !e.target.closest('input, textarea, select')) {
      clearPinnedSourceIdent();
    }
  });

  sourceCode.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const header = e.target.closest('.method-block-header');
    if (!header || !sourceCode.contains(header)) return;
    if (header.closest('.source-method-view')) return;
    e.preventDefault();
    openMethodFromUiEvent(e);
  });
}

/** Re-render source pane from currentSourceRaw/currentSourceBlocks and sourceSearchQuery, update count and match list. */
function renderSourceWithSearch() {
  if (!sourceCode) return;
  wireSourceFoldClicks();
  if (currentSourceBlocks && currentSourceBlocks.length > 0) {
    sourceCode.className = 'source-code language-java src-has-folds src-multi-methods';
    const q = sourceSearchQuery || '';
    const selectedMi = codeViewMethodIdx;
    sourceCode.innerHTML = currentSourceBlocks.map((b, bi) => {
      const highlighted = renderFoldableJavaSource(b.raw, q, 'm' + bi, {
        classIdx: b.classIdx,
        methodIdx: b.methodIdx,
      });
      if (b.isFields || b.methodIdx == null) {
        return `<div class="source-method-block source-fields-block" data-class-idx="${b.classIdx}" data-method-name="fields"><div class="method-block-header source-fields-header" tabindex="-1"><span class="method-block-title">fields</span></div>${highlighted}</div>`;
      }
      const selected = selectedMi != null && Number(b.methodIdx) === Number(selectedMi) ? ' is-selected' : '';
      return `<div class="source-method-block${selected}" data-class-idx="${b.classIdx}" data-method-idx="${b.methodIdx}" data-method-name="${escapeAttr(b.name)}">${renderMethodBlockHeader(b.name, { openCfg: true, hint: 'Open CFG' })}${highlighted}</div>`;
    }).join('');
    sourceSearchMatches = sourceCode.querySelectorAll ? Array.from(sourceCode.querySelectorAll('mark.source-search-hit')) : [];
    if (sourceSearchCount) {
      sourceSearchCount.textContent = sourceSearchMatches.length > 0
        ? (sourceSearchMatchIndex + 1) + ' / ' + sourceSearchMatches.length
        : (sourceSearchQuery.trim() ? '0 matches' : '');
    }
    if (sourceSearchMatches.length > 0) {
      sourceSearchMatches.forEach((m, i) => m.classList.toggle('current', i === sourceSearchMatchIndex));
      const target = sourceSearchMatches[sourceSearchMatchIndex];
      if (target && sourceCode.parentElement) target.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    restoreSourceIdentHighlight();
    return;
  }
  if (!currentSourceRaw) {
    sourceCode.className = 'source-code';
    sourceCode.innerHTML = bytecodeEmptyHtml('No source yet', 'Select a method — or open All methods and click a method header / Open CFG');
    if (sourceSearchCount) sourceSearchCount.textContent = '';
    sourceSearchMatches = [];
    sourceIdentHighlight = null;
    return;
  }
  const looksLikeJava = currentSourceRaw.length > 20 && (
    /\b(public|private|protected|void|class|interface|return|import|package)\b/.test(currentSourceRaw) ||
    /\b(if|else|for|while|try|catch|throw|new)\s*[\(\{]/.test(currentSourceRaw) ||
    /^\s*\/\*|^\s*\/\//m.test(currentSourceRaw) ||
    /=\s*new\s+[\w.]+\[/.test(currentSourceRaw)
  );
  if (looksLikeJava) {
    sourceCode.className = 'source-code language-java src-has-folds';
    const methodRef = currentSourceMethodMeta
      ? { classIdx: currentSourceMethodMeta.classIdx, methodIdx: currentSourceMethodMeta.methodIdx }
      : (codeViewMethodIdx != null ? { classIdx: codeViewClassIdx, methodIdx: codeViewMethodIdx } : null);
    const body = renderFoldableJavaSource(currentSourceRaw, sourceSearchQuery, 's', methodRef);
    if (currentSourceMethodMeta) {
      const m = currentSourceMethodMeta;
      sourceCode.innerHTML = `<div class="source-method-view" data-class-idx="${m.classIdx}" data-method-idx="${m.methodIdx}" data-method-name="${escapeAttr(m.name || '')}">${renderMethodBlockHeader(m.name || 'method', { openCfg: true, hint: 'Show CFG', backToClass: true })}${body}</div>`;
    } else {
      sourceCode.innerHTML = body;
    }
  } else {
    sourceCode.className = 'source-code';
    const q = sourceSearchQuery.trim();
    if (q) {
      const escapedRe = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(escapedRe, 'gi');
      const withMarks = currentSourceRaw.replace(re, (match) => MARK_START + match + MARK_END);
      const html = escapeHtml(withMarks).replace(/\n/g, '<br>')
        .split(MARK_START).join('<mark class="source-search-hit">')
        .split(MARK_END).join('</mark>');
      sourceCode.innerHTML = html;
    } else {
      sourceCode.textContent = currentSourceRaw;
    }
  }
  sourceSearchMatches = sourceCode.querySelectorAll ? Array.from(sourceCode.querySelectorAll('mark.source-search-hit')) : [];
  if (sourceSearchCount) {
    sourceSearchCount.textContent = sourceSearchMatches.length > 0
      ? (sourceSearchMatchIndex + 1) + ' / ' + sourceSearchMatches.length
      : (sourceSearchQuery.trim() ? '0 matches' : '');
  }
  if (sourceSearchMatches.length > 0) {
    sourceSearchMatches.forEach((m, i) => m.classList.toggle('current', i === sourceSearchMatchIndex));
    const target = sourceSearchMatches[sourceSearchMatchIndex];
    if (target && sourceCode.parentElement) target.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }
  restoreSourceIdentHighlight();
}

/** Set source tab content: when el is the Code tab source pane, store raw and render with highlight + search. */
function setSourceContent(el, text) {
  if (el === sourceCode) {
    el.classList.remove('res-xml', 'manifest-xml');
  }
  if (text == null || text === '') {
    if (el === sourceCode) {
      currentSourceRaw = '';
      currentSourceBlocks = null;
      sourceFoldedStarts = new Set();
      sourceSearchMatches = [];
      sourceIdentHighlight = null;
      if (sourceSearchCount) sourceSearchCount.textContent = '';
      renderSourceWithSearch();
    } else if (el) {
      el.textContent = '';
      el.className = 'source-code';
    }
    return;
  }
  const s = String(text);
  if (el === sourceCode) {
    currentSourceRaw = s;
    currentSourceBlocks = null;
    sourceFoldedStarts = new Set();
    sourceSearchMatchIndex = 0;
    sourceIdentHighlight = null;
    renderSourceWithSearch();
  } else if (el) {
    const looksLikeJava = s.length > 20 && (
      /\b(public|private|protected|void|class|interface|return|import|package)\b/.test(s) ||
      /\b(if|else|for|while|try|catch|throw|new)\s*[\(\{]/.test(s) ||
      /^\s*\/\*|^\s*\/\//m.test(s)
    );
    if (looksLikeJava) {
      el.className = 'source-code language-java';
      el.innerHTML = applySourceHighlight(s, '');
    } else {
      el.className = 'source-code';
      el.textContent = s;
    }
  }
}

/** Set source pane to "all methods" view with one block per method (enables resolving method from click). */
function setSourceContentAllMethods(el, classIdx, methodsWithSource) {
  if (el !== sourceCode || !Array.isArray(methodsWithSource)) return;
  currentSourceRaw = '';
  currentSourceMethodMeta = null;
  const fieldsSrc = formatClassFieldsSource(classIdx);
  currentSourceBlocks = [];
  if (fieldsSrc) {
    currentSourceBlocks.push({
      classIdx,
      methodIdx: null,
      name: 'fields',
      raw: fieldsSrc,
      isFields: true,
    });
  }
  for (let methodIdx = 0; methodIdx < methodsWithSource.length; methodIdx++) {
    const m = methodsWithSource[methodIdx];
    currentSourceBlocks.push({
      classIdx,
      methodIdx,
      name: m.name || ('method ' + methodIdx),
      raw: m.decompilation || '(no body)',
    });
  }
  sourceFoldedStarts = new Set();
  sourceSearchMatchIndex = 0;
  sourceIdentHighlight = null;
  renderSourceWithSearch();
}

/** Build index: class name -> { file, classIdx } from all DEX files in current APK. */
async function buildApkClassIndex() {
  resetApkClassIndexMaps();
  apkDexStats = { dexFiles: 0, classes: 0, methods: 0, ready: false, totalDex: 0, current: 0, currentName: '' };
  updateStatusBar();
  if (!currentApkBytes || currentType !== 'apk' || !Array.isArray(currentData?.files)) {
    debug('[buildApkClassIndex] skip (no apk/files)');
    clearUiActivity('index');
    return;
  }
  // Prefer primary DEXes first so Info/manifest links work before the whole multidex finishes.
  const dexFiles = listApkDexNames(currentData.files).map((name) => ({ name }));
  apkDexStats.totalDex = dexFiles.length;
  const tIdx = timer();
  debug('[buildApkClassIndex] start dexFiles=', dexFiles.length, '(compact index)');
  setUiActivity('index', 'Indexing classes', `0/${dexFiles.length} DEX`);
  setWorkNotice(
    'Indexing classes in this browser',
    dexFiles.length > 4
      ? `${dexFiles.length} DEX files — large APKs can pause the UI for a few seconds between steps. Progress is in the bottom status bar.`
      : 'Building a class map so Manifest links and package browse work. Progress is in the bottom status bar.',
    { tone: 'info', sticky: true }
  );
  await ensureMainWasm();
  // Let first paint / auto-open primary DEX land before we hog extract + worker.
  await new Promise((r) => setTimeout(r, 300));
  if (currentType !== 'apk') {
    clearUiActivity('index');
    setWorkNotice(null);
    return;
  }

  for (let i = 0; i < dexFiles.length; i++) {
    // Index runs on the parse worker and never waits on securityScanBusy —
    // security uses a separate worker so browse stays responsive.
    const f = dexFiles[i];
    const label = shortDexLabel(f.name);
    const prog = `${i + 1}/${dexFiles.length}`;
    apkDexStats.current = i + 1;
    apkDexStats.currentName = f.name || '';
    const classBit = apkDexStats.classes ? ` · ${formatCount(apkDexStats.classes)} classes` : '';
    setUiActivity('index', 'Extracting DEX', `${prog} · ${label}${classBit}`);
    await yieldToUiFrame();
    let bytes;
    try {
      bytes = get_apk_file_content(currentApkBytes, f.name);
    } catch (e) {
      warn('[buildApkClassIndex] extract failed', f.name, e);
      continue;
    }
    await yieldToUiFrame();
    if (!bytes || bytes.length === 0) continue;
    try {
      setUiActivity(
        'index',
        'Indexing classes',
        `${prog} · ${label} · ${formatFileSize(bytes.length)}${classBit}`
      );
      // Compact worker index — NOT full parse_file (avoids multi-MB freezes).
      const result = await indexDexClassesInWorker(bytes);
      // Drop extract buffer ASAP so GC can reclaim during long multidex indexes.
      bytes = null;
      setUiActivity('index', 'Merging class index', `${prog} · ${label}${classBit}`);
      await yieldToUiFrame();
      const list = result?.ok && Array.isArray(result?.data?.classes) ? result.data.classes : null;
      if (!list) continue;
      apkDexStats.dexFiles += 1;
      // Insert in chunks so large class maps don't block clicks.
      const CHUNK = 400;
      for (let c = 0; c < list.length; c++) {
        const entry = list[c];
        const name = entry?.name;
        if (name) putApkClassIndexEntry(name, f.name, c, apkClassToDex, entry?.method_count);
        apkDexStats.classes += 1;
        apkDexStats.methods += Number(entry?.method_count) || 0;
        if ((c + 1) % CHUNK === 0) {
          if ((c + 1) % (CHUNK * 4) === 0) {
            setUiActivity(
              'index',
              'Merging class index',
              `${prog} · ${label} · ${formatCount(c + 1)}/${formatCount(list.length)}`
            );
          }
          await yieldToUiFrame();
        }
      }
    } catch (e) {
      warn('[buildApkClassIndex] skip DEX', f.name, e);
    }
    await yieldToUiFrame();
    if ((i + 1) % 3 === 0 || i === 0 || i === dexFiles.length - 1) {
      debug('[buildApkClassIndex] progress', (i + 1) + '/' + dexFiles.length,
        'classes=', apkDexStats.classes, 'methods=', apkDexStats.methods);
      updateStatusBar();
    }
  }
  apkDexStats.ready = true;
  apkDexStats.currentName = '';
  tIdx('buildApkClassIndex total');
  debug('[buildApkClassIndex] done classes=', apkDexStats.classes, 'methods=', apkDexStats.methods);
  setUiActivity(
    'index',
    'Linking Manifest',
    `${formatCount(apkDexStats.classes)} classes · ${apkDexStats.dexFiles} DEX`
  );
  setWorkNotice(
    'Linking Manifest',
    'Connecting component names to indexed classes. Large manifests skip full XML rewrites so the tab stays usable.',
    { tone: 'info', sticky: true }
  );
  updateStatusBar();
  await yieldToUiFrame();
  try {
    await measureAsync('applyManifestClassLinksNowAsync', () =>
      applyManifestClassLinksNowAsync({ activityId: 'index' })
    );
  } catch (e) {
    warn('[buildApkClassIndex] manifest link failed', e);
  }
  // Warm package-count cache in chunks so the first tree paint after Ready stays responsive.
  setUiActivity('index', 'Preparing packages', `${formatCount(apkDexStats.classes)} classes`);
  setWorkNotice(
    'Preparing package list',
    `${formatCount(apkDexStats.classes)} classes — building the package dropdown in chunks so the UI can keep responding.`,
    { tone: 'info', sticky: true }
  );
  await warmApkPackageCountsCache();
  clearUiActivity('index');
  setUiActivity('ready', 'Ready', `${formatCount(apkDexStats.classes)} classes indexed`);
  updateStatusBar();
  const pkgN = Object.keys(apkPackageCountsCache || apkClassesByPackage || {}).length;
  setWorkNotice(
    `Ready — ${formatCount(apkDexStats.classes)} classes indexed`,
    pkgN
      ? `Select a package (${formatCount(pkgN)} available) or use search. Huge packages show a capped list so the browser does not freeze.`
      : 'Use Classes → package dropdown or search to browse. Method bodies load on demand when you open a method.',
    { tone: 'ok', autoHideMs: 14000 }
  );
  // Defer unified tree rebuild to idle — never sync-walk the alias map.
  if (currentType === 'apk' && apkLeftMode === 'classes' && !apkDexFilter) {
    const schedule = typeof requestIdleCallback === 'function'
      ? (fn) => requestIdleCallback(fn, { timeout: 800 })
      : (fn) => setTimeout(fn, 0);
    schedule(() => {
      if (currentType !== 'apk' || apkLeftMode !== 'classes' || apkDexFilter) return;
      try { renderApkClassTree(); } catch (_) {}
    });
  }
  setTimeout(() => clearUiActivity('ready'), 4000);
}

/** Build / refresh apkPackageCountsCache without blocking the UI for Facebook-scale indexes. */
async function warmApkPackageCountsCache() {
  if (apkPackageCountsCache) return apkPackageCountsCache;
  const counts = Object.create(null);
  const pkgs = Object.keys(apkClassesByPackage);
  const CHUNK = 80;
  for (let p = 0; p < pkgs.length; p++) {
    const pkg = pkgs[p];
    const list = apkClassesByPackage[pkg];
    let n = 0;
    for (let i = 0; i < list.length; i++) {
      if (shouldShowClassInUi(list[i]?.className || '')) n++;
    }
    if (n) counts[pkg] = n;
    if ((p + 1) % CHUNK === 0) {
      setUiActivity(
        'index',
        'Preparing packages',
        `${formatCount(p + 1)}/${formatCount(pkgs.length)} packages`
      );
      await yieldToUiFrame();
      if (currentType !== 'apk') return null;
    }
  }
  apkPackageCountsCache = counts;
  return counts;
}

/** Return a promise that resolves when apkClassToDex is ready for current APK. */
function ensureApkClassIndex() {
  if (currentType !== 'apk' || !currentApkBytes) return Promise.resolve();
  if (!apkClassIndexPromise) {
    apkClassIndexPromise = buildApkClassIndex().catch((e) => {
      warn('[buildApkClassIndex] failed', e);
      clearUiActivity('index');
      apkDexStats.ready = true;
      updateStatusBar();
      throw e;
    });
  }
  return apkClassIndexPromise;
}

/** Resolve manifest class value (e.g. ".MainActivity" -> "com.example.MainActivity"). */
function resolveManifestClass(value, pkg) {
  const v = (value || '').trim();
  if (!v) return v;
  if (v.startsWith('.')) return (pkg || '') + v;
  // Bare class name without dots is relative to the manifest package
  if (pkg && !v.includes('.')) return `${pkg}.${v}`;
  return v;
}

/** Attributes that typically hold Java/Kotlin class names in AndroidManifest. */
const MANIFEST_CLASS_ATTRS = new Set([
  'name', 'android:name',
  'targetActivity', 'android:targetActivity',
  'parentActivityName', 'android:parentActivityName',
  'backupAgent', 'android:backupAgent',
  'appComponentFactory', 'android:appComponentFactory',
  'zygotePreloadName', 'android:zygotePreloadName',
]);

function looksLikeManifestClassValue(raw) {
  const v = (raw || '').trim();
  if (!v || v.length < 2) return false;
  if (v.startsWith('@') || v.startsWith('?') || v.startsWith('#') || v.startsWith('0x')) return false;
  if (/^https?:\/\//i.test(v)) return false;
  if (v.includes('/') && !v.includes('.')) return false; // permission-like
  // .Relative, com.foo.Bar, Foo$Inner, or bare ClassName
  return /^\.?[A-Za-z_][\w.$]*$/.test(v);
}

/**
 * O(1) class index lookup. Never scans the whole map — Facebook-scale APKs have
 * 100k–300k+ classes; a linear miss-path freezes the UI after indexing finishes.
 */
function lookupApkClass(resolved, classToDex = apkClassToDex) {
  if (!resolved || !classToDex) return null;
  const keys = classNameLookupKeys(resolved);
  for (const key of keys) {
    const direct = classToDex[key];
    if (direct) {
      return {
        file: direct.file,
        classIdx: direct.classIdx,
        name: direct.className || key,
      };
    }
  }
  return null;
}

/** Small set of equivalent spellings for O(1) map hits ($ vs . inners). */
function classNameLookupKeys(name) {
  const x = String(name || '').trim();
  if (!x) return [];
  const keys = [x];
  const asDots = x.replace(/\$/g, '.');
  if (asDots !== x) keys.push(asDots);
  // com.foo.Bar.Inner ↔ com.foo.Bar$Inner (only flip dots before Capital segments)
  if (/\.[A-Z]/.test(x)) {
    const asInner = x.replace(/\.([A-Z])/g, '$$$1');
    if (asInner !== x) keys.push(asInner);
  }
  return keys;
}

/** Clear APK-wide class index + package buckets (call whenever apkClassToDex is reset). */
function resetApkClassIndexMaps() {
  apkClassToDex = {};
  apkClassesByPackage = Object.create(null);
  apkPackageCountsCache = null;
}

/** Insert into apkClassToDex under primary + $→. alias (keeps lookups O(1)). */
function putApkClassIndexEntry(name, file, classIdx, map = apkClassToDex, methodCount = 0) {
  if (!name || !map) return;
  // Already indexed under this spelling — do not duplicate package buckets.
  if (map[name]) return;
  const entry = {
    file,
    classIdx,
    className: name,
    methodCount: Number(methodCount) || 0,
  };
  map[name] = entry;
  const asDots = name.replace(/\$/g, '.');
  if (asDots !== name && map[asDots] == null) map[asDots] = entry;

  // Maintain package→entries for O(packages) dropdown / O(package size) lists.
  if (map === apkClassToDex) {
    const pkg = getPackageFromClassName(name);
    if (!apkClassesByPackage[pkg]) apkClassesByPackage[pkg] = [];
    apkClassesByPackage[pkg].push(entry);
    apkPackageCountsCache = null;
  }
}

/** Unique class-index rows via package buckets (never Object.values on the alias map). */
function iterApkClassIndexUnique(map = apkClassToDex) {
  if (map !== apkClassToDex) {
    // Fallback for alternate maps (tests / partial): still unique by identity.
    const seen = new Set();
    const out = [];
    for (const entry of Object.values(map || {})) {
      if (!entry || typeof entry !== 'object' || seen.has(entry)) continue;
      seen.add(entry);
      const name = entry.className || '';
      if (!name) continue;
      out.push({
        name,
        file: entry.file || '',
        classIdx: entry.classIdx,
        methodCount: Number(entry.methodCount) || 0,
      });
    }
    return out;
  }
  const out = [];
  for (const pkg of Object.keys(apkClassesByPackage)) {
    const list = apkClassesByPackage[pkg];
    for (let i = 0; i < list.length; i++) {
      const entry = list[i];
      const name = entry?.className || '';
      if (!name) continue;
      out.push({
        name,
        file: entry.file || '',
        classIdx: entry.classIdx,
        methodCount: Number(entry.methodCount) || 0,
      });
    }
  }
  return out;
}

/**
 * Wrap class names in manifest XML with links to the corresponding DEX class.
 * Links name / targetActivity / parentActivityName / etc. when they resolve in the APK index.
 * @returns {{ linked: number, unresolved: number }}
 */
function injectManifestClassLinks(container, pkg, classToDex) {
  // Sync path kept for small / partial updates; heavy finals use the async variant.
  const stats = { linked: 0, unresolved: 0 };
  if (!container || !classToDex || typeof classToDex !== 'object') return stats;
  unwrapManifestClassLinks(container);
  const spans = collectManifestClassValueSpans(container);
  for (const span of spans) {
    applyManifestClassLinkToSpan(span, pkg, classToDex, stats);
  }
  return stats;
}

function unwrapManifestClassLinks(container) {
  container.querySelectorAll('a.manifest-class-link, span.manifest-class-unresolved').forEach((el) => {
    const span = document.createElement('span');
    span.className = 'xml-value xml-class-ref';
    span.textContent = el.textContent;
    el.replaceWith(span);
  });
}

/**
 * Collect candidate class-value spans.
 * Prefer `.xml-class-ref` (marked at highlight time) — never walk every `.xml-value`
 * on Facebook-scale manifests (tens of thousands of attrs → multi-second freezes).
 */
function collectManifestClassValueSpans(container) {
  const out = [];
  const seen = new Set();
  const consider = (span) => {
    if (!span || seen.has(span)) return;
    let prev = span.previousSibling;
    while (prev && prev.nodeType !== 1) prev = prev.previousSibling;
    if (!prev || !prev.classList?.contains('xml-attr')) return;
    const attrName = (prev.textContent || '').trim();
    const raw = (span.textContent || '').trim();
    if (!MANIFEST_CLASS_ATTRS.has(attrName) && !(attrName.endsWith(':name') && looksLikeManifestClassValue(raw))) {
      return;
    }
    if (!looksLikeManifestClassValue(raw)) return;
    seen.add(span);
    out.push(span);
  };
  // Highlight already tags dotted / .Relative values as xml-class-ref.
  container.querySelectorAll('.xml-value.xml-class-ref').forEach(consider);
  return out;
}

function applyManifestClassLinkToSpan(span, pkg, classToDex, stats) {
  if (!span?.isConnected) return;
  const raw = (span.textContent || '').trim();
  const resolved = resolveManifestClass(raw, pkg);
  const info = lookupApkClass(resolved, classToDex);
  if (info) {
    const a = document.createElement('a');
    a.href = '#';
    a.className = 'manifest-class-link';
    a.title = `Open ${info.file} → ${info.name}`;
    a.dataset.file = info.file;
    a.dataset.classIdx = String(info.classIdx);
    a.dataset.class = info.name;
    a.textContent = span.textContent;
    span.replaceWith(a);
    stats.linked += 1;
  } else {
    const u = document.createElement('span');
    u.className = 'manifest-class-unresolved';
    u.title = `Class not found in DEX index: ${resolved}`;
    u.textContent = span.textContent;
    span.replaceWith(u);
    stats.unresolved += 1;
  }
}

/** Manifest XML big enough that full DOM re-linking freezes the UI (Facebook ~1MB). */
function isLargeManifestXml(xml) {
  return typeof xml === 'string' && xml.length >= 100000;
}

/** Chunked so Facebook-size manifests don't freeze after indexing hits N/N. */
async function injectManifestClassLinksAsync(container, pkg, classToDex, opts = {}) {
  const stats = { linked: 0, unresolved: 0, skippedXml: false };
  if (!container || !classToDex || typeof classToDex !== 'object') return stats;
  const actId = opts.activityId || 'manifest-link';

  // Mega manifests: skip rewriting every XML value node — components strip covers navigation.
  if (opts.skipXmlBody) {
    stats.skippedXml = true;
    return stats;
  }

  unwrapManifestClassLinks(container);
  await yieldToUiFrame();
  const spans = collectManifestClassValueSpans(container);
  if (!spans.length) return stats;

  // Tiny manifests finish in one tick — avoid a sticky "scanning…" status that never progresses.
  if (spans.length <= 40) {
    for (const span of spans) applyManifestClassLinkToSpan(span, pkg, classToDex, stats);
    return stats;
  }

  setUiActivity(actId, 'Linking Manifest', `0/${formatCount(spans.length)} attrs`);
  await yieldToUiFrame();
  const CHUNK = spans.length > 800 ? 120 : 60;
  for (let i = 0; i < spans.length; i++) {
    applyManifestClassLinkToSpan(spans[i], pkg, classToDex, stats);
    if ((i + 1) % CHUNK === 0 || i + 1 === spans.length) {
      setUiActivity(
        actId,
        'Linking Manifest',
        `${formatCount(i + 1)}/${formatCount(spans.length)} attrs`
      );
      await yieldToUiFrame();
    }
  }
  return stats;
}

function updateManifestLinksToolbarChip(stats) {
  const toolbar = document.getElementById('manifest-toolbar');
  if (!toolbar || toolbar.hidden) return;
  let chip = toolbar.querySelector('.res-chip-manifest-links');
  if (!chip) {
    const meta = toolbar.querySelector('.res-viewer-meta');
    if (meta) {
      chip = document.createElement('span');
      chip.className = 'res-chip res-chip-manifest-links';
      meta.appendChild(chip);
    }
  }
  if (!chip) return;
  const indexing = !apkDexStats.ready;
  if (stats?.skippedXml) {
    chip.innerHTML = `<span class="res-chip-k">classes</span> components linked`
      + (typeof stats.linked === 'number' ? ` · ${stats.linked}` : '')
      + (indexing ? ' · indexing…' : '')
      + ' · large XML';
    chip.title = 'Large manifest: use the Components strip (or outline) to open classes. Full XML body links were skipped to keep the UI responsive.';
    return;
  }
  chip.innerHTML = `<span class="res-chip-k">classes</span> ${stats.linked} linked`
    + (stats.unresolved ? ` · ${stats.unresolved} missing` : '')
    + (indexing ? ' · indexing…' : '');
  chip.title = 'Click underlined class names or components below to open them in Code';
}

/** Apply manifest class links from whatever of apkClassToDex is ready (partial OK). */
function applyManifestClassLinksNow() {
  if (currentType !== 'apk') return;
  const pkg = currentData?.manifest?.package
    || (typeof apkManifestXml === 'string' && (apkManifestXml.match(/\bpackage="([^"]+)"/) || [])[1])
    || '';
  const xml = (typeof apkManifestXml === 'string' && !apkManifestXml.startsWith('(') && !apkManifestXml.startsWith('No '))
    ? apkManifestXml
    : '';
  const codeEl = ensureManifestViewerStructure().code;
  if (!codeEl) return;
  const showingManifest = !apkExtractedFile
    || apkExtractedFile.kind !== 'axml'
    || apkExtractedFile.name === 'AndroidManifest.xml';
  if (!showingManifest || !xml) return;
  // Sync path must stay cheap — Facebook-size DOM rewrites freeze the UI mid-index.
  if (isLargeManifestXml(xml)) {
    renderManifestComponentsStrip(xml, pkg, apkClassToDex);
    updateManifestLinksToolbarChip({ linked: 0, unresolved: 0, skippedXml: true });
    return;
  }
  const stats = injectManifestClassLinks(codeEl, pkg, apkClassToDex);
  renderManifestComponentsStrip(xml, pkg, apkClassToDex);
  updateManifestLinksToolbarChip(stats);
  debug('[manifest] class links', stats, apkDexStats.ready ? 'ready' : 'partial');
}

async function applyManifestClassLinksNowAsync(opts = {}) {
  // Dedicated id so a late remount cannot leave the APK "index" task stuck forever
  // (refreshManifestClassLinks used to re-enter after Ready and never clear it).
  const actId = opts.activityId || 'manifest-link';
  const ownsActivity = actId === 'manifest-link';
  try {
    if (currentType !== 'apk') return;
    const pkg = currentData?.manifest?.package
      || (typeof apkManifestXml === 'string' && (apkManifestXml.match(/\bpackage="([^"]+)"/) || [])[1])
      || '';
    const xml = (typeof apkManifestXml === 'string' && !apkManifestXml.startsWith('(') && !apkManifestXml.startsWith('No '))
      ? apkManifestXml
      : '';
    const codeEl = ensureManifestViewerStructure().code;
    if (!codeEl) return;
    const showingManifest = !apkExtractedFile
      || apkExtractedFile.kind !== 'axml'
      || apkExtractedFile.name === 'AndroidManifest.xml';
    if (!showingManifest || !xml) return;

    const large = isLargeManifestXml(xml);
    setUiActivity(actId, 'Linking Manifest', large ? 'components' : 'class names');
    await yieldToUiFrame();

    // Components strip first (usable navigation) — cheap vs full XML DOM rewrite.
    await renderManifestComponentsStripAsync(xml, pkg, apkClassToDex, { activityId: actId });
    await yieldToUiFrame();

    const stats = await injectManifestClassLinksAsync(codeEl, pkg, apkClassToDex, {
      skipXmlBody: large,
      activityId: actId,
    });
    // Surface component linked count on large manifests.
    if (large) {
      const strip = document.getElementById('manifest-components');
      const linked = strip ? strip.querySelectorAll('.manifest-comp-chip.is-linked').length : 0;
      stats.linked = linked;
      stats.skippedXml = true;
    }
    updateManifestLinksToolbarChip(stats);
    debug('[manifest] class links async', stats, apkDexStats.ready ? 'ready' : 'partial', large ? 'large-xml' : '');
  } finally {
    if (ownsActivity) clearUiActivity(actId);
  }
}

/** Parse component entries from manifest XML for the quick-nav strip. */
function extractManifestComponents(xml, pkg) {
  if (!xml || typeof xml !== 'string') return [];
  const out = [];
  const tagRe = /<(activity-alias|activity|service|receiver|provider|instrumentation|application)\b([^>]*)\/?>/gi;
  let m;
  while ((m = tagRe.exec(xml)) !== null) {
    const kind = m[1].toLowerCase();
    const attrs = m[2] || '';
    const nameMatch = attrs.match(/\b(?:android:)?name\s*=\s*"([^"]+)"/i)
      || attrs.match(/\b(?:android:)?name\s*=\s*'([^']+)'/i);
    if (!nameMatch) continue;
    const raw = nameMatch[1];
    const resolved = resolveManifestClass(raw, pkg);
    out.push({ kind, raw, resolved });
  }
  return out;
}

function renderManifestComponentsStrip(xml, pkg, classToDex) {
  let strip = document.getElementById('manifest-components');
  const toolbar = document.getElementById('manifest-toolbar');
  const viewer = document.getElementById('manifest-viewer');
  if (!viewer) return;
  if (!strip) {
    strip = document.createElement('div');
    strip.id = 'manifest-components';
    strip.className = 'manifest-components';
    strip.hidden = true;
    if (toolbar?.parentNode) toolbar.insertAdjacentElement('afterend', strip);
    else viewer.prepend(strip);
  }
  const comps = extractManifestComponents(xml, pkg);
  if (!comps.length || currentType !== 'apk') {
    strip.hidden = true;
    strip.innerHTML = '';
    return;
  }
  strip.innerHTML = buildManifestComponentsStripHtml(comps, classToDex);
  strip.hidden = false;
}

function buildManifestComponentsStripHtml(comps, classToDex) {
  const byKind = {};
  for (const c of comps) {
    if (!byKind[c.kind]) byKind[c.kind] = [];
    byKind[c.kind].push(c);
  }
  const order = ['application', 'activity', 'activity-alias', 'service', 'receiver', 'provider', 'instrumentation'];
  let html = '<div class="manifest-components-head"><span class="manifest-components-title">Components</span>';
  html += `<span class="muted manifest-components-count">${comps.length}</span></div><div class="manifest-components-body">`;
  for (const kind of order) {
    const list = byKind[kind];
    if (!list?.length) continue;
    html += `<div class="manifest-comp-group"><span class="manifest-comp-kind">${escapeHtml(kind)}</span>`;
    for (const c of list) {
      const info = lookupApkClass(c.resolved, classToDex);
      const short = (c.raw.startsWith('.') ? c.raw : (c.resolved.split('.').pop() || c.raw));
      if (info) {
        html += `<button type="button" class="manifest-comp-chip is-linked" data-file="${escapeAttr(info.file)}" data-class-idx="${info.classIdx}" data-class="${escapeAttr(info.name)}" title="${escapeAttr(info.name)}">${escapeHtml(short)}</button>`;
      } else {
        html += `<span class="manifest-comp-chip is-missing" title="Not found: ${escapeAttr(c.resolved)}">${escapeHtml(short)}</span>`;
      }
    }
    html += '</div>';
  }
  html += '</div>';
  return html;
}

/** Yield while building the components strip on huge manifests (1000+ activities). */
async function renderManifestComponentsStripAsync(xml, pkg, classToDex, opts = {}) {
  const actId = opts.activityId || 'manifest-link';
  let strip = document.getElementById('manifest-components');
  const toolbar = document.getElementById('manifest-toolbar');
  const viewer = document.getElementById('manifest-viewer');
  if (!viewer) return { linked: 0, total: 0 };
  if (!strip) {
    strip = document.createElement('div');
    strip.id = 'manifest-components';
    strip.className = 'manifest-components';
    strip.hidden = true;
    if (toolbar?.parentNode) toolbar.insertAdjacentElement('afterend', strip);
    else viewer.prepend(strip);
  }

  const comps = extractManifestComponents(xml, pkg);
  if (!comps.length || currentType !== 'apk') {
    strip.hidden = true;
    strip.innerHTML = '';
    return { linked: 0, total: 0 };
  }

  // Cap chip explosion on extreme manifests; still link all via XML/outline for smaller apps.
  const MAX_CHIPS = 2500;
  const list = comps.length > MAX_CHIPS ? comps.slice(0, MAX_CHIPS) : comps;

  // Small apps: build strip sync without status-bar spam.
  if (list.length <= 80) {
    strip.innerHTML = buildManifestComponentsStripHtml(list, classToDex);
    strip.hidden = false;
    return { linked: strip.querySelectorAll('.manifest-comp-chip.is-linked').length, total: comps.length };
  }

  if (comps.length > 400) {
    setUiActivity(actId, 'Linking Manifest', `components 0/${formatCount(list.length)}`);
    await yieldToUiFrame();
  }

  const byKind = {};
  for (const c of list) {
    if (!byKind[c.kind]) byKind[c.kind] = [];
    byKind[c.kind].push(c);
  }
  const order = ['application', 'activity', 'activity-alias', 'service', 'receiver', 'provider', 'instrumentation'];
  let html = '<div class="manifest-components-head"><span class="manifest-components-title">Components</span>';
  html += `<span class="muted manifest-components-count">${comps.length}${comps.length > MAX_CHIPS ? ` (showing ${MAX_CHIPS})` : ''}</span></div><div class="manifest-components-body">`;
  let linked = 0;
  let done = 0;
  const YIELD_EVERY = 200;
  for (const kind of order) {
    const kindList = byKind[kind];
    if (!kindList?.length) continue;
    html += `<div class="manifest-comp-group"><span class="manifest-comp-kind">${escapeHtml(kind)}</span>`;
    for (const c of kindList) {
      const info = lookupApkClass(c.resolved, classToDex);
      const short = (c.raw.startsWith('.') ? c.raw : (c.resolved.split('.').pop() || c.raw));
      if (info) {
        linked += 1;
        html += `<button type="button" class="manifest-comp-chip is-linked" data-file="${escapeAttr(info.file)}" data-class-idx="${info.classIdx}" data-class="${escapeAttr(info.name)}" title="${escapeAttr(info.name)}">${escapeHtml(short)}</button>`;
      } else {
        html += `<span class="manifest-comp-chip is-missing" title="Not found: ${escapeAttr(c.resolved)}">${escapeHtml(short)}</span>`;
      }
      done += 1;
      if (done % YIELD_EVERY === 0) {
        setUiActivity(actId, 'Linking Manifest', `components ${formatCount(done)}/${formatCount(list.length)}`);
        await yieldToUiFrame();
      }
    }
    html += '</div>';
  }
  html += '</div>';
  setUiActivity(actId, 'Linking Manifest', 'rendering components');
  await yieldToUiFrame();
  strip.innerHTML = html;
  strip.hidden = false;
  return { linked, total: comps.length };
}

/** Re-apply class links + component strip after Manifest XML is (re)mounted. */
function refreshManifestClassLinks() {
  if (currentType !== 'apk') {
    const strip = document.getElementById('manifest-components');
    if (strip) { strip.hidden = true; strip.innerHTML = ''; }
    return Promise.resolve();
  }
  // Cheap sync pass with whatever of the class index is ready.
  applyManifestClassLinksNow();
  // Kick indexing, but do NOT run a second async link after it finishes —
  // buildApkClassIndex already does the final async pass. A duplicate pass was
  // leaving "Linking Manifest — scanning class attrs" stuck in the status bar.
  return new Promise((resolve) => {
    setTimeout(() => {
      ensureApkClassIndex().finally(resolve);
    }, 500);
  });
}

/** Show APK AndroidManifest.xml in the Manifest tab and wire class links. */
function showApkManifestInViewer(extraMeta) {
  if (apkManifestXml == null) return;
  const xml = apkManifestXml;
  const opts = {
    useManifestHost: true,
    title: 'AndroidManifest.xml',
    meta: extraMeta,
  };

  // Mid/large manifests: paint plain text first so the tab isn't blank while
  // highlight / toolbar wiring runs on the main thread.
  if (typeof xml === 'string' && xml.length >= 20000
    && !xml.startsWith('(') && !xml.startsWith('No ')) {
    const struct = ensureManifestViewerStructure();
    const codeEl = struct.code;
    const prettyFast = formatXmlPrettyFast(xml);
    if (codeEl) {
      codeEl.classList.add('res-xml', 'manifest-xml', 'xml-plain-mode');
      codeEl.classList.remove('xml-light-mode');
      // Direct text on the existing <pre> — do not nest another <pre>.
      codeEl.textContent = prettyFast;
    }
    const gen = (showApkManifestInViewer._gen = (showApkManifestInViewer._gen || 0) + 1);
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (showApkManifestInViewer._gen !== gen || apkManifestXml !== xml) return;
        measureSync('showApkManifestInViewer', () => setXmlContent(null, xml, opts), `${formatCount(String(xml).length)} chars`);
        refreshManifestClassLinks();
      });
    });
    return;
  }

  measureSync('showApkManifestInViewer', () => {
    setXmlContent(null, xml, opts);
  }, `${formatCount(String(xml).length)} chars`);
  refreshManifestClassLinks();
}

/**
 * Resolve a class name to { file, classIdx, name } without waiting for the full multidex index.
 * Uses the partial index, the currently open DEX, then polls while indexing; last resort walks DEXes.
 */
async function resolveApkClassLocation(className) {
  if (!className) return null;
  let hit = lookupApkClass(className);
  if (hit) return hit;

  if (apkExtractedFile?.kind === 'dex') {
    const idx = findClassIndexInDex(apkExtractedFile.data?.classes || [], className);
    if (idx >= 0) {
      const name = apkExtractedFile.data.classes[idx]?.name || className;
      apkClassToDex[name] = { file: apkExtractedFile.name, classIdx: idx };
      return { file: apkExtractedFile.name, classIdx: idx, name };
    }
  }

  const shortClass = String(className).split('.').pop() || className;
  setUiActivity('resolve-class', 'Looking up class', shortClass);
  try {
  // Kick off / join background index; return as soon as this class appears.
  const indexP = ensureApkClassIndex();
  const deadline = (typeof performance !== 'undefined' ? performance.now() : Date.now()) + 90000;
  while (!hit) {
    hit = lookupApkClass(className);
    if (hit) return hit;
    if (apkDexStats.ready) break;
    const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
    if (now > deadline) break;
    setUiActivity(
      'resolve-class',
      'Looking up class',
      `${shortClass}`
        + (apkDexStats.current && apkDexStats.totalDex
          ? ` · index ${apkDexStats.current}/${apkDexStats.totalDex}`
          : '')
    );
    await Promise.race([
      indexP.then(() => {}, () => {}),
      new Promise((r) => setTimeout(r, 80)),
    ]);
  }
  hit = lookupApkClass(className);
  if (hit) return hit;

  // Index finished or timed out without a hit — try remaining DEXes via showApkFile.
  const names = listApkDexNames();
  for (const name of names) {
    hit = lookupApkClass(className);
    if (hit) return hit;
    if (apkExtractedFile?.name === name && apkExtractedFile?.kind === 'dex') {
      const idx = findClassIndexInDex(apkExtractedFile.data?.classes || [], className);
      if (idx >= 0) {
        const full = apkExtractedFile.data.classes[idx]?.name || className;
        apkClassToDex[full] = { file: name, classIdx: idx };
        return { file: name, classIdx: idx, name: full };
      }
      continue;
    }
    try {
      await showApkFile(name);
      const idx = findClassIndexInDex(apkExtractedFile?.data?.classes || [], className);
      if (idx >= 0) {
        const full = apkExtractedFile.data.classes[idx]?.name || className;
        apkClassToDex[full] = { file: name, classIdx: idx };
        return { file: name, classIdx: idx, name: full };
      }
    } catch (e) {
      warn('[resolveApkClass] DEX open failed', name, e);
    }
  }
  return lookupApkClass(className);
  } finally {
    clearUiActivity('resolve-class');
  }
}

/** Open a class referenced from the Manifest (DEX file + class index). */
async function openClassFromManifest(file, classIdx, className) {
  if (currentType !== 'apk') return;
  if (!file && className) {
    const hit = await resolveApkClassLocation(className);
    if (hit) {
      file = hit.file;
      classIdx = hit.classIdx;
      className = hit.name;
    }
  }
  if (!file) {
    if (className) warn('[manifest] class not found in APK', className);
    return;
  }
  try {
    await showApkFile(file);
    apkLeftMode = 'classes';
    updateApkLeftModeButtons();
    let idx = typeof classIdx === 'number' && !Number.isNaN(classIdx) ? classIdx : -1;
    if (idx < 0 && className) {
      idx = findClassIndexInDex(apkExtractedFile?.data?.classes || [], className);
    }
    if (idx < 0) {
      warn('[manifest] class not in DEX', className || classIdx, file);
      return;
    }
    const classes = apkExtractedFile?.data?.classes || [];
    const fullName = classes[idx]?.name || className || '';
    codeViewPackage = getPackageFromClassName(fullName);
    selectedDexPackage = codeViewPackage;
    apkExtractedDexSelection = { classIdx: idx, methodIdx: 0 };
    codeViewClassIdx = idx;
    codeViewMethodIdx = null;
    renderApkClassTree();
    updateCodeView();
    switchToCenterTab('bytecode-tab');
    requestAnimationFrame(() => {
      const el =
        (fullName
          ? treeContent?.querySelector(`.tree-item.class[data-class-name="${CSS.escape(fullName)}"]`)
          : null)
        || treeContent?.querySelector(
          `.tree-item.class[data-dex-file="${CSS.escape(file)}"][data-class="${idx}"]`
        )
        || treeContent?.querySelector(`.tree-item.class[data-class="${idx}"]`);
      if (el) {
        treeContent.querySelectorAll('.tree-item.selected').forEach((n) => n.classList.remove('selected'));
        el.classList.add('selected');
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        const ul = el.nextElementSibling;
        const arrow = el.querySelector('.arrow');
        if (ul && ul.style.display === 'none') {
          ul.style.display = '';
          arrow?.classList.remove('collapsed');
          arrow?.classList.add('expanded');
        }
      }
    });
    debug('[manifest] opened class', fullName, 'in', file);
  } catch (e) {
    warn('[manifest] open class failed', e);
  }
}

/** Build a tree from APK file paths: { "seg": { _path, _size } | { "childSeg": ... } }. */
function buildApkPathTree(files) {
  const root = {};
  for (const f of files) {
    const segments = (f.name || '').split('/').filter(Boolean);
    if (segments.length === 0) {
      root[''] = { _path: f.name, _size: f.size };
      continue;
    }
    let cur = root;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      const isLast = i === segments.length - 1;
      if (isLast) {
        cur[seg] = { _path: f.name, _size: f.size };
      } else {
        if (!cur[seg] || cur[seg]._path !== undefined) {
          cur[seg] = {};
        }
        cur = cur[seg];
      }
    }
  }
  return root;
}

function renderApkTree(node, depth = 0) {
  const entries = Object.entries(node).filter(([k]) => !k.startsWith('_'));
  const folders = entries.filter(([, v]) => v && typeof v === 'object' && v._path === undefined);
  const files = entries.filter(([, v]) => v && v._path !== undefined);
  const sorted = [...folders.sort((a, b) => a[0].localeCompare(b[0])), ...files.sort((a, b) => a[0].localeCompare(b[0]))];
  if (sorted.length === 0) return '';
  let html = '<ul class="tree">';
  for (const [seg, val] of sorted) {
    if (val._path !== undefined) {
      const path = val._path;
      const size = val._size;
      const ext = path.split('.').pop().toLowerCase();
      const icon = ext === 'dex' ? ' dex' : ext === 'png' || ext === 'jpg' || ext === 'jpeg' || ext === 'gif' || ext === 'webp' ? ' img' : ext === 'xml' ? ' xml' : ext === 'arsc' ? ' arsc' : '';
      html += `<li><div class="tree-item apk-file" data-name="${escapeAttr(path)}" title="${escapeAttr(path)}">${escapeHtml(seg)}${icon ? ' <span class="muted">[' + icon.trim() + ']</span>' : ''} <span class="muted">(${size})</span></div></li>`;
    } else {
      const childHtml = renderApkTree(val, depth + 1);
      html += `<li><div class="tree-item apk-folder" data-folder="${escapeAttr(seg)}"><span class="arrow collapsed"></span>${escapeHtml(seg)}</div>${childHtml.replace(/^<ul class="tree">/, '<ul class="tree" style="display:none">')}</li>`;
    }
  }
  html += '</ul>';
  return html;
}

/** Return .dex entry names from the current APK file list (stable order). */
function listApkDexNames(files) {
  const list = Array.isArray(files) ? files : (currentData?.files || []);
  return list
    .map((f) => f?.name || '')
    .filter((n) => n.toLowerCase().endsWith('.dex'))
    .sort((a, b) => {
      const rank = (n) => {
        const m = n.match(/(?:^|\/)classes(\d*)\.dex$/i);
        if (!m) return 1000;
        return m[1] === '' ? 0 : parseInt(m[1], 10) || 0;
      };
      const ra = rank(a);
      const rb = rank(b);
      if (ra !== rb) return ra - rb;
      return a.localeCompare(b);
    });
}

/** Prefer classes.dex, else first numbered classesN.dex, else first .dex. */
function pickPrimaryApkDex(files) {
  const names = listApkDexNames(files);
  return names[0] || null;
}

function updateApkLeftModeButtons() {
  const wrap = document.getElementById('left-panel-modes');
  if (!wrap) return;
  const isApk = currentType === 'apk';
  wrap.hidden = !isApk;
  wrap.querySelectorAll('[data-apk-mode]').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-apk-mode') === apkLeftMode);
  });
}

function updateApkDexFileSelector() {
  if (!dexFileWrap || !dexFileSelect) return;
  const names = listApkDexNames();
  if (!names.length) {
    dexFileWrap.style.display = 'none';
    dexFileSelect.innerHTML = '';
    return;
  }
  dexFileWrap.style.display = 'flex';
  let html = '';
  if (names.length > 1) {
    html += `<option value="">All DEXes (${names.length})</option>`;
  }
  html += names.map((n) => {
    const short = n.includes('/') ? n.split('/').pop() : n;
    return `<option value="${escapeAttr(n)}">${escapeHtml(short)}</option>`;
  }).join('');
  dexFileSelect.innerHTML = html;
  if (names.length === 1) {
    // Single DEX: no All option; keep filter empty (unified == that DEX).
    dexFileSelect.value = names[0];
    return;
  }
  const want = apkDexFilter || '';
  dexFileSelect.value = want && names.includes(want) ? want : '';
}

async function setApkLeftMode(mode) {
  if (mode !== 'files' && mode !== 'classes') return;
  apkLeftMode = mode;
  updateApkLeftModeButtons();
  if (mode === 'classes') {
    const names = listApkDexNames();
    const useUnified = names.length > 1 && !apkDexFilter;
    if (useUnified) {
      renderApkClassTree();
      ensureApkClassIndex().then(() => {
        if (apkLeftMode === 'classes' && !apkDexFilter) renderApkClassTree();
      }).catch(() => {});
      // Warm-open primary DEX for code view without leaving All filter.
      if (!apkExtractedFile || apkExtractedFile.kind !== 'dex') {
        const primary = pickPrimaryApkDex();
        if (primary) {
          showApkFile(primary).catch((e) => warn('[setApkLeftMode] warm-open failed', e));
        }
      }
    } else {
      if (!apkExtractedFile || apkExtractedFile.kind !== 'dex') {
        const want = apkDexFilter || pickPrimaryApkDex();
        if (want) await showApkFile(want);
      }
      renderApkClassTree();
    }
  } else {
    renderApkFileTree();
  }
}

/** Unified package → classes map across all APK DEXes (from light class index). */
function buildApkUnifiedPackageMap() {
  // Back-compat: full map (expensive on Facebook). Prefer counts + per-package builders.
  return measureSync('buildApkUnifiedPackageMap', () => {
    const packageMap = {};
    for (const entry of buildApkUnifiedClassesForPackage(null, { allPackages: true })) {
      const pkg = entry.pkg;
      if (!packageMap[pkg]) packageMap[pkg] = [];
      packageMap[pkg].push(entry);
    }
    for (const pkg of Object.keys(packageMap)) {
      packageMap[pkg].sort((a, b) => a.shortName.localeCompare(b.shortName));
    }
    return packageMap;
  });
}

/** Package name → class count for All-DEXes browser (no per-class arrays). */
function buildApkUnifiedPackageCounts() {
  return measureSync('buildApkUnifiedPackageCounts', () => {
    const parsed = searchQuery ? parseListSearchQuery(searchQuery) : null;
    const q = (parsed?.text || '').toLowerCase();
    const filtering = !!(q || parsed?.bookmarks || parsed?.tag || parsed?.methodOnly);

    // Fast path: use package buckets (O(packages) or O(classes) once, then cached).
    if (!filtering) {
      if (apkPackageCountsCache) return apkPackageCountsCache;
      const counts = Object.create(null);
      const pkgs = Object.keys(apkClassesByPackage);
      for (let p = 0; p < pkgs.length; p++) {
        const pkg = pkgs[p];
        const list = apkClassesByPackage[pkg];
        let n = 0;
        for (let i = 0; i < list.length; i++) {
          if (shouldShowClassInUi(list[i]?.className || '')) n++;
        }
        if (n) counts[pkg] = n;
      }
      apkPackageCountsCache = counts;
      return counts;
    }

    // Search / bookmark filter: walk package buckets only (not alias map).
    const counts = Object.create(null);
    const pkgs = Object.keys(apkClassesByPackage);
    for (let p = 0; p < pkgs.length; p++) {
      const pkg = pkgs[p];
      const list = apkClassesByPackage[pkg];
      let n = 0;
      for (let i = 0; i < list.length; i++) {
        const entry = list[i];
        const name = entry?.className || '';
        if (!name || !shouldShowClassInUi(name)) continue;
        if (parsed?.bookmarks && !findBookmark('class', name)) continue;
        if (parsed?.tag || parsed?.methodOnly) continue;
        if (q) {
          const display = getDisplayClassName(name).toLowerCase();
          const short = display.split('.').filter(Boolean).pop() || '';
          if (!name.toLowerCase().includes(q) && !display.includes(q) && !short.includes(q)) continue;
        }
        n++;
      }
      if (n) counts[pkg] = n;
    }
    return counts;
  }, `${formatCount(apkDexStats.classes || 0)} classes`);
}

/**
 * Classes for one package (or all packages if opts.allPackages).
 * Uses apkClassesByPackage — never scans the full alias map.
 */
function buildApkUnifiedClassesForPackage(packageName, opts = {}) {
  const out = [];
  const openDex = apkExtractedFile?.kind === 'dex' ? apkExtractedFile.name : '';
  const openClasses = openDex && Array.isArray(apkExtractedFile?.data?.classes)
    ? apkExtractedFile.data.classes
    : [];
  const parsed = searchQuery ? parseListSearchQuery(searchQuery) : null;
  const q = (parsed?.text || '').toLowerCase();
  const allPackages = !!opts.allPackages;
  const MAX_SEARCH = opts.maxSearch || 2500;
  /** Cap DOM materialization for huge packages (e.g. com.facebook.*). */
  const MAX_PKG = opts.maxPackage || 2000;

  const pushEntry = (entry) => {
    const name = entry?.className || '';
    if (!name || !shouldShowClassInUi(name)) return false;
    if (parsed?.bookmarks && !findBookmark('class', name)) return false;
    if (parsed?.tag || parsed?.methodOnly) return false;
    if (q) {
      const display = getDisplayClassName(name).toLowerCase();
      const short = display.split('.').filter(Boolean).pop() || '';
      if (!name.toLowerCase().includes(q) && !display.includes(q) && !short.includes(q)) return false;
    }
    const fullClassDisplay = getDisplayClassName(name);
    const shortName = fullClassDisplay.split('.').filter(Boolean).pop() || '?';
    const classIdx = entry.classIdx;
    const file = entry.file || '';
    let methodsWithIdx = [];
    let fieldsOverride;
    if (!allPackages && file === openDex && openClasses[classIdx]?.name === name) {
      const methods = Array.isArray(openClasses[classIdx].methods) ? openClasses[classIdx].methods : [];
      methodsWithIdx = methods.map((m, methodIdx) => ({ methodIdx, m }));
      fieldsOverride = Array.isArray(openClasses[classIdx].fields) ? openClasses[classIdx].fields : [];
    }
    out.push({
      classIdx,
      shortName,
      methodsWithIdx,
      methodCountHint: Number(entry.methodCount) || 0,
      fieldsOverride,
      dexFile: file,
      className: name,
      unified: true,
      pkg: getPackageFromClassName(name),
    });
    return true;
  };

  if (!allPackages && packageName) {
    const list = apkClassesByPackage[packageName] || [];
    for (let i = 0; i < list.length; i++) {
      pushEntry(list[i]);
      if (out.length >= MAX_PKG) break;
    }
  } else {
    const pkgs = Object.keys(apkClassesByPackage);
    for (let p = 0; p < pkgs.length; p++) {
      const list = apkClassesByPackage[pkgs[p]];
      for (let i = 0; i < list.length; i++) {
        pushEntry(list[i]);
        if (q && out.length >= MAX_SEARCH) break;
      }
      if (q && out.length >= MAX_SEARCH) break;
    }
  }
  out.sort((a, b) => a.shortName.localeCompare(b.shortName));
  return out;
}

/** Build package map for a classes array (optionally filtered by search). Shared by DEX / APK class trees. */
function buildDexPackageMap(classes) {
  const packageMap = {};
  const matchPairs = searchQuery ? getDexSearchMatches(classes, searchQuery) : null;

  if (matchPairs !== null) {
    const byClass = new Map();
    for (const { classIdx, methodIdx } of matchPairs) {
      const c = classes[classIdx];
      if (!shouldShowClassInUi(c?.name)) continue;
      if (!byClass.has(classIdx)) {
        const parts = (c.name || '').split('.');
        const fullClassDisplay = getDisplayClassName(c.name || '');
        const shortName = fullClassDisplay.split('.').filter(Boolean).pop() || '?';
        byClass.set(classIdx, {
          classIdx,
          shortName,
          pkg: parts.length > 1 ? parts.slice(0, -1).join('.') : '(default)',
          methodIdxs: [],
        });
      }
      if (methodIdx != null && methodIdx >= 0) {
        byClass.get(classIdx).methodIdxs.push(methodIdx);
      }
    }
    for (const entry of byClass.values()) {
      if (!packageMap[entry.pkg]) packageMap[entry.pkg] = [];
      const methodsWithIdx = entry.methodIdxs.map((methodIdx) => ({
        methodIdx,
        m: classes[entry.classIdx].methods[methodIdx],
      }));
      packageMap[entry.pkg].push({ classIdx: entry.classIdx, shortName: entry.shortName, methodsWithIdx });
    }
  } else {
    classes.forEach((c, classIdx) => {
      if (!shouldShowClassInUi(c?.name)) return;
      const methods = Array.isArray(c.methods) ? c.methods : [];
      const parts = (c.name || '').split('.');
      const pkg = parts.length > 1 ? parts.slice(0, -1).join('.') : '(default)';
      const fullClassDisplay = getDisplayClassName(c.name || '');
      const shortName = fullClassDisplay.split('.').filter(Boolean).pop() || '?';
      if (!packageMap[pkg]) packageMap[pkg] = [];
      const methodsWithIdx = methods.map((m, methodIdx) => ({ methodIdx, m }));
      packageMap[pkg].push({ classIdx, shortName, methodsWithIdx });
    });
  }
  return packageMap;
}

function wireDexClassTreeHandlers(classes, { isApk }) {
  const expandAll = searchQuery.length > 0;
  treeContent.querySelectorAll('.tree-item.class').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.tree-bookmark-star')) return;
      if (e.target.classList.contains('arrow')) return;
      const ul = el.nextElementSibling;
      if (ul) {
        const arrow = el.querySelector('.arrow');
        if (ul.style.display === 'none') {
          ul.style.display = '';
          arrow?.classList.remove('collapsed');
          arrow?.classList.add('expanded');
        } else {
          ul.style.display = 'none';
          arrow?.classList.add('collapsed');
          arrow?.classList.remove('expanded');
        }
      }
      const classIdx = parseInt(el.dataset.class, 10);
      if (Number.isNaN(classIdx)) return;
      const dexFile = (el.dataset.dexFile || '').trim();
      const className = (el.dataset.className || '').trim();
      const unified = el.dataset.unified === '1';
      if (isApk && unified && dexFile) {
        const openName = apkExtractedFile?.kind === 'dex' ? apkExtractedFile.name : '';
        const alreadyOpen = openName === dexFile
          && Array.isArray(classes)
          && classes[classIdx]?.name === (className || classes[classIdx]?.name);
        if (!alreadyOpen) {
          openClassFromManifest(dexFile, classIdx, className || undefined);
          return;
        }
      }
      codeViewClassIdx = classIdx;
      codeViewMethodIdx = null;
      if (isApk) {
        apkExtractedDexSelection = { classIdx, methodIdx: 0 };
        codeViewPackage = getPackageFromClassName(classes[classIdx]?.name || className || '');
      }
      updateCodeView();
    });
  });

  treeContent.querySelectorAll('.tree-item.method').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.tree-bookmark-star')) return;
      treeContent.querySelectorAll('.tree-item.selected').forEach((e2) => e2.classList.remove('selected'));
      el.classList.add('selected');
      const classIdx = parseInt(el.dataset.class, 10);
      const methodIdx = parseInt(el.dataset.method, 10);
      if (Number.isNaN(classIdx) || Number.isNaN(methodIdx)) return;
      codeViewClassIdx = classIdx;
      codeViewMethodIdx = methodIdx;
      if (isApk) {
        apkExtractedDexSelection = { classIdx, methodIdx };
        codeViewPackage = getPackageFromClassName(classes[classIdx]?.name || '');
        updateCodeView();
      } else {
        selectDexMethod(classIdx, methodIdx);
      }
    });
    el.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const classIdx = parseInt(el.dataset.class, 10);
      const methodIdx = parseInt(el.dataset.method, 10);
      if (Number.isNaN(classIdx) || Number.isNaN(methodIdx) || !classes[classIdx]?.methods?.[methodIdx]) return;
      const className = classes[classIdx].name;
      const method = classes[classIdx].methods[methodIdx];
      const methodName = method.name;
      const key = methodRenameKey(className, method);
      const items = [
        {
          label: 'Rename method…',
          onChoose: () => {
            const newName = promptRename('method', getDisplayMethodName(className, methodName));
            if (!newName) return;
            dexRenames.method[key] = newName;
            codeViewClassIdx = classIdx;
            codeViewMethodIdx = methodIdx;
            commitDexRenamesChange();
          },
        },
      ];
      if (dexRenames.method[key]) {
        items.push({
          label: 'Clear method rename',
          onChoose: () => {
            delete dexRenames.method[key];
            commitDexRenamesChange();
          },
        });
      }
      items.push(...annotationContextMenuItems('method', methodAnnotationKey(className, methodName), getDisplayMethodName(className, methodName)));
      showRenameContextMenuMultiple(e.clientX, e.clientY, items);
    });
  });

  treeContent.querySelectorAll('.tree-item.field').forEach((el) => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      treeContent.querySelectorAll('.tree-item.selected').forEach((e2) => e2.classList.remove('selected'));
      el.classList.add('selected');
      const classIdx = parseInt(el.dataset.class, 10);
      const fieldIdx = parseInt(el.dataset.fieldIdx, 10);
      if (Number.isNaN(classIdx) || Number.isNaN(fieldIdx)) return;
      codeViewClassIdx = classIdx;
      codeViewMethodIdx = null;
      if (isApk) {
        apkExtractedDexSelection = { classIdx, methodIdx: 0 };
        codeViewPackage = getPackageFromClassName(classes[classIdx]?.name || '');
      }
      updateCodeView();
      requestAnimationFrame(() => openFieldXrefsPanel(fieldIdx, { classIdx }));
    });
    el.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const classIdx = parseInt(el.dataset.class, 10);
      const fieldLocal = parseInt(el.dataset.fieldLocal, 10);
      const fieldIdx = parseInt(el.dataset.fieldIdx, 10);
      const field = classes[classIdx]?.fields?.[fieldLocal];
      if (!field) return;
      const className = field.class_name || field.className || classes[classIdx]?.name || '';
      const fieldName = field.name || '';
      const key = `${className}#${fieldName}`;
      const items = [
        {
          label: 'Find field usages (xrefs)',
          onChoose: () => {
            codeViewClassIdx = classIdx;
            codeViewMethodIdx = null;
            updateCodeView();
            requestAnimationFrame(() => openFieldXrefsPanel(fieldIdx, { classIdx }));
          },
        },
        {
          label: 'Rename field…',
          onChoose: () => {
            const newName = promptRename('field', getDisplayFieldName(className, fieldName));
            if (!newName) return;
            dexRenames.field[key] = newName;
            commitDexRenamesChange({ allClasses: true });
          },
        },
      ];
      if (dexRenames.field[key]) {
        items.push({
          label: 'Clear field rename',
          onChoose: () => {
            delete dexRenames.field[key];
            commitDexRenamesChange({ allClasses: true });
          },
        });
      }
      showRenameContextMenuMultiple(e.clientX, e.clientY, items);
    });
  });

  treeContent.querySelectorAll('.tree-item.class').forEach((el) => {
    el.addEventListener('contextmenu', (e) => {
      if (e.target.closest('.tree-bookmark-star')) return;
      e.preventDefault();
      const classIdx = parseInt(el.dataset.class, 10);
      const dexFile = (el.dataset.dexFile || '').trim();
      const unified = el.dataset.unified === '1';
      const fullName = (el.dataset.className || '').trim()
        || (Number.isNaN(classIdx) ? '' : (classes[classIdx]?.name || ''));
      if (!fullName) return;
      if (unified && dexFile && apkExtractedFile?.name !== dexFile) {
        // Open the owning DEX first so rename/export see full class data.
        openClassFromManifest(dexFile, classIdx, fullName);
        return;
      }
      if (Number.isNaN(classIdx) || !classes[classIdx]) return;
      const items = [
        {
          label: 'Rename class…',
          onChoose: () => {
            const newName = promptRename('class', getDisplayClassName(fullName));
            if (!newName) return;
            dexRenames.class[fullName] = newName;
            commitDexRenamesChange({ allClasses: true });
          },
        },
      ];
      if (dexRenames.class[fullName]) {
        items.push({
          label: 'Clear class rename',
          onChoose: () => {
            delete dexRenames.class[fullName];
            commitDexRenamesChange({ allClasses: true });
          },
        });
      }
      items.push(...annotationContextMenuItems('class', fullName, getDisplayClassName(fullName)));
      items.push({
        label: 'Export class source (.java)…',
        onChoose: () => {
          codeViewClassIdx = classIdx;
          codeViewPackage = getPackageFromClassName(fullName);
          exportDecompiledSource('class');
        },
      });
      showRenameContextMenuMultiple(e.clientX, e.clientY, items);
    });
  });
  syncListBookmarksFilterButton();
}

function renderClassTreeFromPackageMap(classes, packageMap, { isApk, skipPackageSelect = false } = {}) {
  const sortedPackages = Object.keys(packageMap).sort();
  if (dexPackageSelect && !skipPackageSelect) {
    dexPackageSelect.innerHTML = '<option value="">Select package…</option>' +
      sortedPackages.map((pkg) => {
        const n = packageMap[pkg]?.length || 0;
        return `<option value="${escapeAttr(pkg)}"${pkg === selectedDexPackage ? ' selected' : ''}>${escapeHtml(pkg)} (${formatCountLabel(n, 'class', 'classes')})</option>`;
      }).join('');
  }
  const expandAll = searchQuery.length > 0;
  const searchActive = searchQuery.length > 0;

  const renderClassList = (pkgClasses) => {
    let html = '';
    pkgClasses.forEach((entry) => {
      const {
        classIdx,
        shortName,
        methodsWithIdx,
        methodCountHint,
        fieldsOverride,
        dexFile,
        className: entryClassName,
        unified,
      } = entry;
      const className = entryClassName || classes[classIdx]?.name || '';
      const methodCount = (methodsWithIdx && methodsWithIdx.length)
        || methodCountHint
        || 0;
      const fields = Array.isArray(fieldsOverride)
        ? fieldsOverride
        : (Array.isArray(classes[classIdx]?.fields) ? classes[classIdx].fields : []);
      const fieldCount = fields.length;
      const countBits = [
        fieldCount ? formatCountLabel(fieldCount, 'field') : null,
        formatCountLabel(methodCount, 'method'),
      ].filter(Boolean).join(', ');
      const dexAttr = dexFile
        ? ` data-dex-file="${escapeAttr(dexFile)}" data-class-name="${escapeAttr(className)}" data-unified="${unified ? '1' : '0'}"`
        : (entryClassName ? ` data-class-name="${escapeAttr(className)}"` : '');
      const dexHint = unified && dexFile && listApkDexNames().length > 1
        ? ` <span class="muted tree-dex-hint" title="${escapeAttr(dexFile)}">[${escapeHtml((dexFile.includes('/') ? dexFile.split('/').pop() : dexFile))}]</span>`
        : '';
      html += `<li><div class="tree-item class${findBookmark('class', className) ? ' is-bookmarked' : ''}" data-class="${classIdx}"${dexAttr}><span class="arrow ${expandAll ? 'expanded' : 'collapsed'}"></span><span class="tree-item-label">${escapeHtml(shortName)}</span>${dexHint} <span class="muted tree-count">(${escapeHtml(countBits)})</span>${treeBookmarkStarHtml('class', classIdx, null, className)}${treeAnnotationBadgeHtml('class', className)}</div><ul style="${expandAll ? '' : 'display:none'}">`;
      if (fields.length) {
        html += `<li class="tree-section-label muted">fields</li>`;
        fields.forEach((f, fieldLocalIdx) => {
          const fname = getDisplayFieldName(className, f?.name || '');
          const typ = shortJavaType(f?.type || f?.typ || '');
          const init = f?.initial_value ?? f?.initialValue;
          const initBit = init != null && String(init) !== '' ? ` = ${init}` : '';
          const fIdx = f?.field_idx ?? f?.fieldIdx ?? '';
          const title = formatFieldDeclaration(f, className);
          html += `<li><div class="tree-item field" data-class="${classIdx}" data-field-local="${fieldLocalIdx}" data-field-idx="${fIdx}" title="${escapeAttr(title)}"><span class="tree-item-label">${escapeHtml(fname)}</span> <span class="muted tree-field-type">${escapeHtml(typ)}${initBit ? escapeHtml(initBit) : ''}</span></div></li>`;
        });
        html += `<li class="tree-section-label muted">methods</li>`;
      }
      (methodsWithIdx || []).forEach(({ methodIdx, m }) => {
        const methodDisplayName = getDisplayMethodName(className, m?.name ?? '');
        const mKey = methodAnnotationKey(className, m?.name ?? '');
        html += `<li><div class="tree-item method${findBookmark('method', mKey) ? ' is-bookmarked' : ''}" data-class="${classIdx}" data-method="${methodIdx}"><span class="tree-item-label">${escapeHtml(methodDisplayName)}</span>${treeBookmarkStarHtml('method', classIdx, methodIdx, mKey)}${treeAnnotationBadgeHtml('method', mKey)}</div></li>`;
      });
      html += '</ul></li>';
    });
    return html;
  };

  // Active search (incl. tag:# / tag:name): show all matching packages — no package gate
  if (searchActive) {
    if (!sortedPackages.length) {
      const parsed = parseListSearchQuery(searchQuery);
      const hint = parsed.bookmarks
        ? ' Star a class/method with ★, or open Bookmarks in the annotation panel.'
        : (parsed.tag ? ' No methods with that tag.' : '');
      treeContent.innerHTML = `<div class="muted">No matches for “${escapeHtml(searchQuery)}”.${hint} Use <code>method:name</code> / <code>m:name</code> for methods, <code>tag:name</code> / <code>#name</code> for tags, or <code>bookmark:</code> / ★ for bookmarks.</div>`;
      return;
    }
    let html = '<ul class="tree">';
    for (const pkg of sortedPackages) {
      const pkgClasses = packageMap[pkg] || [];
      html += `<li class="tree-pkg-group"><div class="tree-pkg-label muted">${escapeHtml(pkg)} <span class="tree-count">(${formatCountLabel(pkgClasses.length, 'class', 'classes')})</span></div><ul class="tree">`;
      html += renderClassList(pkgClasses);
      html += '</ul></li>';
    }
    html += '</ul>';
    treeContent.innerHTML = html;
    wireDexClassTreeHandlers(classes, { isApk });
    return;
  }

  const pkgClasses = selectedDexPackage ? packageMap[selectedDexPackage] : null;
  const hasMatches = pkgClasses && pkgClasses.length > 0;
  if (!selectedDexPackage) {
    treeContent.innerHTML = '<div class="muted">Select a package above to view classes.</div>';
  } else if (!hasMatches) {
    treeContent.innerHTML = '<div class="muted">No classes in this package.</div>';
  } else {
    treeContent.innerHTML = `<ul class="tree">${renderClassList(pkgClasses)}</ul>`;
    wireDexClassTreeHandlers(classes, { isApk });
  }
}

function renderApkClassTree() {
  const tTree = nowMs();
  const names = listApkDexNames();
  const useUnified = names.length > 1 && !apkDexFilter;
  updateApkLeftModeButtons();
  treePlaceholder.style.display = 'none';
  treeContent.style.display = 'block';
  if (listSearchWrap) listSearchWrap.style.display = 'flex';
  if (dexPackageWrap) dexPackageWrap.style.display = 'block';
  updateApkDexFileSelector();

  if (useUnified) {
    leftPanelTitle.textContent = 'Classes';
    leftPanelTitle.title = `All DEXes (${names.length})`;
    const hasIndex = (apkDexStats.classes || 0) > 0
      || Object.keys(apkClassesByPackage || {}).length > 0;
    if (!hasIndex) {
      if (dexPackageWrap) dexPackageWrap.style.display = 'none';
      const prog = apkDexStats?.totalDex
        ? `${apkDexStats.current || 0}/${apkDexStats.totalDex}`
        : '';
      treeContent.innerHTML = apkDexStats?.ready
        ? '<div class="muted">No classes indexed yet. Switch to Files to browse the APK.</div>'
        : `<div class="work-notice is-warn" style="margin:8px 0">`
          + `<span class="work-notice-title">Indexing classes${prog ? ` (${escapeHtml(prog)})` : ''}…</span>`
          + `<span class="work-notice-body">Large APKs can briefly freeze clicks while a DEX is indexed. The bottom status bar shows progress — this is expected.</span>`
          + `</div>`;
      ensureApkClassIndex().then(() => {
        if (apkLeftMode === 'classes' && !apkDexFilter) renderApkClassTree();
      }).catch(() => {});
      return;
    }

    const searchActive = !!(searchQuery && String(searchQuery).length);
    const counts = buildApkUnifiedPackageCounts();
    const sortedPackages = Object.keys(counts).sort();
    // Huge package lists (Facebook) — don't inject 10k+ <option>s in one go.
    const MAX_PKG_OPTIONS = 2500;
    const packageOptions = sortedPackages.length > MAX_PKG_OPTIONS
      ? sortedPackages.slice(0, MAX_PKG_OPTIONS)
      : sortedPackages;
    if (dexPackageSelect) {
      let optsHtml = '<option value="">Select package…</option>';
      if (selectedDexPackage && counts[selectedDexPackage] != null
        && !packageOptions.includes(selectedDexPackage)) {
        optsHtml += `<option value="${escapeAttr(selectedDexPackage)}" selected>${escapeHtml(selectedDexPackage)} (${formatCountLabel(counts[selectedDexPackage])})</option>`;
      }
      optsHtml += packageOptions.map((pkg) => {
        const n = counts[pkg] || 0;
        return `<option value="${escapeAttr(pkg)}"${pkg === selectedDexPackage ? ' selected' : ''}>${escapeHtml(pkg)} (${formatCountLabel(n)})</option>`;
      }).join('');
      if (sortedPackages.length > MAX_PKG_OPTIONS) {
        optsHtml += `<option disabled>… ${formatCount(sortedPackages.length - MAX_PKG_OPTIONS)} more — use search</option>`;
      }
      dexPackageSelect.innerHTML = optsHtml;
    }

    const openClasses = apkExtractedFile?.kind === 'dex' && Array.isArray(apkExtractedFile?.data?.classes)
      ? apkExtractedFile.data.classes
      : [];

    if (searchActive) {
      // Cap search materialization so typing doesn't freeze on 100k+ classes.
      const matches = measureSync(
        'unifiedSearchClasses',
        () => buildApkUnifiedClassesForPackage(null, { allPackages: true, maxSearch: 800 }),
        searchQuery
      );
      if (!matches.length) {
        treeContent.innerHTML = `<div class="muted">No matches for “${escapeHtml(searchQuery)}”.</div>`;
      } else {
        const byPkg = {};
        for (const e of matches) {
          if (!byPkg[e.pkg]) byPkg[e.pkg] = [];
          byPkg[e.pkg].push(e);
        }
        renderClassTreeFromPackageMap(openClasses, byPkg, { isApk: true, skipPackageSelect: true });
      }
    } else if (!selectedDexPackage) {
      treeContent.innerHTML = `<div class="muted">Select a package above to view classes.`
        + (sortedPackages.length ? ` <span class="muted">(${formatCount(sortedPackages.length)} packages)</span>` : '')
        + `</div>`
        + (isLargeApkWorkload()
          ? `<div class="work-notice" style="margin-top:10px"><span class="work-notice-title">Tip for large APKs</span>`
            + `<span class="work-notice-body">Don’t expand everything at once — pick a package or search. Method source loads only when you open a method.</span></div>`
          : '');
    } else {
      const MAX_PKG = 2000;
      const pkgClasses = measureSync(
        'unifiedPackageClasses',
        () => buildApkUnifiedClassesForPackage(selectedDexPackage, { maxPackage: MAX_PKG }),
        selectedDexPackage
      );
      const totalInPkg = counts[selectedDexPackage] || pkgClasses.length;
      if (!pkgClasses.length) {
        treeContent.innerHTML = '<div class="muted">No classes in this package.</div>';
      } else {
        renderClassTreeFromPackageMap(openClasses, { [selectedDexPackage]: pkgClasses }, { isApk: true, skipPackageSelect: true });
        if (totalInPkg > pkgClasses.length) {
          const note = document.createElement('div');
          note.className = 'work-notice is-warn';
          note.style.margin = '8px 0 0';
          note.innerHTML = `<span class="work-notice-title">Showing ${escapeHtml(formatCount(pkgClasses.length))} of ${escapeHtml(formatCount(totalInPkg))} classes</span>`
            + `<span class="work-notice-body">List is capped on purpose so the browser stays responsive. Narrow with search (or another package).</span>`;
          treeContent.appendChild(note);
        }
      }
    }

    if (!apkDexStats?.ready) {
      ensureApkClassIndex().catch(() => {});
    }
    recordPerf('renderApkClassTree', nowMs() - tTree, 'unified');
    return;
  }

  // Single-DEX filter (or APK with only one DEX).
  const wantDex = apkDexFilter || names[0] || '';
  if (wantDex && apkExtractedFile?.kind === 'dex' && apkExtractedFile.name !== wantDex) {
    treeContent.innerHTML = `<div class="muted">Opening ${escapeHtml(wantDex.includes('/') ? wantDex.split('/').pop() : wantDex)}…</div>`;
    showApkFile(wantDex).then(() => {
      if (apkLeftMode === 'classes' && (apkDexFilter === wantDex || (!apkDexFilter && names.length <= 1))) {
        renderApkClassTree();
      }
    }).catch((e) => warn('[renderApkClassTree] open DEX failed', e));
    return;
  }

  const classes = Array.isArray(apkExtractedFile?.data?.classes) ? apkExtractedFile.data.classes : [];
  const dexName = apkExtractedFile?.name || wantDex || 'classes.dex';
  const short = dexName.includes('/') ? dexName.split('/').pop() : dexName;
  leftPanelTitle.textContent = 'Classes';
  leftPanelTitle.title = dexName;

  if (!classes.length) {
    if (dexPackageWrap) dexPackageWrap.style.display = 'none';
    if (wantDex && (!apkExtractedFile || apkExtractedFile.name !== wantDex)) {
      treeContent.innerHTML = `<div class="muted">Opening ${escapeHtml(short)}…</div>`;
      showApkFile(wantDex).then(() => {
        if (apkLeftMode === 'classes') renderApkClassTree();
      }).catch((e) => warn('[renderApkClassTree] open DEX failed', e));
      return;
    }
    treeContent.innerHTML = '<div class="muted">No classes in this DEX. Switch to Files to browse the APK.</div>';
    return;
  }

  const strings = Array.isArray(apkExtractedFile?.data?.strings) ? apkExtractedFile.data.strings : [];
  const parsedSearch = parseListSearchQuery(searchQuery);
  const needIndex = parsedSearch.text && (!dexSearchIndex || dexSearchIndex.classSearchable.length !== classes.length);
  if (needIndex) {
    dexSearchIndex = buildDexSearchIndex(classes, strings);
  }

  const packageMap = buildDexPackageMap(classes);
  renderClassTreeFromPackageMap(classes, packageMap, { isApk: true });
  recordPerf('renderApkClassTree', nowMs() - tTree, short);
}

function renderApkFileTree() {
  const files = currentData.files || [];
  leftPanelTitle.textContent = 'Files';
  leftPanelTitle.title = '';
  updateApkLeftModeButtons();
  treePlaceholder.style.display = 'none';
  treeContent.style.display = 'block';
  if (listSearchWrap) listSearchWrap.style.display = 'flex';
  if (dexPackageWrap) dexPackageWrap.style.display = 'none';
  if (dexFileWrap) dexFileWrap.style.display = 'none';

  const filteredFiles = searchQuery
    ? files.filter((f) => (f.name || '').toLowerCase().includes(searchQuery))
    : files;
  if (filteredFiles.length === 0) {
    treeContent.innerHTML = searchQuery
      ? '<div class="muted">No files match “‘ + escapeHtml(searchQuery) + ’”.</div>'
      : '<div class="muted">No files in this APK.</div>';
  } else {
    const pathTree = buildApkPathTree(filteredFiles);
    treeContent.innerHTML = renderApkTree(pathTree);
  }

  treeContent.querySelectorAll('.tree-item.apk-folder').forEach((el) => {
    el.addEventListener('click', (e) => {
      if (e.target.classList.contains('arrow')) return;
      const ul = el.nextElementSibling;
      if (!ul || ul.tagName !== 'UL') return;
      const arrow = el.querySelector('.arrow');
      if (ul.style.display === 'none') {
        ul.style.display = '';
        arrow?.classList.remove('collapsed');
        arrow?.classList.add('expanded');
      } else {
        ul.style.display = 'none';
        arrow?.classList.add('collapsed');
        arrow?.classList.remove('expanded');
      }
    });
  });

  treeContent.querySelectorAll('.tree-item.apk-file').forEach((el) => {
    el.addEventListener('click', async () => {
      treeContent.querySelectorAll('.tree-item.selected').forEach((e) => e.classList.remove('selected'));
      el.classList.add('selected');
      const name = el.dataset.name;
      await showApkFile(name);
      if (apkExtractedFile?.kind === 'dex') {
        apkLeftMode = 'classes';
        selectedDexPackage = '';
        renderApkClassTree();
      }
    });
  });

  if (apkExtractedFile?.name) {
    treeContent.querySelectorAll('.tree-item.apk-file').forEach((el) => {
      el.classList.toggle('selected', el.dataset.name === apkExtractedFile.name);
    });
  }
}

function normalizePermissionUsageResult(raw) {
  if (raw == null) return null;
  if (typeof raw === 'string') {
    try { raw = JSON.parse(raw); } catch (_) { return null; }
  }
  return raw;
}

function collectApkPermissionNames(data) {
  const m = data?.manifest || {};
  const names = [];
  const seen = new Set();
  const push = (n) => {
    const s = String(n || '').trim();
    if (!s || seen.has(s)) return;
    seen.add(s);
    names.push(s);
  };
  for (const p of (m.uses_permission_details || [])) push(p?.name);
  for (const p of (m.uses_permissions || [])) push(p);
  return names;
}

async function collectDexTargetsForPermissionScan() {
  const out = [];
  if (currentType === 'apk' && currentApkBytes && Array.isArray(currentData?.files)) {
    // Prefer primary DEXes and stop early — do not extract every Facebook multidex blob on the main thread.
    const names = listApkDexNames(currentData.files);
    for (const name of names) {
      if (out.length >= SECURITY_MAX_DEX_FILES) break;
      let bytes;
      try {
        bytes = get_apk_file_content(currentApkBytes, name);
      } catch (e) {
        warn('[permission-usages] extract failed', name, e);
        continue;
      }
      await yieldToUi();
      if (!bytes?.length) continue;
      if (bytes.length > SECURITY_MAX_DEX_BYTES) {
        debug('[permission-usages] skip oversized', name, formatFileSize(bytes.length));
        continue;
      }
      out.push({ name, bytes });
    }
    return out;
  }
  if (currentType === 'dex') {
    if (loadedDexFiles.length) {
      for (const d of loadedDexFiles) {
        if (d?.bytes?.length) out.push({ name: d.name || 'classes.dex', bytes: d.bytes });
      }
    } else if (currentDexBytes?.length) {
      out.push({ name: currentFilename || 'classes.dex', bytes: currentDexBytes });
    }
  }
  return prioritizeDexScanTargets(out);
}

async function buildPermissionUsageIndex(permissions) {
  const perms = Array.isArray(permissions) ? permissions.filter(Boolean) : [];
  const index = Object.create(null);
  for (const p of perms) index[p] = [];
  if (!perms.length) {
    apkPermissionUsageIndex = index;
    apkPermissionUsageStatus = 'ready';
    clearUiActivity('perms');
    return index;
  }
  apkPermissionUsageStatus = 'loading';
  setUiActivity('perms', 'Scanning permissions', `${formatCount(perms.length)} names`);
  await ensureMainWasm();
  // Let the first paint / Info clicks land before we queue heavy worker jobs.
  await yieldToUi();
  while (currentType === 'apk' && apkClassIndexPromise && !apkDexStats.ready) {
    setUiActivity(
      'perms',
      'Permission scan paused',
      'waiting for class index'
    );
    await new Promise((r) => setTimeout(r, 250));
    if (currentType !== 'apk' && currentType !== 'dex') {
      clearUiActivity('perms');
      return index;
    }
  }
  const targets = await collectDexTargetsForPermissionScan();
  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    setUiActivity(
      'perms',
      'Scanning permissions',
      `${i + 1}/${targets.length} · ${shortDexLabel(t.name)}`
    );
    try {
      const raw = await findPermissionUsagesInWorker(t.bytes, perms);
      const result = normalizePermissionUsageResult(raw);
      if (!result?.ok || !Array.isArray(result.groups)) continue;
      for (const g of result.groups) {
        const key = g.permission;
        if (!key) continue;
        if (!index[key]) index[key] = [];
        const usages = Array.isArray(g.usages) ? g.usages : [];
        for (const u of usages) {
          index[key].push({
            class_name: u.class_name,
            method_name: u.method_name,
            offset: u.offset,
            string_index: u.string_index,
            dex_file: t.name,
            in_string_pool: !!g.in_string_pool,
          });
        }
        if (g.in_string_pool) index[key].in_string_pool = true;
      }
    } catch (e) {
      warn('[permission-usages]', t.name, e);
    }
    await yieldToUi();
  }
  apkPermissionUsageIndex = index;
  apkPermissionUsageStatus = 'ready';
  clearUiActivity('perms');
  return index;
}

function ensurePermissionUsageIndex() {
  if (apkPermissionUsageStatus === 'ready' && apkPermissionUsageIndex) {
    return Promise.resolve(apkPermissionUsageIndex);
  }
  if (apkPermissionUsagePromise) return apkPermissionUsagePromise;
  const perms = collectApkPermissionNames(currentData);
  apkPermissionUsagePromise = buildPermissionUsageIndex(perms)
    .catch((e) => {
      warn('[permission-usages] index failed', e);
      apkPermissionUsageStatus = 'error';
      apkPermissionUsageIndex = Object.create(null);
      clearUiActivity('perms');
      return apkPermissionUsageIndex;
    })
    .finally(() => { apkPermissionUsagePromise = null; });
  return apkPermissionUsagePromise;
}

function refreshApkPermissionInfoSection() {
  if (currentType !== 'apk' || !infoContent) return;
  if (!currentData?.manifest && !currentData?.files) return;
  infoContent.innerHTML = buildApkInfoHtml(currentData);
  hydrateInfoResourceThumbs();
  renderPermissionsTab();
  renderComponentsTab();
}

/** Short label for a permission name (last dotted segment). */
function shortPermissionLabel(name) {
  const s = String(name || '');
  const i = s.lastIndexOf('.');
  return i >= 0 ? s.slice(i + 1) : s;
}

/** Common dangerous/runtime Android permissions — badge for quick scanning. */
const DANGEROUS_ANDROID_PERMISSIONS = new Set([
  'android.permission.READ_CALENDAR', 'android.permission.WRITE_CALENDAR',
  'android.permission.CAMERA',
  'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS', 'android.permission.GET_ACCOUNTS',
  'android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION', 'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.RECORD_AUDIO',
  'android.permission.READ_PHONE_STATE', 'android.permission.READ_PHONE_NUMBERS', 'android.permission.CALL_PHONE',
  'android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG', 'android.permission.ADD_VOICEMAIL',
  'android.permission.USE_SIP', 'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.BODY_SENSORS', 'android.permission.BODY_SENSORS_BACKGROUND',
  'android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS',
  'android.permission.RECEIVE_WAP_PUSH', 'android.permission.RECEIVE_MMS',
  'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.READ_MEDIA_IMAGES', 'android.permission.READ_MEDIA_VIDEO', 'android.permission.READ_MEDIA_AUDIO',
  'android.permission.NEARBY_WIFI_DEVICES', 'android.permission.BLUETOOTH_CONNECT', 'android.permission.BLUETOOTH_SCAN',
  'android.permission.POST_NOTIFICATIONS', 'android.permission.ACTIVITY_RECOGNITION',
]);

let permissionsTabFilter = 'all';
let permissionsTabSearch = '';

function apkHasManifestForPermissionsTab() {
  if (currentType !== 'apk' || !currentData) return false;
  if (Array.isArray(currentData.files) && currentData.files.some((f) => f.name === 'AndroidManifest.xml')) return true;
  const m = currentData.manifest;
  if (m && (m.uses_permissions?.length || m.uses_permission_details?.length || m.permissions_declared?.length)) return true;
  if (typeof apkManifestXml === 'string' && apkManifestXml && !apkManifestXml.startsWith('(') && !apkManifestXml.startsWith('No ')) return true;
  return false;
}

function updatePermissionsTabVisibility() {
  const btn = document.getElementById('permissions-tab-btn');
  const show = apkHasManifestForPermissionsTab();
  if (btn) btn.hidden = !show;
  if (!show && getActiveCenterTabId() === 'permissions-tab') {
    switchToCenterTab('bytecode-tab');
  }
  updateComponentsTabVisibility();
  if (centerTabsMenu && !centerTabsMenu.hidden) renderCenterTabsMenu();
}

function collectPermissionsTabRows() {
  const m = currentData?.manifest || {};
  const details = Array.isArray(m.uses_permission_details) && m.uses_permission_details.length
    ? m.uses_permission_details
    : (m.uses_permissions || []).map((name) => ({ name }));
  const declared = Array.isArray(m.permissions_declared) ? m.permissions_declared : [];
  const rows = [];
  const seen = new Set();
  for (const p of details) {
    const name = String(p?.name || '').trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    rows.push({
      name,
      kind: 'uses',
      maxSdk: p.max_sdk_version != null ? p.max_sdk_version : null,
      dangerous: DANGEROUS_ANDROID_PERMISSIONS.has(name),
    });
  }
  for (const nameRaw of declared) {
    const name = String(nameRaw || '').trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    rows.push({ name, kind: 'declared', maxSdk: null, dangerous: false });
  }
  // Fallback: pull from decoded AXML meta if structured manifest is empty.
  if (!rows.length && typeof apkManifestXml === 'string') {
    const meta = extractAxmlMeta(apkManifestXml, null);
    for (const nameRaw of (meta.permissions || [])) {
      const name = String(nameRaw || '').trim();
      if (!name || seen.has(name)) continue;
      seen.add(name);
      rows.push({
        name,
        kind: 'uses',
        maxSdk: null,
        dangerous: DANGEROUS_ANDROID_PERMISSIONS.has(name),
      });
    }
  }
  return rows;
}

function permissionUsageCount(name) {
  const list = apkPermissionUsageIndex?.[name];
  return Array.isArray(list) ? list.length : 0;
}

function renderPermissionUsageListHtml(permission, { max = 12 } = {}) {
  const name = String(permission || '');
  if (apkPermissionUsageStatus === 'loading' || !apkPermissionUsageIndex) {
    return `<div class="perms-uses muted">Scanning DEX string references…</div>`;
  }
  const list = apkPermissionUsageIndex[name];
  if (!list || !list.length) {
    return `<div class="perms-uses muted">No code string references found</div>`;
  }
  const links = list.slice(0, max).map((u) => {
    const simpleClass = String(u.class_name || '').split('.').pop() || u.class_name || '?';
    const loc = `${simpleClass}#${u.method_name || '?'}`;
    const off = u.offset != null ? formatSecHexOffset(u.offset) : '';
    const title = `${u.class_name}#${u.method_name}${off ? ' @ ' + off : ''}${u.dex_file ? ' · ' + u.dex_file : ''}`;
    return `<button type="button" class="perms-use info-perm-use" data-class="${escapeAttr(u.class_name)}" data-method="${escapeAttr(u.method_name)}" data-dex="${escapeAttr(u.dex_file || '')}" data-offset="${u.offset ?? ''}" title="${escapeAttr(title)}">${escapeHtml(loc)}${off ? ` <span class="muted">${escapeHtml(off)}</span>` : ''}</button>`;
  }).join('');
  const more = list.length > max
    ? `<span class="perms-use-more muted">+${formatCount(list.length - max)} more</span>`
    : '';
  return `<div class="perms-uses"><span class="perms-use-count">${formatCount(list.length)} use${list.length === 1 ? '' : 's'}</span>${links}${more}</div>`;
}

function renderPermissionsTab() {
  const body = document.getElementById('perms-body');
  const metaEl = document.getElementById('perms-meta');
  const countEl = document.getElementById('perms-count');
  if (!body) return;

  if (!apkHasManifestForPermissionsTab()) {
    body.innerHTML = '<div class="muted center-text">Load an APK with a Manifest to inspect permissions</div>';
    if (metaEl) metaEl.textContent = '';
    if (countEl) countEl.textContent = '';
    return;
  }

  const rows = collectPermissionsTabRows();
  const q = (permissionsTabSearch || '').trim().toLowerCase();
  let usedN = 0;
  let unusedN = 0;
  let declaredN = 0;
  for (const r of rows) {
    if (r.kind === 'declared') {
      declaredN += 1;
      continue;
    }
    const n = permissionUsageCount(r.name);
    if (n > 0) usedN += 1;
    else unusedN += 1;
  }

  if (metaEl) {
    const scan = apkPermissionUsageStatus === 'loading'
      ? ' · scanning…'
      : (apkPermissionUsageStatus === 'ready' ? '' : '');
    metaEl.textContent = `${formatCount(rows.length)} listed · ${formatCount(usedN)} used · ${formatCount(unusedN)} unused${declaredN ? ` · ${formatCount(declaredN)} declared` : ''}${scan}`;
  }

  const filtered = rows.filter((r) => {
    if (permissionsTabFilter === 'declared' && r.kind !== 'declared') return false;
    if (permissionsTabFilter === 'used') {
      if (r.kind === 'declared') return false;
      if (apkPermissionUsageStatus === 'ready' && permissionUsageCount(r.name) <= 0) return false;
    }
    if (permissionsTabFilter === 'unused') {
      if (r.kind === 'declared') return false;
      if (apkPermissionUsageStatus === 'ready' && permissionUsageCount(r.name) > 0) return false;
    }
    if (permissionsTabFilter === 'all' && r.kind === 'declared') {
      // Keep declared in All, at the end after uses — still include.
    }
    if (!q) return true;
    return r.name.toLowerCase().includes(q) || shortPermissionLabel(r.name).toLowerCase().includes(q);
  });

  // Sort: uses first (dangerous, then by usage count desc, then name), declared last.
  filtered.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'uses' ? -1 : 1;
    if (a.dangerous !== b.dangerous) return a.dangerous ? -1 : 1;
    const ua = permissionUsageCount(a.name);
    const ub = permissionUsageCount(b.name);
    if (ua !== ub) return ub - ua;
    return a.name.localeCompare(b.name);
  });

  if (countEl) {
    countEl.textContent = filtered.length === rows.length
      ? `${formatCount(filtered.length)} shown`
      : `${formatCount(filtered.length)} / ${formatCount(rows.length)}`;
  }

  if (!rows.length) {
    body.innerHTML = '<div class="muted center-text">No <code>uses-permission</code> entries found in the Manifest</div>';
    return;
  }
  if (!filtered.length) {
    body.innerHTML = '<div class="muted center-text">No permissions match this filter</div>';
    return;
  }

  const parts = [];
  let lastKind = '';
  for (const r of filtered) {
    if (r.kind !== lastKind) {
      lastKind = r.kind;
      parts.push(`<div class="perms-section-label">${r.kind === 'declared' ? 'Declared (custom)' : 'Requested (uses-permission)'}</div>`);
    }
    const short = shortPermissionLabel(r.name);
    const badges = [];
    if (r.dangerous) badges.push('<span class="perms-badge perms-badge-danger">dangerous</span>');
    if (r.kind === 'declared') badges.push('<span class="perms-badge">declared</span>');
    if (r.maxSdk != null) badges.push(`<span class="perms-badge">maxSdk ${escapeHtml(String(r.maxSdk))}</span>`);
    const usageN = permissionUsageCount(r.name);
    if (apkPermissionUsageStatus === 'ready') {
      badges.push(usageN
        ? `<span class="perms-badge perms-badge-used">${formatCount(usageN)} use${usageN === 1 ? '' : 's'}</span>`
        : '<span class="perms-badge perms-badge-unused">unused</span>');
    }
    parts.push(
      `<article class="perms-card${r.dangerous ? ' is-dangerous' : ''}${usageN ? ' is-used' : ''}" data-perm="${escapeAttr(r.name)}">` +
      `<header class="perms-card-head">` +
      `<div class="perms-card-titles"><span class="perms-card-short">${escapeHtml(short)}</span>` +
      `<span class="perms-card-full muted" title="${escapeAttr(r.name)}">${escapeHtml(r.name)}</span></div>` +
      `<div class="perms-card-badges">${badges.join('')}</div>` +
      `</header>` +
      (r.kind === 'uses' ? renderPermissionUsageListHtml(r.name) : '<div class="perms-uses muted">App-defined permission</div>') +
      `</article>`
    );
  }
  body.innerHTML = parts.join('');
}

function wirePermissionsTabControls() {
  const search = document.getElementById('perms-search');
  const filters = document.getElementById('perms-filters');
  search?.addEventListener('input', () => {
    permissionsTabSearch = search.value || '';
    renderPermissionsTab();
  });
  search?.addEventListener('keydown', (e) => e.stopPropagation());
  filters?.addEventListener('click', (e) => {
    const chip = e.target.closest('.perms-chip[data-filter]');
    if (!chip) return;
    permissionsTabFilter = chip.dataset.filter || 'all';
    filters.querySelectorAll('.perms-chip').forEach((c) => c.classList.toggle('active', c === chip));
    renderPermissionsTab();
  });
}
wirePermissionsTabControls();

let componentsTabFilter = 'all';
let componentsTabSearch = '';

function apkHasComponentsForTab() {
  if (currentType !== 'apk' || !currentData) return false;
  const m = currentData.manifest;
  if (m && (
    m.activities?.length || m.services?.length || m.receivers?.length || m.providers?.length
  )) return true;
  return apkHasManifestForPermissionsTab();
}

function updateComponentsTabVisibility() {
  const btn = document.getElementById('components-tab-btn');
  const show = apkHasComponentsForTab();
  if (btn) btn.hidden = !show;
  if (!show && getActiveCenterTabId() === 'components-tab') {
    switchToCenterTab('bytecode-tab');
  }
}

function collectComponentsTabRows() {
  const m = currentData?.manifest || {};
  const pkg = m.package || currentData?.package || '';
  const rows = [];
  const pushAll = (kind, list) => {
    for (const c of (Array.isArray(list) ? list : [])) {
      const name = String(c?.name || '').trim();
      if (!name) continue;
      rows.push({
        kind,
        name,
        resolved: resolveManifestClass(name, pkg),
        exported: c.exported,
        enabled: c.enabled,
        permission: c.permission || '',
        process: c.process || '',
        authorities: c.authorities || '',
        isLauncher: !!c.is_launcher,
      });
    }
  };
  pushAll('activity', m.activities);
  pushAll('service', m.services);
  pushAll('receiver', m.receivers);
  pushAll('provider', m.providers);
  return rows;
}

function renderComponentsTab() {
  const body = document.getElementById('comps-body');
  const metaEl = document.getElementById('comps-meta');
  const countEl = document.getElementById('comps-count');
  if (!body) return;

  if (!apkHasComponentsForTab()) {
    body.innerHTML = '<div class="muted center-text">Load an APK with a Manifest to inspect components</div>';
    if (metaEl) metaEl.textContent = '';
    if (countEl) countEl.textContent = '';
    return;
  }

  const rows = collectComponentsTabRows();
  const counts = { activity: 0, service: 0, receiver: 0, provider: 0, exported: 0, launcher: 0 };
  for (const r of rows) {
    if (counts[r.kind] != null) counts[r.kind] += 1;
    if (r.exported === true) counts.exported += 1;
    if (r.isLauncher) counts.launcher += 1;
  }
  if (metaEl) {
    metaEl.textContent = [
      counts.activity ? `${formatCount(counts.activity)} activities` : null,
      counts.service ? `${formatCount(counts.service)} services` : null,
      counts.receiver ? `${formatCount(counts.receiver)} receivers` : null,
      counts.provider ? `${formatCount(counts.provider)} providers` : null,
      counts.exported ? `${formatCount(counts.exported)} exported` : null,
    ].filter(Boolean).join(' · ') || 'No components';
  }

  const q = (componentsTabSearch || '').trim().toLowerCase();
  const filtered = rows.filter((r) => {
    if (componentsTabFilter === 'activity' && r.kind !== 'activity') return false;
    if (componentsTabFilter === 'service' && r.kind !== 'service') return false;
    if (componentsTabFilter === 'receiver' && r.kind !== 'receiver') return false;
    if (componentsTabFilter === 'provider' && r.kind !== 'provider') return false;
    if (componentsTabFilter === 'exported' && r.exported !== true) return false;
    if (componentsTabFilter === 'launcher' && !r.isLauncher) return false;
    if (!q) return true;
    return r.name.toLowerCase().includes(q)
      || r.resolved.toLowerCase().includes(q)
      || shortPermissionLabel(r.name).toLowerCase().includes(q)
      || (r.permission && r.permission.toLowerCase().includes(q))
      || (r.authorities && r.authorities.toLowerCase().includes(q));
  });

  const kindOrder = { activity: 0, service: 1, receiver: 2, provider: 3 };
  filtered.sort((a, b) => {
    const ka = kindOrder[a.kind] ?? 9;
    const kb = kindOrder[b.kind] ?? 9;
    if (ka !== kb) return ka - kb;
    if (a.isLauncher !== b.isLauncher) return a.isLauncher ? -1 : 1;
    if ((a.exported === true) !== (b.exported === true)) return a.exported === true ? -1 : 1;
    return a.resolved.localeCompare(b.resolved);
  });

  if (countEl) {
    countEl.textContent = filtered.length === rows.length
      ? `${formatCount(filtered.length)} shown`
      : `${formatCount(filtered.length)} / ${formatCount(rows.length)}`;
  }

  if (!rows.length) {
    body.innerHTML = '<div class="muted center-text">No activities, services, receivers, or providers in the Manifest</div>';
    return;
  }
  if (!filtered.length) {
    body.innerHTML = '<div class="muted center-text">No components match this filter</div>';
    return;
  }

  const kindLabel = {
    activity: 'Activities',
    service: 'Services',
    receiver: 'Receivers',
    provider: 'Providers',
  };
  const parts = [];
  let lastKind = '';
  for (const r of filtered) {
    if (r.kind !== lastKind) {
      lastKind = r.kind;
      parts.push(`<div class="perms-section-label">${kindLabel[r.kind] || r.kind}</div>`);
    }
    const short = shortPermissionLabel(r.name);
    const badges = [];
    badges.push(`<span class="perms-badge perms-badge-kind">${escapeHtml(r.kind)}</span>`);
    if (r.isLauncher) badges.push('<span class="perms-badge perms-badge-used">launcher</span>');
    if (r.exported === true) badges.push('<span class="perms-badge perms-badge-danger">exported</span>');
    if (r.exported === false) badges.push('<span class="perms-badge">not exported</span>');
    if (r.enabled === false) badges.push('<span class="perms-badge perms-badge-unused">disabled</span>');

    const metaBits = [];
    if (r.permission) {
      metaBits.push(`<div class="comps-meta-row"><span class="comps-meta-k">permission</span> <span class="comps-meta-v">${escapeHtml(r.permission)}</span></div>`);
    }
    if (r.process) {
      metaBits.push(`<div class="comps-meta-row"><span class="comps-meta-k">process</span> <span class="comps-meta-v">${escapeHtml(r.process)}</span></div>`);
    }
    if (r.authorities) {
      metaBits.push(`<div class="comps-meta-row"><span class="comps-meta-k">authorities</span> <span class="comps-meta-v">${escapeHtml(r.authorities)}</span></div>`);
    }

    parts.push(
      `<article class="perms-card comps-card${r.exported === true ? ' is-dangerous' : ''}${r.isLauncher ? ' is-used' : ''}" data-class="${escapeAttr(r.resolved)}">` +
      `<header class="perms-card-head">` +
      `<div class="perms-card-titles">` +
      `<span class="perms-card-short">${escapeHtml(short)}</span>` +
      `<button type="button" class="info-class-link comps-class-link" data-class="${escapeAttr(r.resolved)}" title="${escapeAttr('Open ' + r.resolved)}">${escapeHtml(r.resolved)}</button>` +
      (r.name !== r.resolved ? `<span class="perms-card-full muted">${escapeHtml(r.name)}</span>` : '') +
      `</div>` +
      `<div class="perms-card-badges">${badges.join('')}</div>` +
      `</header>` +
      (metaBits.length ? `<div class="comps-meta">${metaBits.join('')}</div>` : '') +
      `<div class="comps-actions">` +
      `<button type="button" class="btn btn-small comps-open-btn info-class-link" data-class="${escapeAttr(r.resolved)}">Open class</button>` +
      `</div>` +
      `</article>`
    );
  }
  body.innerHTML = parts.join('');
}

function wireComponentsTabControls() {
  const search = document.getElementById('comps-search');
  const filters = document.getElementById('comps-filters');
  const body = document.getElementById('comps-body');
  search?.addEventListener('input', () => {
    componentsTabSearch = search.value || '';
    renderComponentsTab();
  });
  search?.addEventListener('keydown', (e) => e.stopPropagation());
  filters?.addEventListener('click', (e) => {
    const chip = e.target.closest('.perms-chip[data-filter]');
    if (!chip) return;
    componentsTabFilter = chip.dataset.filter || 'all';
    filters.querySelectorAll('.perms-chip').forEach((c) => c.classList.toggle('active', c === chip));
    renderComponentsTab();
  });
  body?.addEventListener('click', (e) => {
    const btn = e.target.closest('button.info-class-link, button.comps-open-btn');
    if (!btn) return;
    e.preventDefault();
    const className = btn.dataset.class || '';
    if (!className) return;
    openClassFromManifest(null, null, className);
  });
}
wireComponentsTabControls();

function renderPermissionUsageLinks(permission) {
  const name = String(permission || '');
  if (apkPermissionUsageStatus === 'loading' || !apkPermissionUsageIndex) {
    return `<div class="info-perm-uses muted">scanning code…</div>`;
  }
  const list = apkPermissionUsageIndex[name];
  if (!list || !list.length) {
    const inPool = !!(list && list.in_string_pool);
    return `<div class="info-perm-uses muted">${inPool ? 'in string pool only' : 'no code references'}</div>`;
  }
  const max = 5;
  const links = list.slice(0, max).map((u) => {
    const simpleClass = String(u.class_name || '').split('.').pop() || u.class_name || '?';
    const loc = `${simpleClass}#${u.method_name || '?'}`;
    const off = u.offset != null ? formatSecHexOffset(u.offset) : '';
    const title = `${u.class_name}#${u.method_name}${off ? ' @ ' + off : ''}${u.dex_file ? ' · ' + u.dex_file : ''}`;
    return `<button type="button" class="info-perm-use" data-class="${escapeAttr(u.class_name)}" data-method="${escapeAttr(u.method_name)}" data-dex="${escapeAttr(u.dex_file || '')}" data-offset="${u.offset ?? ''}" title="${escapeAttr(title)}">${escapeHtml(loc)}${off ? ` <span class="muted">${escapeHtml(off)}</span>` : ''}</button>`;
  }).join('');
  const more = list.length > max
    ? `<span class="info-perm-meta muted">+${list.length - max} more</span>`
    : '';
  return `<div class="info-perm-uses"><span class="info-perm-meta">${list.length} use${list.length === 1 ? '' : 's'}</span>${links}${more}</div>`;
}

function formatApkBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB`;
}

function infoProp(label, value, opts = {}) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return '';
  const text = Array.isArray(value) ? value.join(', ') : String(value);
  const title = opts.title ? ` title="${escapeAttr(opts.title)}"` : (text.length > 80 ? ` title="${escapeAttr(text)}"` : '');
  const htmlValue = opts.htmlValue != null ? opts.htmlValue : escapeHtml(text);
  return `<div class="info-row"${title}><span class="info-label">${escapeHtml(label)}</span><span class="info-value">${htmlValue}</span></div>`;
}

/** Parse `@7F1400BE` / `@0x7f1400be` / bare hex into a numeric resource id. */
function parseAndroidResourceRefId(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  let hex = s;
  if (hex.startsWith('@')) hex = hex.slice(1);
  if (/^0x/i.test(hex)) hex = hex.slice(2);
  if (!/^[0-9a-fA-F]{1,8}$/.test(hex)) return null;
  const id = parseInt(hex, 16);
  return Number.isFinite(id) ? (id >>> 0) : null;
}

/**
 * Resolve a manifest resource attribute to human-readable text.
 * Prefer string value ("Facebook"), else R.type.name, else the raw `@7F…`.
 */
function resolveApkResourceDisplay(raw) {
  const original = raw == null ? '' : String(raw);
  if (!original) return { display: '', title: '', raw: '' };
  // Already a literal label / path
  if (!original.startsWith('@') && !/^0x[0-9a-fA-F]+$/i.test(original)) {
    return { display: original, title: '', raw: original, name: '', value: original.startsWith('res/') ? original : '' };
  }
  const id = parseAndroidResourceRefId(original);
  if (id == null) return { display: original, title: '', raw: original, name: '', value: '' };
  const key = String(id);
  const name = apkResourceMap?.[key] || apkResourceMap?.[id] || '';
  let value = apkResourceValues?.[key] || apkResourceValues?.[id] || '';
  // Unresolved reference stubs from ARSC (`@XXXXXXXX`) are not display values.
  if (value && /^@[0-9A-Fa-f]{8}$/.test(value)) value = '';
  if (value) {
    return {
      display: value,
      title: name ? `${name} (${original})` : original,
      raw: original,
      name,
      value,
    };
  }
  if (name) {
    return { display: name, title: original, raw: original, name, value: '' };
  }
  return { display: original, title: '', raw: original, name: '', value: '' };
}

/** Parse `R.mipmap.ic_launcher` / `android.R.drawable.foo` → { type, name }. */
function parseResourceJavaName(javaName) {
  const m = String(javaName || '').match(/^(?:android\.)?R\.([A-Za-z_]\w*)\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$/);
  if (!m) return null;
  return { type: m[1], name: m[2] };
}

function isApkImagePath(path) {
  return /\.(png|jpe?g|gif|webp|bmp)$/i.test(String(path || ''));
}

function isApkXmlPath(path) {
  return /\.xml$/i.test(String(path || ''));
}

/** Density preference for picking a preview drawable. */
function resourcePathDensityScore(path) {
  const m = String(path || '').match(/-(xxxhdpi|xxhdpi|xhdpi|hdpi|mdpi|ldpi|anydpi|nodpi)(?:-|$)/i);
  if (!m) return 3;
  const order = { xxxhdpi: 6, xxhdpi: 5, xhdpi: 4, hdpi: 3, mdpi: 2, ldpi: 1, anydpi: 0, nodpi: 0 };
  return order[m[1].toLowerCase()] ?? 3;
}

/**
 * Find APK zip entries for a resource type/name (e.g. mipmap / ic_launcher).
 * Matches res/{type}/name.ext and res/{type}-qualifiers/name.ext.
 */
function findApkResourceFilesByTypeName(type, entryName) {
  const files = Array.isArray(currentData?.files) ? currentData.files : [];
  if (!type || !entryName || !files.length) return [];
  const hits = [];
  const wantStem = String(entryName);
  for (const f of files) {
    const n = f.name || '';
    if (!n.startsWith('res/')) continue;
    const parts = n.split('/');
    if (parts.length < 3) continue;
    const folder = parts[1] || '';
    if (!(folder === type || folder.startsWith(`${type}-`))) continue;
    const base = parts[parts.length - 1] || '';
    const stem = base.replace(/\.[^.]+$/, '');
    if (stem === wantStem) hits.push(n);
  }
  return hits;
}

/** Resolve resource attr → APK file paths (best first). */
function resolveApkResourceFilePaths(raw, resolved) {
  const r = resolved || resolveApkResourceDisplay(raw);
  const files = Array.isArray(currentData?.files) ? currentData.files : [];
  const fileSet = new Set(files.map((f) => f.name));
  const out = [];
  const push = (p) => {
    if (!p || out.includes(p) || !fileSet.has(p)) return;
    out.push(p);
  };

  // Direct path from ARSC value or literal.
  const val = String(r.value || '').trim();
  if (val.startsWith('res/')) push(val);
  if (String(r.display || '').startsWith('res/')) push(r.display);

  const parsed = parseResourceJavaName(r.name)
    || (typeof r.display === 'string' && r.display.startsWith('R.') ? parseResourceJavaName(r.display) : null);
  if (parsed) {
    for (const p of findApkResourceFilesByTypeName(parsed.type, parsed.name)) push(p);
  }

  // Prefer images, then higher density, then shorter path.
  out.sort((a, b) => {
    const ia = isApkImagePath(a) ? 1 : 0;
    const ib = isApkImagePath(b) ? 1 : 0;
    if (ia !== ib) return ib - ia;
    const da = resourcePathDensityScore(a);
    const db = resourcePathDensityScore(b);
    if (da !== db) return db - da;
    return a.length - b.length;
  });
  return out;
}

function pickApkResourcePreviewPath(paths) {
  return (paths || []).find((p) => isApkImagePath(p)) || null;
}

async function openApkResourceFile(path) {
  if (!path || currentType !== 'apk') return;
  try {
    await showApkFile(path);
    if (apkExtractedFile) addOrShowFileTab(apkExtractedFile);
  } catch (e) {
    warn('[info] open resource failed', path, e);
  }
}

/** After Info HTML is mounted, fill icon thumbnails from APK bytes. */
function hydrateInfoResourceThumbs() {
  if (!infoContent || currentType !== 'apk' || !currentApkBytes) return;
  clearInfoResourceThumbUrls();
  const imgs = infoContent.querySelectorAll('img.info-res-thumb[data-path]');
  imgs.forEach((img) => {
    const path = img.dataset.path || '';
    if (!path || !isApkImagePath(path)) return;
    try {
      const bytes = get_apk_file_content(currentApkBytes, path);
      if (!bytes?.length) {
        img.hidden = true;
        return;
      }
      const ext = (path.split('.').pop() || 'png').toLowerCase();
      const mime = ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg'
        : ext === 'gif' ? 'image/gif'
          : ext === 'webp' ? 'image/webp'
            : 'image/png';
      const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
      infoResourceThumbUrls.push(url);
      img.src = url;
      img.hidden = false;
    } catch (_) {
      img.hidden = true;
    }
  });
}

function infoResourceProp(label, raw) {
  if (raw == null || raw === '') return '';
  const resolved = resolveApkResourceDisplay(raw);
  const paths = resolveApkResourceFilePaths(raw, resolved);
  const primary = paths[0] || '';
  const preview = pickApkResourcePreviewPath(paths);
  const title = resolved.title || resolved.raw || resolved.display;

  let valueHtml = '';
  if (preview) {
    valueHtml += `<img class="info-res-thumb" data-path="${escapeAttr(preview)}" alt="" title="${escapeAttr(preview)}" hidden />`;
  }
  if (primary) {
    const short = primary.split('/').pop() || primary;
    valueHtml += `<button type="button" class="info-res-link" data-path="${escapeAttr(primary)}" title="${escapeAttr(primary)}">${escapeHtml(resolved.display || short)}</button>`;
    if (resolved.name && resolved.display !== resolved.name) {
      valueHtml += `<span class="info-res-rname muted">${escapeHtml(resolved.name)}</span>`;
    }
    if (paths.length > 1) {
      const extras = paths.slice(1, 6).map((p) => {
        const s = p.split('/').pop() || p;
        return `<button type="button" class="info-res-link info-res-alt" data-path="${escapeAttr(p)}" title="${escapeAttr(p)}">${escapeHtml(s)}</button>`;
      }).join('');
      const more = paths.length > 6 ? `<span class="muted">+${paths.length - 6}</span>` : '';
      valueHtml += `<span class="info-res-alts">${extras}${more}</span>`;
    }
  } else {
    valueHtml += escapeHtml(resolved.display || String(raw));
    if (resolved.name && resolved.display !== resolved.name) {
      valueHtml += ` <span class="muted">(${escapeHtml(resolved.name)})</span>`;
    }
  }

  return `<div class="info-row info-res-row"${title ? ` title="${escapeAttr(title)}"` : ''}>` +
    `<span class="info-label">${escapeHtml(label)}</span>` +
    `<span class="info-value info-res-value">${valueHtml}</span></div>`;
}

function infoBool(label, value) {
  if (value == null) return '';
  return infoProp(label, value ? 'yes' : 'no');
}

function infoSection(title, bodyHtml) {
  if (!bodyHtml || !String(bodyHtml).trim()) return '';
  return `<div class="info-section">${escapeHtml(title)}</div>${bodyHtml}`;
}

function infoListItems(items, mapFn, limit = 24) {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return '';
  const shown = list.slice(0, limit).map(mapFn).join('');
  const more = list.length > limit
    ? `<div class="info-row muted"><span class="info-label">…</span><span>+${list.length - limit} more</span></div>`
    : '';
  return shown + more;
}

function formatComponentLine(c) {
  const flags = [];
  if (c.exported === true) flags.push('exported');
  if (c.exported === false) flags.push('not-exported');
  if (c.enabled === false) flags.push('disabled');
  if (c.is_launcher) flags.push('launcher');
  if (c.permission) flags.push(`perm=${c.permission}`);
  if (c.authorities) flags.push(`auth=${c.authorities}`);
  const suffix = flags.length ? ` · ${flags.join(', ')}` : '';
  const pkg = currentData?.manifest?.package || currentData?.package || '';
  const nameLink = infoClassLinkHtml(c.name || '?', pkg);
  return `<div class="info-row" title="${escapeAttr((c.name || '') + suffix)}"><span class="info-label">·</span><span class="info-value">${nameLink}${flags.length ? `<span class="muted">${escapeHtml(suffix)}</span>` : ''}</span></div>`;
}

/** Clickable class name for Info panel → open DEX class. */
function infoClassLinkHtml(rawName, pkg) {
  const raw = String(rawName || '').trim();
  if (!raw || raw === '-' || raw === '?') return escapeHtml(raw || '?');
  if (!looksLikeManifestClassValue(raw)) return escapeHtml(raw);
  const resolved = resolveManifestClass(raw, pkg || '');
  return `<button type="button" class="info-class-link" data-class="${escapeAttr(resolved)}" title="${escapeAttr('Open ' + resolved)}">${escapeHtml(raw)}</button>`;
}

/** infoProp variant that links a class-valued field. */
function infoClassProp(label, value, pkg) {
  if (value == null || value === '') return '';
  return `<div class="info-row"><span class="info-label">${escapeHtml(label)}</span><span class="info-value">${infoClassLinkHtml(value, pkg)}</span></div>`;
}

function infoClassListProp(label, names, pkg) {
  const list = (Array.isArray(names) ? names : []).filter(Boolean);
  if (!list.length) return '';
  const links = list.map((n) => infoClassLinkHtml(n, pkg)).join(', ');
  return `<div class="info-row"><span class="info-label">${escapeHtml(label)}</span><span class="info-value">${links}</span></div>`;
}

function buildApkInfoHtml(data) {
  const m = data?.manifest || {};
  const s = data?.stats || {};
  const sig = data?.signing || {};
  const app = m.application || {};
  const versionBits = [m.version_name, m.version_code != null ? `(${m.version_code})` : null].filter(Boolean).join(' ');
  const sdkBits = [
    m.min_sdk_version != null ? `min ${m.min_sdk_version}` : null,
    m.target_sdk_version != null ? `target ${m.target_sdk_version}` : null,
    m.max_sdk_version != null ? `max ${m.max_sdk_version}` : null,
  ].filter(Boolean).join(' · ');

  const pkg = m.package || data?.package || '';
  const identity = [
    infoProp('Package', m.package || data?.package),
    infoProp('Version', versionBits || null),
    infoProp('SDK', sdkBits || null),
    infoProp('Compile SDK', m.compile_sdk_version != null
      ? `${m.compile_sdk_version}${m.compile_sdk_version_codename ? ` (${m.compile_sdk_version_codename})` : ''}`
      : null),
    infoProp('Platform', [m.platform_build_version_name, m.platform_build_version_code].filter(Boolean).join(' / ') || null),
    infoProp('Shared UID', m.shared_user_id),
    infoProp('Install', m.install_location),
    infoClassListProp('Main', m.main_activities || [], pkg),
  ].join('');

  const application = [
    infoClassProp('Name', app.name, pkg),
    infoResourceProp('Label', app.label),
    infoResourceProp('Icon', app.icon),
    infoResourceProp('Theme', app.theme),
    infoBool('Debuggable', app.debuggable),
    infoBool('Allow backup', app.allow_backup),
    infoBool('Cleartext', app.uses_cleartext_traffic),
    infoResourceProp('NetSecCfg', app.network_security_config),
    infoBool('Extract libs', app.extract_native_libs),
    infoBool('Large heap', app.large_heap),
    infoBool('Multi-arch', app.multi_arch),
    infoBool('RTL', app.supports_rtl),
    infoBool('Legacy storage', app.request_legacy_external_storage),
    infoClassProp('Factory', app.app_component_factory, pkg),
    infoResourceProp('Backup rules', app.full_backup_content || app.data_extraction_rules),
  ].join('');

  const permDetails = Array.isArray(m.uses_permission_details) && m.uses_permission_details.length
    ? m.uses_permission_details
    : (m.uses_permissions || []).map((name) => ({ name }));
  const permissions = infoListItems(permDetails, (p) => {
    const extra = p.max_sdk_version != null ? ` (maxSdk ${p.max_sdk_version})` : '';
    const uses = renderPermissionUsageLinks(p.name || '');
    return `<div class="info-row info-perm-row" title="${escapeAttr(p.name || '')}"><span class="info-label">·</span><span class="info-value"><div class="info-perm-name">${escapeHtml(p.name || '')}${extra ? `<span class="muted">${escapeHtml(extra)}</span>` : ''}</div>${uses}</span></div>`;
  }, 60);

  const declared = infoListItems(m.permissions_declared || [], (p) =>
    `<div class="info-row"><span class="info-label">·</span><span class="info-value">${escapeHtml(p)}</span></div>`, 40);

  const features = infoListItems(m.uses_features || [], (f) => {
    const req = f.required == null ? '' : (f.required ? ' required' : ' optional');
    return `<div class="info-row"><span class="info-label">·</span><span class="info-value">${escapeHtml(f.name || '')}<span class="muted">${escapeHtml(req)}</span></span></div>`;
  });

  const libraries = infoListItems(m.uses_libraries || [], (f) => {
    const req = f.required == null ? '' : (f.required ? ' required' : ' optional');
    return `<div class="info-row"><span class="info-label">·</span><span class="info-value">${escapeHtml(f.name || '')}<span class="muted">${escapeHtml(req)}</span></span></div>`;
  });

  const activities = infoListItems(m.activities || [], formatComponentLine, 40);
  const services = infoListItems(m.services || [], formatComponentLine, 40);
  const receivers = infoListItems(m.receivers || [], formatComponentLine, 40);
  const providers = infoListItems(m.providers || [], formatComponentLine, 40);

  const packageStats = [
    infoProp('Files', s.file_count ?? data?.files?.length),
    infoProp('Size', s.uncompressed_size != null ? formatApkBytes(s.uncompressed_size) : null),
    infoProp('DEX', s.dex_count != null ? `${s.dex_count}${(s.dex_files || []).length ? ` · ${(s.dex_files || []).join(', ')}` : ''}` : null),
    infoProp('Native libs', s.native_lib_count != null
      ? `${s.native_lib_count}${(s.native_abis || []).length ? ` · ${(s.native_abis || []).join(', ')}` : ''}`
      : null),
    infoProp('Assets', s.asset_count),
    infoProp('Res', s.res_count),
    infoProp('META-INF', s.meta_inf_count),
    infoBool('Manifest', s.has_manifest),
    infoBool('resources.arsc', s.has_resources_arsc),
  ].join('');

  const certs = Array.isArray(sig.certificates) ? sig.certificates : [];
  const signingHead = [
    infoProp('Schemes', (sig.schemes || []).join(', ') || (certs.length ? 'present' : null)),
    infoProp('v1 blocks', (sig.v1_files || []).join(', ') || null),
  ].join('');
  const signingBody = certs.map((c, i) => {
    const bits = [
      infoProp('Scheme', c.scheme),
      infoProp('Subject', c.subject),
      infoProp('Issuer', c.issuer),
      infoProp('Serial', c.serial_number),
      infoProp('Valid', [c.not_before, c.not_after].filter(Boolean).join(' → ') || null),
      infoProp('Sig alg', c.signature_algorithm),
      infoProp('Key', [c.public_key_algorithm, c.public_key_size != null ? `${c.public_key_size}-bit` : null].filter(Boolean).join(' ') || null),
      infoProp('SHA-1', c.sha1),
      infoProp('SHA-256', c.sha256),
      infoProp('Source', c.source),
    ].join('');
    return `<div class="info-cert">${infoSection(`Certificate ${i + 1}`, bits)}</div>`;
  }).join('');

  return [
    infoSection('Identity', identity),
    infoSection('Application', application),
    infoSection(`Permissions (${permDetails.length})`, permissions),
    infoSection(`Declared permissions (${(m.permissions_declared || []).length})`, declared),
    infoSection(`Features (${(m.uses_features || []).length})`, features),
    infoSection(`Libraries (${(m.uses_libraries || []).length})`, libraries),
    infoSection(`Activities (${(m.activities || []).length})`, activities),
    infoSection(`Services (${(m.services || []).length})`, services),
    infoSection(`Receivers (${(m.receivers || []).length})`, receivers),
    infoSection(`Providers (${(m.providers || []).length})`, providers),
    infoSection('Package contents', packageStats),
    infoSection('Signing', signingHead + (signingBody || (certs.length ? '' : '<div class="muted">No certificates found</div>'))),
  ].filter(Boolean).join('') || '<div class="muted">No APK metadata</div>';
}

function renderApk() {
  const tRender = nowMs();
  const files = currentData.files || [];
  debug('[renderApk] start files=', files.length, 'search=', searchQuery || '(none)', 'mode=', apkLeftMode);

  // Info: always show rich APK / manifest / signing metadata
  infoContent.innerHTML = measureSync('buildApkInfoHtml', () => buildApkInfoHtml(currentData));
  hydrateInfoResourceThumbs();
  updatePermissionsTabVisibility();
  renderPermissionsTab();
  renderComponentsTab();
  // Resolve @7F… label/icon/theme once ARSC maps are ready.
  ensureApkResourceMap().then(() => {
    if (currentType !== 'apk' || !infoContent) return;
    infoContent.innerHTML = buildApkInfoHtml(currentData);
    hydrateInfoResourceThumbs();
  }).catch(() => {});
  // Defer permission scan until class index is ready so Facebook multidex
  // doesn't fight the worker / freeze after "20/20".
  setTimeout(async () => {
    if (currentType !== 'apk') return;
    try {
      await ensureApkClassIndex();
    } catch (_) {}
    if (currentType !== 'apk') return;
    ensurePermissionUsageIndex().then(() => {
      refreshApkPermissionInfoSection();
      renderPermissionsTab();
    });
  }, 600);

  setStringsAndRender(apkExtractedFile?.kind === 'dex' && Array.isArray(apkExtractedFile?.data?.strings) ? apkExtractedFile.data.strings : []);

  if (!apkExtractedFile && currentApkBytes?.length) {
    setHexEditorBytes(currentApkBytes, currentFilename || 'apk');
  }

  // Manifest: cache APK manifest (raw string) and show it unless we're viewing an extracted AXML file
  debug('[renderApk] manifest...');
  const tMan = timer();
  let apkManifestMeta = null;
  if (currentApkBytes && currentData.files.some((f) => f.name === 'AndroidManifest.xml')) {
    const manifestBytes = get_apk_file_content(currentApkBytes, 'AndroidManifest.xml');
    tMan('get_apk_file_content(AndroidManifest.xml)');
    if (manifestBytes && manifestBytes.length > 0) {
      const axmlResult = parse_axml(manifestBytes);
      tMan('parse_axml(manifest)');
      if (axmlResult.ok && axmlResult.data) {
        apkManifestXml = axmlResult.data.xml || '(empty)';
        apkManifestMeta = extractAxmlMeta(apkManifestXml, axmlResult.data);
      } else {
        apkManifestXml = '(Could not parse AXML)';
      }
    } else {
      apkManifestXml = '(Could not extract AndroidManifest.xml)';
    }
  } else {
    apkManifestXml = 'No AndroidManifest.xml in this APK.';
  }
  if (!apkExtractedFile || apkExtractedFile.kind !== 'axml') {
    showApkManifestInViewer(apkManifestMeta || undefined);
  }
  tMan('manifest + ensureApkClassIndex started');

  updateApkLeftModeButtons();

  const primaryDex = pickPrimaryApkDex(files);
  const dexNames = listApkDexNames(files);
  const useUnified = dexNames.length > 1 && !apkDexFilter;
  const needAutoOpen = !apkExtractedFile && !!primaryDex && apkLeftMode === 'classes';

  if (apkLeftMode === 'classes' && useUnified) {
    // Multidex: show unified packages immediately; warm-open primary DEX for code view.
    leftPanelTitle.textContent = 'Classes';
    leftPanelTitle.title = `All DEXes (${dexNames.length})`;
    treePlaceholder.style.display = 'none';
    treeContent.style.display = 'block';
    if (listSearchWrap) listSearchWrap.style.display = 'flex';
    renderApkClassTree();
    if (needAutoOpen) {
      showApkFile(primaryDex).then(() => {
        if (currentType !== 'apk' || apkLeftMode !== 'classes') return;
        if (!apkDexFilter) renderApkClassTree();
        debug('[renderApk] warm-opened', primaryDex, '(All DEXes)');
      }).catch((e) => {
        warn('[renderApk] warm-open DEX failed', e);
      });
    }
    debug('[renderApk] renderApkExtractedContent...');
    renderApkExtractedContent();
    debug('[renderApk] done');
    recordPerf('renderApk', nowMs() - tRender, 'unified');
    return;
  }

  if (needAutoOpen) {
    leftPanelTitle.textContent = 'Classes';
    treePlaceholder.style.display = 'none';
    treeContent.style.display = 'block';
    treeContent.innerHTML = `<div class="muted">Opening ${escapeHtml(primaryDex)}…</div>`;
    if (listSearchWrap) listSearchWrap.style.display = 'flex';
    bytecodeListing.innerHTML = `<div class="muted">Opening ${escapeHtml(primaryDex)}…</div>`;
    showApkFile(primaryDex).then(() => {
      if (currentType !== 'apk') return;
      selectedDexPackage = '';
      renderApkClassTree();
      debug('[renderApk] auto-opened', primaryDex);
    }).catch((e) => {
      warn('[renderApk] auto-open DEX failed', e);
      apkLeftMode = 'files';
      renderApkFileTree();
      renderApkExtractedContent();
    });
    recordPerf('renderApk', nowMs() - tRender, 'auto-open');
    return;
  }

  if (apkLeftMode === 'classes' && apkExtractedFile?.kind === 'dex') {
    renderApkClassTree();
  } else {
    if (apkLeftMode === 'classes' && !primaryDex) apkLeftMode = 'files';
    renderApkFileTree();
  }

  debug('[renderApk] renderApkExtractedContent...');
  renderApkExtractedContent();
  debug('[renderApk] done');
  recordPerf('renderApk', nowMs() - tRender, apkLeftMode);
}

async function showApkFile(name) {
  debug('[showApkFile] start', name);
  const tShowAll = nowMs();
  if (!currentApkBytes || currentType !== 'apk') {
    warn('showApkFile: no APK loaded');
    return;
  }
  await ensureMainWasm();
  if (apkExtractedFile?.name === name) {
    debug('[showApkFile] same file already selected, skip re-parse');
    treeContent.querySelectorAll('.tree-item.apk-file').forEach(el => {
      el.classList.toggle('selected', el.dataset.name === name);
    });
    renderApkExtractedContent();
    recordPerf('showApkFile', nowMs() - tShowAll, 'same');
    return;
  }
  const cached = apkFileCache[name];
  if (cached) {
    debug('[showApkFile] use cache', name);
    apkExtractedFile = cached;
    apkExtractedFileRawBytes = cached.bytes || null;
    if (cached.kind === 'dex') apkExtractedDexSelection = { classIdx: 0, methodIdx: 0 };
    treeContent.querySelectorAll('.tree-item.apk-file').forEach(el => {
      el.classList.toggle('selected', el.dataset.name === name);
    });
    renderApkExtractedContent();
    if (apkExtractedFile?.kind === 'dex' && Array.isArray(apkExtractedFile?.data?.strings)) {
      setStringsAndRender(apkExtractedFile.data.strings);
    }
    if (apkExtractedFile?.kind === 'dex') scheduleEnsureDexStringsLoaded();
    recordPerf('showApkFile', nowMs() - tShowAll, 'cache');
    return;
  }
  const short = shortDexLabel(name);
  setUiActivity('open-file', name.toLowerCase().endsWith('.dex') ? 'Opening DEX' : 'Opening file', short);
  try {
    const tShow = timer();
    const bytes = get_apk_file_content(currentApkBytes, name);
    tShow('get_apk_file_content(' + name + ')');
    if (!bytes) {
      warn('showApkFile: could not extract', name);
      apkExtractedFile = { name, kind: 'binary', data: null, bytes: null };
      apkExtractedFileRawBytes = null;
      apkFileCache[name] = apkExtractedFile;
      renderApkExtractedContent();
      return;
    }
    apkExtractedFileRawBytes = bytes;
    debug('[showApkFile] extracted', name, 'size=', bytes.length);
    if (name.toLowerCase().endsWith('.dex') && bytes.length > 4 * 1024 * 1024) {
      setWorkNotice(
        `Parsing ${short}`,
        `${formatFileSize(bytes.length)} — class tree metadata loads first; method bodies wait until you open a method. The tab may hitch briefly.`,
        { tone: 'warn', sticky: true }
      );
    }
    setUiActivity(
      'open-file',
      name.toLowerCase().endsWith('.dex') ? 'Parsing DEX' : 'Parsing file',
      `${short} · ${formatFileSize(bytes.length)}`
    );

    const u8 = new Uint8Array(bytes);
    debug('[showApkFile] parse_file...', name, 'bytes=', bytes.length);
    let result;
    try {
      // Large DEXes (Facebook) must not run on the main thread or Info clicks freeze.
      // Browse parse omits string pool; method bodies stay on-demand via get_dex_method.
      if (name.toLowerCase().endsWith('.dex') || bytes.length > 2 * 1024 * 1024) {
        result = await parseFileInWorker(u8, name);
      } else {
        const resultRaw = parse_file(u8, name);
        result = typeof resultRaw === 'string' ? JSON.parse(resultRaw) : resultRaw;
      }
    } catch (e) {
      error('[showApkFile] parse_file threw', name, e);
      throw e;
    }
    tShow('parse_file(' + name + ')');
    debug('[showApkFile] parse_file done');
    debug('parse_file for', name, result.ok ? 'ok' : 'fail');

    const ext = (name.split('.').pop() || '').toLowerCase();
    const isImage = ['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext);

    if (result.ok && result.data) {
      if (name.endsWith('.dex')) {
        const data = result.data;
        if (!Array.isArray(data.classes)) data.classes = data.classes ?? [];
        if (!Array.isArray(data.strings)) data.strings = data.strings ?? [];
        const nc = data.classes.length;
        const nm = data.classes.reduce((s, c) => s + (c?.methods?.length ?? 0), 0);
        debug(
          '[showApkFile] DEX', name,
          'classes=', nc,
          'methods total=', nm,
          data.strings_omitted ? `strings_omitted=${data.string_count || 0}` : `strings=${data.strings.length}`
        );
        apkExtractedFile = { name, kind: 'dex', data, bytes };
        apkExtractedDexSelection = { classIdx: 0, methodIdx: 0 };
      } else if (name.endsWith('.xml') || name === 'AndroidManifest.xml') {
        apkExtractedFile = { name, kind: 'axml', data: result.data, bytes };
      } else if (name.endsWith('.arsc')) {
        apkExtractedFile = { name, kind: 'arsc', data: result.data, bytes };
      } else if (isImage) {
        apkExtractedFile = { name, kind: 'png', data: null, bytes };
      } else {
        apkExtractedFile = { name, kind: 'binary', data: null, bytes };
      }
    } else {
      apkExtractedFile = { name, kind: 'binary', data: null, bytes };
    }
    apkFileCache[name] = apkExtractedFile;

    if (apkExtractedFile?.kind === 'dex') {
      seedPartialApkClassIndexFromDex(apkExtractedFile.name, apkExtractedFile.data?.classes);
    }

    renderApkExtractedContent();
    treeContent.querySelectorAll('.tree-item.apk-file').forEach(el => {
      el.classList.toggle('selected', el.dataset.name === name);
    });
    if (apkExtractedFile?.kind === 'dex') {
      scheduleEnsureDexStringsLoaded();
    }
  } finally {
    clearUiActivity('open-file');
    // Keep indexing / Ready notices; clear only the per-DEX parse sticky.
    if (!uiActivityTasks.has('index') && !uiActivityTasks.has('ready')) {
      const el = document.getElementById('work-notice');
      if (el && !el.hidden && el.classList.contains('is-warn')) {
        setWorkNotice(null);
      }
    }
    recordPerf('showApkFile', nowMs() - tShowAll, shortDexLabel(name));
  }
}

/** Merge an already-opened DEX into the class index so Info links work before full indexing finishes. */
function seedPartialApkClassIndexFromDex(dexName, classes) {
  if (!dexName || !Array.isArray(classes) || !classes.length) return;
  let added = 0;
  for (let idx = 0; idx < classes.length; idx++) {
    const name = classes[idx]?.name;
    if (!name || apkClassToDex[name]) continue;
    const methodCount = Array.isArray(classes[idx]?.methods) ? classes[idx].methods.length : 0;
    putApkClassIndexEntry(name, dexName, idx, apkClassToDex, methodCount);
    added += 1;
  }
  if (added) {
    debug('[class-index] seeded', added, 'classes from open DEX', dexName);
    try { applyManifestClassLinksNow(); } catch (_) {}
    // Avoid rebuilding the unified tree on every seed while the full index is still running.
    if (
      currentType === 'apk'
      && apkLeftMode === 'classes'
      && !apkDexFilter
      && listApkDexNames().length > 1
      && apkDexStats?.ready
    ) {
      try { renderApkClassTree(); } catch (_) {}
    }
  }
}

/** Switch center panel to a tab by id (bytecode-tab, manifest-tab, raw-tab, file-tab-123). */
function switchToCenterTab(tabId) {
  document.querySelectorAll('.center-panel .tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.center-panel .tab-content').forEach(c => c.classList.toggle('active', c.id === tabId));
  if (centerTabsMenu && !centerTabsMenu.hidden) renderCenterTabsMenu();
  if (tabId === 'raw-tab' && rawHexEditor && typeof rawHexEditor.refresh === 'function') {
    requestAnimationFrame(() => rawHexEditor.refresh());
  }
  if (tabId === 'permissions-tab') {
    renderPermissionsTab();
    ensurePermissionUsageIndex().then(() => renderPermissionsTab()).catch(() => {});
  }
  if (tabId === 'components-tab') {
    renderComponentsTab();
  }
}

/** Revoke and clear all blob URLs for file tabs, remove DOM, clear state. */
function closeAllApkFileTabs() {
  Object.values(apkFileTabBlobUrls).forEach(url => URL.revokeObjectURL(url));
  apkFileTabBlobUrls = {};
  apkOpenFileTabs = [];
  apkFileCache = {};
  apkExtractedFileRawBytes = null;
  if (centerTabsDynamic) centerTabsDynamic.innerHTML = '';
  centerTabContentsParent?.querySelectorAll('.tab-content[id^="file-tab-"]').forEach(el => el.remove());
  updateCenterTabsChrome();
  setCenterTabsMenuOpen(false);
}

/** Close one file tab by id; if it was active, switch to bytecode-tab. */
function closeApkFileTab(tabId) {
  if (apkFileTabBlobUrls[tabId]) {
    URL.revokeObjectURL(apkFileTabBlobUrls[tabId]);
    delete apkFileTabBlobUrls[tabId];
  }
  apkOpenFileTabs = apkOpenFileTabs.filter(t => t.id !== tabId);
  const btn = document.querySelector(`.center-tabs .tab-btn[data-tab="${tabId}"]`);
  const content = document.getElementById(tabId);
  const wasActive = btn?.classList.contains('active') || getActiveCenterTabId() === tabId;
  if (btn) btn.remove();
  if (content) content.remove();
  updateCenterTabsChrome();
  if (wasActive) switchToCenterTab('bytecode-tab');
  else if (centerTabsMenu && !centerTabsMenu.hidden) renderCenterTabsMenu();
}

/** Render content for ef into the file tab content element for tabId. Manages blob URLs for this tab. */
function renderContentIntoFileTab(tabId, ef) {
  const container = document.querySelector(`#${tabId} .file-tab-content`);
  if (!container) return;
  if (apkFileTabBlobUrls[tabId]) {
    URL.revokeObjectURL(apkFileTabBlobUrls[tabId]);
    delete apkFileTabBlobUrls[tabId];
  }
  if (ef.kind === 'axml') {
    const xml = ef.data?.xml || '(empty)';
    const meta = extractAxmlMeta(xml, ef.data);
    container.innerHTML = `<div class="res-viewer"><div class="res-viewer-toolbar file-xml-toolbar"></div><div class="res-viewer-scroll"><pre class="manifest-xml res-xml file-xml-code"></pre></div></div>`;
    mountXmlViewer(container.querySelector('.file-xml-code'), container.querySelector('.file-xml-toolbar'), xml, {
      meta,
      data: ef.data,
      title: ef.name || 'AXML',
    });
    return;
  }
  if (ef.kind === 'arsc') {
    const pkgs = ef.data?.packages || [];
    mountArscViewer(container, pkgs, {
      title: ef.name || 'resources.arsc',
      overviewXml: ef.data?.overview_xml || buildArscOverviewXml(pkgs),
    });
    return;
  }
  if (ef.kind === 'png' && ef.bytes) {
    const ext = (ef.name || '').split('.').pop().toLowerCase();
    const mime = ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : ext === 'gif' ? 'image/gif' : ext === 'webp' ? 'image/webp' : 'image/png';
    const url = URL.createObjectURL(new Blob([ef.bytes], { type: mime }));
    apkFileTabBlobUrls[tabId] = url;
    container.innerHTML = `<div class="apk-image-wrap"><img src="${url}" alt="${escapeAttr(ef.name)}" class="apk-extracted-image"/></div>`;
    return;
  }
  if (ef.bytes) {
    const hex = hexDump(ef.bytes.slice(0, 8192));
    const more = ef.bytes.length > 8192 ? `\n\n... (${ef.bytes.length - 8192} more bytes)` : '';
    const downloadUrl = URL.createObjectURL(new Blob([ef.bytes], { type: 'application/octet-stream' }));
    apkFileTabBlobUrls[tabId] = downloadUrl;
    container.innerHTML = `<pre class="raw-content">${escapeHtml(hex + more)}</pre><p><a href="${downloadUrl}" download="${escapeAttr(ef.name)}">Download file</a></p>`;
    return;
  }
  container.innerHTML = '<span class="muted">Could not extract file</span>';
}

/** Ensure a tab exists for this file and switch to it; create tab and render if new. */
function addOrShowFileTab(ef) {
  const name = ef.name || 'file';
  let tab = apkOpenFileTabs.find(t => t.name === name);
  if (tab) {
    renderContentIntoFileTab(tab.id, ef);
    switchToCenterTab(tab.id);
    updateCenterTabsChrome();
    return;
  }
  const id = `file-tab-${apkFileTabCounter++}`;
  tab = { id, name, kind: ef.kind, data: ef.data, bytes: ef.bytes };
  apkOpenFileTabs.push(tab);

  const tabBtn = document.createElement('div');
  tabBtn.className = 'tab-btn file-tab-btn';
  tabBtn.dataset.tab = id;
  tabBtn.setAttribute('role', 'tab');
  tabBtn.setAttribute('tabindex', '0');
  tabBtn.title = name;
  tabBtn.innerHTML =
    `<span class="file-tab-label">${escapeHtml(shortFileTabLabel(name))}</span>` +
    `<button type="button" class="file-tab-close" data-tab-id="${escapeAttr(id)}" aria-label="Close ${escapeAttr(shortFileTabLabel(name))}" title="Close">×</button>`;
  tabBtn.addEventListener('click', (e) => {
    if (e.target.closest('.file-tab-close')) return;
    switchToCenterTab(id);
  });
  tabBtn.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      switchToCenterTab(id);
    }
  });
  centerTabsDynamic.appendChild(tabBtn);

  const tabContent = document.createElement('div');
  tabContent.className = 'tab-content';
  tabContent.id = id;
  tabContent.innerHTML = '<div class="file-tab-content"></div>';
  centerTabContentsParent.appendChild(tabContent);

  renderContentIntoFileTab(id, ef);
  switchToCenterTab(id);
  updateCenterTabsChrome();
}

// Close button for dynamic file tabs (delegated)
if (centerTabsDynamic) {
  centerTabsDynamic.addEventListener('click', (e) => {
    const closeBtn = e.target.closest('.file-tab-close');
    if (!closeBtn) return;
    e.preventDefault();
    e.stopPropagation();
    closeApkFileTab(closeBtn.dataset.tabId);
  });
}

centerTabsCloseAllBtn?.addEventListener('click', () => {
  const activeId = getActiveCenterTabId();
  const closingActive = apkOpenFileTabs.some((t) => t.id === activeId);
  closeAllApkFileTabs();
  if (closingActive) switchToCenterTab('bytecode-tab');
});

centerTabsMenuBtn?.addEventListener('click', (e) => {
  e.stopPropagation();
  setCenterTabsMenuOpen(!!centerTabsMenu?.hidden);
});

centerTabsMenu?.addEventListener('click', (e) => {
  const closeId = e.target.closest('[data-tab-close]')?.getAttribute('data-tab-close');
  if (closeId) {
    e.preventDefault();
    e.stopPropagation();
    closeApkFileTab(closeId);
    return;
  }
  const gotoId = e.target.closest('[data-tab-goto]')?.getAttribute('data-tab-goto');
  if (gotoId) {
    e.preventDefault();
    switchToCenterTab(gotoId);
    setCenterTabsMenuOpen(false);
  }
});

document.addEventListener('click', (e) => {
  if (!centerTabsMenu || centerTabsMenu.hidden) return;
  if (e.target.closest('.center-tabs-menu-wrap')) return;
  setCenterTabsMenuOpen(false);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && centerTabsMenu && !centerTabsMenu.hidden) {
    setCenterTabsMenuOpen(false);
  }
});

updateCenterTabsChrome();

/** Fill center (and optionally right) panel from apkExtractedFile. Does not change currentData. */
function renderApkExtractedContent() {
  try {
  if (!apkExtractedFile) {
    if (lastApkImageBlobUrl) {
      URL.revokeObjectURL(lastApkImageBlobUrl);
      lastApkImageBlobUrl = null;
    }
    apkExtractedFileRawBytes = null;

    bytecodeListing.innerHTML = '<div class="muted">Select a file from the list</div>';
    sourceCode.innerHTML = '';
    if (currentApkBytes?.length) setHexEditorBytes(currentApkBytes, currentFilename || 'apk');
    else setHexEditorBytes(null);
    return;
  }
  const ef = apkExtractedFile;

  if (ef.kind === 'dex') {
    const classes = Array.isArray(ef.data?.classes) ? ef.data.classes : [];
    if (classes.length === 0) {

      bytecodeListing.innerHTML = '<div class="muted">No classes in this DEX.</div>';
      setSourceContent(sourceCode, '');
      setRawTabHex(ef);
      return;
    }

    const classIdx = Math.min(apkExtractedDexSelection.classIdx, Math.max(0, classes.length - 1));
    codeViewClassIdx = classIdx;
    codeViewMethodIdx = null;
    apkExtractedDexSelection = { classIdx, methodIdx: 0 };
    updateCodeView();
    setRawTabHex(ef);
    if (apkManifestXml != null) showApkManifestInViewer();
    return;
  }
  if (ef.kind === 'axml') {

    if (ef.name === 'AndroidManifest.xml') {
      bytecodeListing.innerHTML = '<div class="muted">AXML — see Manifest tab</div>';
      const axmlStr = ef.data?.xml || '(empty)';
      const meta = extractAxmlMeta(axmlStr, ef.data);
      setXmlContent(null, axmlStr, { useManifestHost: true, meta, data: ef.data, title: 'AndroidManifest.xml' });
      apkManifestXml = axmlStr;
      refreshManifestClassLinks();
      setRawTabHex(ef);
      if (sourceCode) {
        sourceCode.classList.remove('res-xml', 'manifest-xml', 'src-has-folds');
        sourceCode.innerHTML = '<div class="code-empty"><div class="code-empty-title">AndroidManifest.xml</div><div class="code-empty-hint muted">Open the <strong>Manifest</strong> tab for the full XML</div></div>';
      }
      return;
    }
    addOrShowFileTab(ef);
    bytecodeListing.innerHTML = '<div class="muted">Viewing resource — see file tab</div>';
    sourceCode.innerHTML = '';
    setRawTabHex(ef);
    if (apkManifestXml != null) showApkManifestInViewer();
    return;
  }
  if (ef.kind === 'arsc') {

    addOrShowFileTab(ef);
    bytecodeListing.innerHTML = '<div class="muted">Viewing resource — see file tab</div>';
    sourceCode.innerHTML = '';
    setRawTabHex(ef);
    if (apkManifestXml != null) showApkManifestInViewer();
    return;
  }
  if (ef.kind === 'png' && ef.bytes) {

    if (lastApkImageBlobUrl) { URL.revokeObjectURL(lastApkImageBlobUrl); lastApkImageBlobUrl = null; }
    addOrShowFileTab(ef);
    bytecodeListing.innerHTML = '<div class="muted">Viewing resource — see file tab</div>';
    sourceCode.innerHTML = '';
    setRawTabHex(ef);
    if (apkManifestXml != null) showApkManifestInViewer();
    return;
  }
  if (ef.bytes) {

    addOrShowFileTab(ef);
    bytecodeListing.innerHTML = '<div class="muted">Viewing resource — see file tab</div>';
    sourceCode.innerHTML = '';
    setRawTabHex(ef);
    if (apkManifestXml != null) showApkManifestInViewer();
    return;
  }

  bytecodeListing.innerHTML = '<div class="muted">Could not extract file</div>';
  setSourceContent(sourceCode, '');
  setRawTabHex(ef);
  if (apkManifestXml != null) showApkManifestInViewer();
  } finally {
    updateStatusBar();
  }
}

function getRawBytesForApkFile(ef) {
  if (ef.bytes) return ef.bytes;
  if (apkExtractedFileRawBytes && ef.name === apkExtractedFile?.name) return apkExtractedFileRawBytes;
  if (currentType === 'apk' && currentApkBytes && ef.name) return get_apk_file_content(currentApkBytes, ef.name);
  return null;
}

function setHexEditorBytes(u8, label) {
  if (!rawHexEditor) return;
  if (!u8 || !u8.length) {
    rawHexEditor.clear();
    return;
  }
  rawHexEditor.setBytes(u8, { label: label || '' });
}

function setRawTabHex(ef) {
  const rawBytes = getRawBytesForApkFile(ef);
  if (!rawBytes || rawBytes.length === 0) {
    setHexEditorBytes(null);
    return;
  }
  setHexEditorBytes(rawBytes, ef?.name || 'file');
}

/** Plain hex dump for small previews (e.g. file tabs). Prefer setRawTabHex for the Raw tab. */
function hexDump(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const hex = Array.from(bytes.slice(i, i + 16))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
    const ascii = Array.from(bytes.slice(i, i + 16))
      .map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.')
      .join('');
    lines.push(hex.padEnd(48) + '  ' + ascii);
  }
  return lines.join('\n');
}

function renderAxml() {
  debug('renderAxml', 'xml length=', currentData.xml?.length);
  leftPanelTitle.textContent = 'AXML';
  updateApkLeftModeButtons();
  if (listSearchWrap) listSearchWrap.style.display = 'none';
  if (dexPackageWrap) dexPackageWrap.style.display = 'none';
  if (dexFileWrap) dexFileWrap.style.display = 'none';
  if (searchInput) searchInput.placeholder = 'Search… method:onCreate · tag:crypto';

  const xml = currentData.xml || '(empty)';
  const meta = extractAxmlMeta(xml, currentData);
  const mounted = setXmlContent(null, xml, { useManifestHost: true, meta, data: currentData, title: meta.root_tag || 'AXML' });
  if (sourceCode) {
    sourceCode.classList.remove('res-xml', 'manifest-xml', 'src-has-folds');
    sourceCode.innerHTML = '<div class="code-empty"><div class="code-empty-title">AXML</div><div class="code-empty-hint muted">Open the <strong>Manifest</strong> tab for the full XML</div></div>';
  }
  bytecodeListing.innerHTML = '<div class="muted">AXML — structure outline on the left; full XML in Manifest</div>';

  const outline = (mounted?.outline && mounted.outline.length)
    ? mounted.outline
    : (mounted?.pretty && mounted.mode !== 'plain'
      ? buildXmlOutline(mounted.pretty)
      : []);
  treePlaceholder.style.display = 'none';
  treeContent.style.display = 'block';
  treeContent.innerHTML = renderXmlOutlineTree(outline);
  bindXmlOutlineClicks(treeContent, ensureManifestViewerStructure().code);

  const permList = (meta.permissions || []).slice(0, 40).map((p) => `<div class="info-row"><span class="info-label">·</span><span>${escapeHtml(p)}</span></div>`).join('');
  const morePerms = (meta.permissions?.length || 0) > 40 ? `<div class="muted">…and ${meta.permissions.length - 40} more</div>` : '';
  infoContent.innerHTML = `
    <div class="info-row"><span class="info-label">Package:</span><span>${escapeHtml(meta.package ?? '-')}</span></div>
    <div class="info-row"><span class="info-label">Version:</span><span>${escapeHtml([meta.version_name, meta.version_code].filter(Boolean).join(' / ') || '-')}</span></div>
    <div class="info-row"><span class="info-label">Root:</span><span>${escapeHtml(meta.root_tag ?? '-')}</span></div>
    <div class="info-row"><span class="info-label">Packed:</span><span>${meta.is_packed ? 'yes' : 'no'}</span></div>
    <div class="info-row"><span class="info-label">Permissions:</span><span>${meta.permissions?.length || 0}</span></div>
    ${permList}${morePerms}
  `;
  setStringsAndRender([]);
  setHexEditorBytes(currentFileBytes, currentFilename || 'axml');
  switchToCenterTab('manifest-tab');
}

function renderArsc() {
  const pkgs = currentData.packages || [];
  debug('renderArsc', 'packages=', pkgs.length);
  leftPanelTitle.textContent = 'ARSC';
  updateApkLeftModeButtons();
  if (listSearchWrap) listSearchWrap.style.display = '';
  if (dexPackageWrap) dexPackageWrap.style.display = 'none';
  if (dexFileWrap) dexFileWrap.style.display = 'none';
  if (searchInput) searchInput.placeholder = 'Filter packages / types…';

  treePlaceholder.style.display = 'none';
  treeContent.style.display = 'block';
  const q = searchQuery;
  let outlinePkgs = pkgs;
  if (q) {
    outlinePkgs = pkgs.map((p) => {
      const name = (typeof p === 'string' ? p : (p?.name ?? '')).toLowerCase();
      const allTypes = Array.isArray(p?.types) ? p.types : [];
      const types = allTypes.filter((t) => String(t).toLowerCase().includes(q) || name.includes(q));
      if (name.includes(q) || types.length) {
        return { name: typeof p === 'string' ? p : p.name, types: name.includes(q) ? allTypes : types };
      }
      return null;
    }).filter(Boolean);
  }
  treeContent.innerHTML = outlinePkgs.length
    ? renderArscOutlineTree(outlinePkgs)
    : `<div class="muted">No packages/types match “${escapeHtml(q)}”.</div>`;

  const overviewXml = currentData.overview_xml || buildArscOverviewXml(pkgs);
  const tab = document.getElementById('manifest-tab');
  if (tab) {
    tab.innerHTML = '<div class="res-viewer-host" id="arsc-manifest-host"></div>';
    mountArscViewer(document.getElementById('arsc-manifest-host'), pkgs, { title: 'resources.arsc', overviewXml });
  }
  manifestXml = null;

  bytecodeListing.innerHTML = '<div class="muted">ARSC — packages/types on the left; overview in Manifest</div>';
  setSourceContent(sourceCode, '');

  const bindArscOutline = () => {
    treeContent.querySelectorAll('.arsc-outline-pkg').forEach((el) => {
      el.addEventListener('click', () => {
        const arrow = el.querySelector('.arrow');
        const ul = el.nextElementSibling;
        if (ul && ul.tagName === 'UL') {
          const open = ul.style.display !== 'none';
          ul.style.display = open ? 'none' : '';
          if (arrow) arrow.className = 'arrow ' + (open ? 'collapsed' : 'expanded');
        }
        const hostEl = document.getElementById('arsc-manifest-host');
        const pkgName = el.dataset.pkgName || '';
        if (hostEl?._arscSelectPackage) {
          switchToCenterTab('manifest-tab');
          hostEl._arscSelectPackage(pkgName);
          return;
        }
        const card = hostEl && [...hostEl.querySelectorAll('.arsc-pkg-row, .arsc-pkg-card')].find((c) => c.dataset.pkgName === pkgName);
        if (card) {
          switchToCenterTab('manifest-tab');
          card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
          hostEl.querySelectorAll('.arsc-pkg-row.selected, .arsc-pkg-card.selected').forEach((n) => n.classList.remove('selected'));
          card.classList.add('selected');
          card.click?.();
        }
      });
    });
    treeContent.querySelectorAll('.arsc-outline-type').forEach((el) => {
      el.addEventListener('click', () => {
        treeContent.querySelectorAll('.tree-item.selected').forEach((n) => n.classList.remove('selected'));
        el.classList.add('selected');
        switchToCenterTab('manifest-tab');
        const hostEl = document.getElementById('arsc-manifest-host');
        const type = el.dataset.type || '';
        const pkgName = el.dataset.pkgName || '';
        if (hostEl?._arscSelectType) {
          hostEl._arscSelectType(pkgName, type);
          return;
        }
        const chip = [...(hostEl?.querySelectorAll('.res-type-chip, .arsc-type-row') || [])].find((c) => {
          const card = c.closest('.arsc-pkg-card, .arsc-viewer');
          return (c.dataset.type === type) && (!pkgName || card?.dataset?.pkgName === pkgName || true);
        });
        chip?.click();
      });
    });
  };
  bindArscOutline();

  const totalTypes = pkgs.reduce((n, p) => n + (Array.isArray(p?.types) ? p.types.length : 0), 0);
  infoContent.innerHTML = `<div class="info-row"><span class="info-label">Packages:</span><span>${pkgs.length}</span></div><div class="info-row"><span class="info-label">Resource types:</span><span>${totalTypes}</span></div>`;
  setStringsAndRender([]);
  setHexEditorBytes(currentFileBytes, currentFilename || 'resources.arsc');
  switchToCenterTab('manifest-tab');
}

/* ===== Security: vuln detectors + Semgrep + MT taint solver ===== */
const SECURITY_CACHE_KEY = 'droid2web-security-cache-v1';
const SECURITY_VERDICTS_KEY = 'droid2web-security-verdicts-v1';
const SECURITY_RULES_KEY = 'droid2web-semgrep-rules-yaml';
const SECURITY_CACHE_MAX_ENTRIES = 8;
const SECURITY_CACHE_MAX_CHARS = 4_500_000;
const SECURITY_VERDICTS_MAX_ENTRIES = 24;

let securityVulnFindings = [];
let securitySemgrepFindings = [];
let securityMtReport = null;
let securityFilterQuery = '';
let securitySourceFilter = '';
let securityCategoryFilter = '';
/** Severity filter: '' | 'sev-high' | 'sev-med' | 'sev-low' | 'sev-info' */
let securitySeverityFilter = '';
/** Triage filter: '' | 'unmarked' | 'tp' | 'fp' */
let securityVerdictFilter = '';
/** findingId → 'tp' | 'fp' for the current file fingerprint */
let securityVerdictsMap = {};
let securityScansRun = { vuln: false, semgrep: false, mt: false };
let securityFromCache = false;
let securityCacheSavedAt = 0;
const securityGroupCollapseState = new Map(); // groupKey → collapsed?

function isSecurityGroupCollapsed(key, defaultCollapsed = false) {
  if (securityGroupCollapseState.has(key)) return !!securityGroupCollapseState.get(key);
  return !!defaultCollapsed;
}

function toggleSecurityGroupCollapsed(key, defaultCollapsed = false) {
  securityGroupCollapseState.set(key, !isSecurityGroupCollapsed(key, defaultCollapsed));
}
/** Active Semgrep rules YAML (null/empty = All builtin via WASM: starter + MASTG). */
let securitySemgrepRulesYaml = null;
let securitySemgrepRuleInfos = [];
/** Cached builtin rule summaries (filled once after WASM init — avoids re-parsing on every scan). */
let securitySemgrepBuiltinRuleInfos = [];

/** Match dex-decompiler library skip: android / androidx / java / kotlin / Google Android SDK. */
function isSecurityLibraryClass(className) {
  const n = String(className || '').trim();
  return n === 'android' || n.startsWith('android.')
    || n === 'androidx' || n.startsWith('androidx.')
    || n.startsWith('android.support.')
    || n === 'java' || n.startsWith('java.')
    || n === 'javax' || n.startsWith('javax.')
    || n === 'kotlin' || n.startsWith('kotlin.')
    || n === 'kotlinx' || n.startsWith('kotlinx.')
    || n.startsWith('com.google.android.')
    || n.startsWith('com.android.');
}

function filterLibraryVulnFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.filter((f) => !isSecurityLibraryClass(f?.class_name));
}

const securityStatusEl = document.getElementById('security-status');
const securityOverviewEl = document.getElementById('security-overview');
const securityOverviewGrid = document.getElementById('security-overview-grid');
const securityOverviewBarWrap = document.getElementById('security-overview-bar-wrap');
const securityOverviewBar = document.getElementById('security-overview-bar');
const securityOverviewBarLegend = document.getElementById('security-overview-bar-legend');
const securityOverviewScans = document.getElementById('security-overview-scans');
const securityFiltersEl = document.getElementById('security-filters');
const securitySourceTabsEl = document.getElementById('security-source-tabs');
const securitySevTabsEl = document.getElementById('security-sev-tabs');
const securityVerdictTabsEl = document.getElementById('security-verdict-tabs');
const securityFindingsList = document.getElementById('security-findings-list');
const securityFindingsCount = document.getElementById('security-findings-count');
const securityFilterInput = document.getElementById('security-filter');
const securityChipsEl = document.getElementById('security-chips');
const securityRulesPanel = document.getElementById('security-rules-panel');
const securityRulesEditor = document.getElementById('security-rules-editor');
const securityRulesHighlight = document.getElementById('security-rules-highlight');
const securityRulesList = document.getElementById('security-rules-list');
const securityRulesCount = document.getElementById('security-rules-count');
const securityRulesStatus = document.getElementById('security-rules-status');
const securityProgressEl = document.getElementById('security-progress');
const securityProgressLabel = document.getElementById('security-progress-label');
const securityProgressPct = document.getElementById('security-progress-pct');
const securityProgressDetail = document.getElementById('security-progress-detail');
const securityProgressExtra = document.getElementById('security-progress-extra');
const securityProgressStats = document.getElementById('security-progress-stats');
const securityProgressBar = document.getElementById('security-progress-bar');
const securityProgressTrack = document.getElementById('security-progress-track');
const securityProgressElapsed = document.getElementById('security-progress-elapsed');
const securityProgressPhases = document.getElementById('security-progress-phases');
const securityProgressStopBtn = document.getElementById('security-progress-stop');
const securityCacheModal = document.getElementById('security-cache-modal');
const securityCacheModalBody = document.getElementById('security-cache-modal-body');

const SECURITY_SCAN_BTNS = ['security-scan', 'security-clear-cache'];
let securityScanBusy = false;
let securityScanProgressText = '';
let securityScanAbortRequested = false;
let securityScanStartedAt = 0;
let securityScanElapsedTimer = null;
let securityScanHideTimer = null;
/** @type {{ vuln: string, semgrep: string, mt: string }} */
let securityScanPhaseState = { vuln: 'pending', semgrep: 'pending', mt: 'pending' };
let securityCachePromptResolver = null;
/** Element to restore focus when the security cache modal closes. */
let securityCacheModalReturnFocus = null;

class SecurityScanAbortError extends Error {
  constructor(message = 'Scan stopped') {
    super(message);
    this.name = 'SecurityScanAbortError';
    this.aborted = true;
  }
}

function isSecurityScanAbortError(e) {
  return !!(e && (e.name === 'SecurityScanAbortError' || e.aborted === true));
}

function throwIfSecurityScanAborted() {
  if (securityScanAbortRequested) throw new SecurityScanAbortError();
}

function setSecurityStatus(msg) {
  if (securityStatusEl) securityStatusEl.textContent = msg || '';
}

function setSecurityScanButtonsDisabled(disabled) {
  for (const id of SECURITY_SCAN_BTNS) {
    const el = document.getElementById(id);
    if (el) el.disabled = !!disabled;
  }
}

function formatScanElapsed(ms) {
  const n = Math.max(0, Math.round(ms));
  if (n < 1000) return `${n} ms`;
  if (n < 60_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)} s`;
  return `${Math.floor(n / 60_000)}m ${Math.round((n % 60_000) / 1000)}s`;
}

function formatScanElapsedLive(ms) {
  const n = Math.max(0, ms);
  if (n < 60_000) return `${(n / 1000).toFixed(1)}s`;
  const m = Math.floor(n / 60_000);
  const s = Math.floor((n % 60_000) / 1000);
  return `${m}m ${String(s).padStart(2, '0')}s`;
}

function updateSecurityElapsedDisplay() {
  if (!securityProgressElapsed || !securityScanStartedAt) return;
  securityProgressElapsed.textContent = formatScanElapsedLive(performance.now() - securityScanStartedAt);
}

function startSecurityElapsedTimer() {
  stopSecurityElapsedTimer();
  securityScanStartedAt = performance.now();
  updateSecurityElapsedDisplay();
  securityScanElapsedTimer = setInterval(updateSecurityElapsedDisplay, 200);
}

function stopSecurityElapsedTimer() {
  if (securityScanElapsedTimer) {
    clearInterval(securityScanElapsedTimer);
    securityScanElapsedTimer = null;
  }
  updateSecurityElapsedDisplay();
}

function setSecurityProgressStopVisible(visible) {
  if (!securityProgressStopBtn) return;
  securityProgressStopBtn.hidden = !visible;
  securityProgressStopBtn.disabled = !visible;
  securityProgressStopBtn.textContent = 'Stop';
}

function setSecurityScanPhases(phases) {
  if (!phases || typeof phases !== 'object') return;
  securityScanPhaseState = { ...securityScanPhaseState, ...phases };
  if (!securityProgressPhases) return;
  const keys = ['vuln', 'semgrep', 'mt'];
  const any = keys.some((k) => securityScanPhaseState[k] && securityScanPhaseState[k] !== 'pending');
  securityProgressPhases.hidden = !any && !securityScanBusy;
  keys.forEach((key) => {
    const el = securityProgressPhases.querySelector(`.security-phase[data-phase="${key}"]`);
    if (!el) return;
    const state = securityScanPhaseState[key] || 'pending';
    el.dataset.state = state;
    el.classList.toggle('is-active', state === 'active');
    el.classList.toggle('is-done', state === 'done');
    el.classList.toggle('is-error', state === 'error');
    el.classList.toggle('is-skipped', state === 'skipped');
  });
}

function securityFindingsSoFarChips() {
  const vuln = securityVulnFindings.length;
  const sg = securitySemgrepFindings.length;
  const mt = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0;
  return [
    `<strong>${vuln + sg + mt}</strong> findings`,
    `${vuln} vuln`,
    `${sg} Semgrep`,
    `${mt} MT`,
  ];
}

function showSecurityProgress(label, {
  indeterminate = false,
  pct = 0,
  detail = '',
  extra = '',
  stats = null,
  phases = null,
  stoppable = undefined,
} = {}) {
  if (!securityProgressEl) return;
  if (securityScanHideTimer) {
    clearTimeout(securityScanHideTimer);
    securityScanHideTimer = null;
  }
  securityProgressEl.hidden = false;
  securityProgressEl.classList.toggle('indeterminate', !!indeterminate);
  securityProgressEl.classList.toggle('is-stopped', !!securityScanAbortRequested && !securityScanBusy);
  const text = label || 'Scanning…';
  securityScanProgressText = detail ? `${text} — ${detail}` : text;
  if (securityProgressLabel) securityProgressLabel.textContent = text;
  if (securityProgressDetail) {
    if (detail) {
      securityProgressDetail.hidden = false;
      securityProgressDetail.textContent = detail;
    } else {
      securityProgressDetail.hidden = true;
      securityProgressDetail.textContent = '';
    }
  }
  if (securityProgressExtra) {
    if (extra) {
      securityProgressExtra.hidden = false;
      securityProgressExtra.textContent = extra;
    } else {
      securityProgressExtra.hidden = true;
      securityProgressExtra.textContent = '';
    }
  }
  if (securityProgressStats) {
    const chips = Array.isArray(stats) ? stats.filter(Boolean) : [];
    if (chips.length) {
      securityProgressStats.hidden = false;
      securityProgressStats.innerHTML = chips.map((s) =>
        `<span class="security-progress-stat">${s}</span>`
      ).join('');
    } else {
      securityProgressStats.hidden = true;
      securityProgressStats.innerHTML = '';
    }
  }
  if (phases) setSecurityScanPhases(phases);
  else if (securityScanBusy) setSecurityScanPhases(securityScanPhaseState);

  const showStop = stoppable !== undefined ? !!stoppable : !!securityScanBusy;
  setSecurityProgressStopVisible(showStop);

  const clamped = Math.max(0, Math.min(100, Math.round(pct)));
  if (securityProgressPct) {
    securityProgressPct.textContent = indeterminate ? '…' : `${clamped}%`;
  }
  if (securityProgressBar && !indeterminate) {
    securityProgressBar.style.width = `${clamped}%`;
  }
  if (securityProgressTrack) {
    securityProgressTrack.setAttribute('aria-valuenow', indeterminate ? '0' : String(clamped));
    securityProgressTrack.setAttribute('aria-label', securityScanProgressText);
  }
  updateSecurityElapsedDisplay();
  updateStatusBar();
}

function updateSecurityProgress(done, total, label, detail = '', stats = null, extraOpts = {}) {
  const t = Math.max(1, total || 1);
  const d = Math.max(0, Math.min(done, t));
  const pct = Math.round((d / t) * 100);
  showSecurityProgress(label || `Progress ${d}/${t}`, {
    indeterminate: false,
    pct,
    detail,
    stats,
    ...extraOpts,
  });
}

function updateSecurityProgressWeighted(doneWeight, totalWeight, label, detail = '', stats = null, extraOpts = {}) {
  const tw = Math.max(1, totalWeight || 1);
  const dw = Math.max(0, Math.min(doneWeight, tw));
  const pct = Math.round((dw / tw) * 100);
  showSecurityProgress(label, { indeterminate: false, pct, detail, stats, ...extraOpts });
}

function hideSecurityProgress() {
  if (!securityProgressEl) return;
  if (securityScanHideTimer) {
    clearTimeout(securityScanHideTimer);
    securityScanHideTimer = null;
  }
  securityProgressEl.hidden = true;
  securityProgressEl.classList.remove('indeterminate', 'is-stopped');
  if (securityProgressBar) securityProgressBar.style.width = '0%';
  if (securityProgressDetail) {
    securityProgressDetail.hidden = true;
    securityProgressDetail.textContent = '';
  }
  if (securityProgressExtra) {
    securityProgressExtra.hidden = true;
    securityProgressExtra.textContent = '';
  }
  if (securityProgressStats) {
    securityProgressStats.hidden = true;
    securityProgressStats.innerHTML = '';
  }
  if (securityProgressPhases) securityProgressPhases.hidden = true;
  setSecurityProgressStopVisible(false);
  securityScanProgressText = '';
  updateStatusBar();
}

function beginSecurityScan(label, { phases } = {}) {
  securityScanAbortRequested = false;
  securityScanBusy = true;
  securityScanPhaseState = phases || { vuln: 'pending', semgrep: 'pending', mt: 'pending' };
  setSecurityScanButtonsDisabled(true);
  startSecurityElapsedTimer();
  showSecurityProgress(label || 'Starting scan…', {
    indeterminate: true,
    phases: securityScanPhaseState,
    stoppable: true,
    stats: securityFindingsSoFarChips(),
  });
}

function endSecurityScan({ aborted = false, keepProgressMs = 1600 } = {}) {
  securityScanBusy = false;
  setSecurityScanButtonsDisabled(false);
  stopSecurityElapsedTimer();
  setSecurityProgressStopVisible(false);
  if (aborted) {
    securityProgressEl?.classList.add('is-stopped');
    return;
  }
  if (keepProgressMs > 0 && securityProgressEl && !securityProgressEl.hidden) {
    securityScanHideTimer = setTimeout(() => {
      securityScanHideTimer = null;
      if (!securityScanBusy) hideSecurityProgress();
    }, keepProgressMs);
  } else {
    hideSecurityProgress();
  }
}

function requestSecurityScanStop() {
  if (!securityScanBusy || securityScanAbortRequested) return;
  securityScanAbortRequested = true;
  if (securityProgressStopBtn) {
    securityProgressStopBtn.disabled = true;
    securityProgressStopBtn.textContent = 'Stopping…';
  }
  showSecurityProgress('Stopping scan…', {
    indeterminate: true,
    detail: 'Finishing current worker job or aborting it…',
    extra: 'Partial findings will be kept',
    stats: securityFindingsSoFarChips(),
    stoppable: false,
  });
  setSecurityStatus('Stopping security scan…');
  abortAllParseWorkerJobs(new SecurityScanAbortError());
}

function yieldToUi() {
  return new Promise((r) => setTimeout(r, 0));
}

/** Longer yield so the browser can paint/handle input between heavy APK steps. */
function yieldToUiFrame() {
  return new Promise((r) => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => setTimeout(r, 0));
    } else {
      setTimeout(r, 16);
    }
  });
}

/** Fast fingerprint of loaded APK/DEX for cache keys (sampled FNV-1a). */
function hashBytesSample(u8) {
  if (!u8?.length) return '0';
  let h = 2166136261 >>> 0;
  const n = u8.length;
  const step = Math.max(1, Math.floor(n / 4096));
  for (let i = 0; i < n; i += step) {
    h ^= u8[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  h ^= n >>> 0;
  h = Math.imul(h, 16777619) >>> 0;
  if (n > 64) {
    for (let i = n - 32; i < n; i++) {
      h ^= u8[i];
      h = Math.imul(h, 16777619) >>> 0;
    }
  }
  return h.toString(16);
}

function securityFileFingerprint() {
  const name = currentFilename || '';
  let size = 0;
  let sample = '0';
  if (currentType === 'apk' && currentApkBytes?.length) {
    size = currentApkBytes.length;
    sample = hashBytesSample(currentApkBytes);
  } else if (loadedDexFiles.length > 1) {
    // Stable fingerprint across a multi-DEX list (order by name)
    const parts = loadedDexFiles
      .map((d) => ({
        n: d.name || '',
        s: d.bytes?.length || 0,
        h: hashBytesSample(d.bytes),
      }))
      .sort((a, b) => a.n.localeCompare(b.n));
    size = parts.reduce((acc, p) => acc + p.s, 0);
    sample = parts.map((p) => `${p.n}:${p.s}:${p.h}`).join(';');
    return `dexlist|${parts.length}|${size}|${hashBytesSample(new TextEncoder().encode(sample))}`;
  } else if (currentDexBytes?.length) {
    size = currentDexBytes.length;
    sample = hashBytesSample(currentDexBytes);
  } else if (apkExtractedFile?.bytes?.length) {
    size = apkExtractedFile.bytes.length;
    sample = hashBytesSample(apkExtractedFile.bytes);
  } else {
    return '';
  }
  return `${currentType}|${name}|${size}|${sample}`;
}

function readSecurityCacheStore() {
  try {
    const raw = localStorage.getItem(SECURITY_CACHE_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeSecurityCacheStore(store) {
  try {
    let json = JSON.stringify(store);
    if (json.length > SECURITY_CACHE_MAX_CHARS) {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (json.length > SECURITY_CACHE_MAX_CHARS && keys.length > 1) {
        const drop = keys.shift();
        delete store.entries[drop.k];
        json = JSON.stringify(store);
      }
    }
    localStorage.setItem(SECURITY_CACHE_KEY, json);
    return true;
  } catch (e) {
    warn('security cache write failed', e);
    try {
      const keys = Object.keys(store.entries || {})
        .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
        .sort((a, b) => a.at - b.at);
      while (keys.length > 1) {
        delete store.entries[keys.shift().k];
        try {
          localStorage.setItem(SECURITY_CACHE_KEY, JSON.stringify(store));
          return true;
        } catch (_) { /* keep pruning */ }
      }
    } catch (_) {}
    return false;
  }
}

function loadSecurityCacheEntry(fp) {
  if (!fp) return null;
  const store = readSecurityCacheStore();
  const entry = store.entries[fp];
  if (!entry || entry.version !== 1) return null;
  return entry;
}

function readSecurityVerdictsStore() {
  try {
    const raw = localStorage.getItem(SECURITY_VERDICTS_KEY);
    if (!raw) return { entries: {} };
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { entries: {} };
    return { entries: parsed.entries && typeof parsed.entries === 'object' ? parsed.entries : {} };
  } catch (_) {
    return { entries: {} };
  }
}

function writeSecurityVerdictsStore(store) {
  try {
    const keys = Object.keys(store.entries || {})
      .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
      .sort((a, b) => b.at - a.at);
    while (keys.length > SECURITY_VERDICTS_MAX_ENTRIES) {
      const drop = keys.pop();
      delete store.entries[drop.k];
    }
    localStorage.setItem(SECURITY_VERDICTS_KEY, JSON.stringify(store));
    return true;
  } catch (e) {
    warn('security verdicts write failed', e);
    return false;
  }
}

function loadSecurityVerdictsForCurrent() {
  const fp = securityFileFingerprint();
  if (!fp) {
    securityVerdictsMap = {};
    return;
  }
  const entry = readSecurityVerdictsStore().entries[fp];
  const verdicts = entry?.verdicts;
  securityVerdictsMap = (verdicts && typeof verdicts === 'object') ? { ...verdicts } : {};
}

function getFindingVerdict(findingId) {
  if (!findingId) return '';
  const v = securityVerdictsMap[findingId];
  return v === 'tp' || v === 'fp' ? v : '';
}

function persistSecurityVerdictsMap() {
  const fp = securityFileFingerprint();
  if (!fp) return false;
  const store = readSecurityVerdictsStore();
  if (!Object.keys(securityVerdictsMap).length) {
    delete store.entries[fp];
  } else {
    store.entries[fp] = {
      fingerprint: fp,
      filename: currentFilename || '',
      savedAt: Date.now(),
      verdicts: { ...securityVerdictsMap },
    };
  }
  return writeSecurityVerdictsStore(store);
}

/** Toggle TP/FP; clicking the active mark again clears it. */
function setFindingVerdict(findingId, verdict) {
  if (!findingId || (verdict !== 'tp' && verdict !== 'fp')) return;
  const cur = getFindingVerdict(findingId);
  if (cur === verdict) delete securityVerdictsMap[findingId];
  else securityVerdictsMap[findingId] = verdict;
  persistSecurityVerdictsMap();
  renderSecurityPanel();
}

function clearSecurityVerdictsForCurrent() {
  const fp = securityFileFingerprint();
  securityVerdictsMap = {};
  if (!fp) return;
  const store = readSecurityVerdictsStore();
  if (store.entries[fp]) {
    delete store.entries[fp];
    writeSecurityVerdictsStore(store);
  }
}

function securityFindingIdParts(...parts) {
  return parts.map((p) => encodeURIComponent(String(p ?? ''))).join('|');
}

function securityVulnFindingId(f) {
  return securityFindingIdParts(
    'vuln',
    f?.category,
    f?.class_name,
    f?.method_name,
    f?.dex_file,
    f?.sink_offset,
    f?.source_offset,
    f?.sink_desc,
    f?.source_desc,
    f?.title,
    f?.cwe,
  );
}

function securitySemgrepFindingId(f) {
  return securityFindingIdParts(
    'semgrep',
    f?.rule_id,
    f?.class_name,
    f?.method_name,
    f?.dex_file,
    f?.sink_offset,
    f?.message,
    f?.sink_desc,
  );
}

function securityMtFindingId(iss, idx = 0) {
  const nav = securityMtNavTarget(iss);
  return securityFindingIdParts(
    'mt',
    iss?.rule_code,
    iss?.rule_name,
    iss?.callable,
    iss?.dex_file || nav.dexFile,
    nav.offset,
    iss?.source_kind,
    iss?.sink_kind,
    idx,
  );
}

function securityMatchesVerdict(findingId) {
  if (!securityVerdictFilter) return true;
  const v = getFindingVerdict(findingId);
  if (securityVerdictFilter === 'unmarked') return !v;
  return v === securityVerdictFilter;
}

function collectVerdictCounts() {
  const counts = { unmarked: 0, tp: 0, fp: 0 };
  const countOne = (id) => {
    const v = getFindingVerdict(id);
    if (v === 'tp') counts.tp++;
    else if (v === 'fp') counts.fp++;
    else counts.unmarked++;
  };
  for (const f of securityVulnFindings) countOne(securityVulnFindingId(f));
  for (const f of securitySemgrepFindings) countOne(securitySemgrepFindingId(f));
  const issues = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues : [];
  issues.forEach((iss, idx) => countOne(securityMtFindingId(iss, idx)));
  return counts;
}

function renderFindingVerdictControls(findingId) {
  const v = getFindingVerdict(findingId);
  return `<div class="security-finding-verdict" role="group" aria-label="Mark finding">
    <button type="button" class="security-verdict-btn tp${v === 'tp' ? ' active' : ''}" data-verdict="tp" data-finding-id="${escapeAttr(findingId)}" title="True positive (click again to clear)">TP</button>
    <button type="button" class="security-verdict-btn fp${v === 'fp' ? ' active' : ''}" data-verdict="fp" data-finding-id="${escapeAttr(findingId)}" title="False positive (click again to clear)">FP</button>
  </div>`;
}

/* ===== Analysis localStorage export / import (continue elsewhere) ===== */
const ANALYSIS_EXPORT_FORMAT = 'droid2web-analysis-export';
const ANALYSIS_EXPORT_VERSION = 1;

function analysisExportKeyList() {
  return [
    SECURITY_CACHE_KEY,
    SECURITY_VERDICTS_KEY,
    SECURITY_RULES_KEY,
    RENAMES_STORAGE_KEY,
    ANNOTATIONS_STORAGE_KEY,
    BOOKMARKS_STORAGE_KEY,
    CFG_STATE_KEY,
    SOURCE_COMMENTS_KEY,
    'droid2web-decompile-options',
    THEME_STORAGE_KEY,
    UI_SETTINGS_KEY,
    SHOW_ANDROID_CLASSES_KEY,
    'droid2web-show-hex',
    'droid2web-bytecode-open',
    'droid2web-source-open',
    'droid2web-cfg-open',
    'droid2web-emulator-open',
    'droid2web-cfg-compact',
    'droid2web-cfg-show-addr',
    'droid2web-cfg-dock-w',
    'droid2web-cfg-dock-h',
  ];
}

function reportStorageIoStatus(msg) {
  const text = String(msg || '');
  const headerEl = document.getElementById('header-storage-status');
  if (headerEl) {
    headerEl.textContent = text;
    headerEl.title = text;
  }
  const settingsEl = document.getElementById('settings-storage-status');
  if (settingsEl) settingsEl.textContent = text;
  try {
    if (typeof setSecurityStatus === 'function') setSecurityStatus(text);
  } catch (_) {}
}

function collectAnalysisLocalStorageExport() {
  const keys = {};
  const summary = {};
  for (const key of analysisExportKeyList()) {
    try {
      const raw = localStorage.getItem(key);
      if (raw == null || raw === '') continue;
      keys[key] = raw;
      let entries = null;
      try {
        const parsed = JSON.parse(raw);
        if (parsed?.entries && typeof parsed.entries === 'object') {
          entries = Object.keys(parsed.entries).length;
        }
      } catch (_) { /* plain string (rules / options) */ }
      summary[key] = { chars: raw.length, ...(entries != null ? { entries } : {}) };
    } catch (_) { /* ignore */ }
  }
  let fingerprint = null;
  try { fingerprint = securityFileFingerprint() || null; } catch (_) {}
  return {
    format: ANALYSIS_EXPORT_FORMAT,
    version: ANALYSIS_EXPORT_VERSION,
    exportedAt: new Date().toISOString(),
    app: 'droid2web',
    currentFile: currentFilename || null,
    currentFingerprint: fingerprint,
    keys,
    summary,
  };
}

function downloadAnalysisLocalStorageExport() {
  const payload = collectAnalysisLocalStorageExport();
  const keyCount = Object.keys(payload.keys).length;
  if (!keyCount) {
    reportStorageIoStatus('Nothing to save — no data in localStorage yet');
    return;
  }
  const json = JSON.stringify(payload, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const base = (currentFilename || 'analysis').replace(/[^\w.-]+/g, '_').slice(0, 48);
  a.href = url;
  a.download = `droid2web-${base}-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  const bits = Object.entries(payload.summary).map(([k, s]) => {
    const short = k.replace(/^droid2web-/, '');
    return s.entries != null ? `${short}:${s.entries}` : short;
  });
  reportStorageIoStatus(`Saved ${keyCount} key(s) · ${formatFileSize(json.length)} · ${bits.join(', ')}`);
}

function normalizeExportKeyValue(value) {
  if (typeof value === 'string') return value;
  if (value == null) return null;
  try { return JSON.stringify(value); } catch (_) { return null; }
}

/** Merge `{ entries: {…} }` stores; optional map field (e.g. verdicts) is deep-merged. */
function mergeAnalysisEntriesJson(localRaw, importedRaw, mapField = null) {
  let local = { entries: {} };
  let imported = { entries: {} };
  try {
    const p = JSON.parse(localRaw || '{}');
    if (p && typeof p === 'object' && p.entries && typeof p.entries === 'object') local = p;
  } catch (_) { /* keep empty */ }
  try {
    const p = JSON.parse(importedRaw || '{}');
    if (p && typeof p === 'object' && p.entries && typeof p.entries === 'object') imported = p;
  } catch (_) { /* keep empty */ }
  const out = { entries: { ...(local.entries || {}) } };
  for (const [fp, entry] of Object.entries(imported.entries || {})) {
    if (!entry || typeof entry !== 'object') continue;
    const existing = out.entries[fp];
    if (!existing) {
      out.entries[fp] = entry;
      continue;
    }
    if (mapField && entry[mapField] && typeof entry[mapField] === 'object') {
      out.entries[fp] = {
        ...existing,
        ...entry,
        [mapField]: { ...(existing[mapField] || {}), ...(entry[mapField] || {}) },
        savedAt: Math.max(Number(existing.savedAt) || 0, Number(entry.savedAt) || 0),
      };
    } else if ((Number(entry.savedAt) || 0) >= (Number(existing.savedAt) || 0)) {
      out.entries[fp] = entry;
    }
  }
  return JSON.stringify(out);
}

function applyImportedAnalysisState() {
  loadSecurityVerdictsForCurrent();
  try { loadDexRenamesFromStorage(); } catch (_) {}
  try { loadDexAnnotationsFromStorage(); } catch (_) {}
  try { loadDexBookmarksFromStorage(); } catch (_) {}
  try { loadCfgMethodBlockState(); } catch (_) {}

  try {
    const yaml = localStorage.getItem(SECURITY_RULES_KEY);
    if (yaml != null) {
      securitySemgrepRulesYaml = yaml.trim() ? yaml : null;
      if (securityRulesEditor && yaml.trim()) {
        setSemgrepRulesEditorValue(yaml);
        try {
          renderSemgrepRulesList(validateYamlText(yaml));
        } catch (_) { /* invalid yaml — leave editor as-is */ }
      }
    }
  } catch (_) {}

  try {
    const raw = localStorage.getItem('droid2web-decompile-options');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && typeof decompileOptions === 'object') {
        Object.assign(decompileOptions, parsed);
        if (typeof syncDecompileOptionsUI === 'function') syncDecompileOptionsUI();
      }
    }
  } catch (_) {}

  // Theme + custom UI tokens
  try {
    const theme = localStorage.getItem(THEME_STORAGE_KEY);
    if (theme && typeof setTheme === 'function') {
      setTheme(theme, { playNyan: false });
    }
  } catch (_) {}
  try {
    if (typeof loadUiSettings === 'function') {
      uiSettings = loadUiSettings();
      applyUiTokenOverrides();
      if (typeof refreshSettingsControls === 'function') refreshSettingsControls();
    }
  } catch (_) {}

  try {
    showAndroidFrameworkClasses = localStorage.getItem(SHOW_ANDROID_CLASSES_KEY) === '1';
    const chk = document.getElementById('show-android-classes');
    if (chk) chk.checked = showAndroidFrameworkClasses;
  } catch (_) {}

  const fp = securityFileFingerprint();
  const entry = fp ? loadSecurityCacheEntry(fp) : null;
  if (entry) {
    applySecurityCacheEntry(entry);
  } else {
    renderSecurityPanel();
  }

  // Refresh CFG so imported block positions / read / notes apply to the open method.
  try {
    const ctx = getCodeViewContext();
    if (ctx && codeViewMethodIdx != null) {
      const method = ctx.classes[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
      if (method) renderCfgGraph(method);
    }
  } catch (_) {}

  // Refresh source so imported line comments / renames appear.
  try { renderSourceWithSearch(); } catch (_) {}
  try {
    if (typeof invalidateCurrentMethodAndRefresh === 'function') {
      // Keep cached decompilation if present; tree labels still need rename refresh.
      if (typeof refreshTreeRenameLabels === 'function') refreshTreeRenameLabels();
    }
  } catch (_) {}
  try { updateAnnotationPanel(); } catch (_) {}
}

/**
 * @param {object} payload
 * @param {'merge'|'replace'} mode
 * @returns {string[]} applied keys
 */
function importAnalysisLocalStorage(payload, mode = 'merge') {
  if (!payload || typeof payload !== 'object') throw new Error('Invalid export file');
  if (payload.format !== ANALYSIS_EXPORT_FORMAT) {
    throw new Error('Not a droid2web analysis export (missing format marker)');
  }
  if (!payload.keys || typeof payload.keys !== 'object') throw new Error('Export has no keys');
  const allowed = new Set(analysisExportKeyList());
  const applied = [];
  for (const [key, value] of Object.entries(payload.keys)) {
    if (!allowed.has(key)) continue;
    const raw = normalizeExportKeyValue(value);
    if (raw == null) continue;
    try {
      if (
        mode === 'merge' &&
        (key === SECURITY_CACHE_KEY ||
          key === SECURITY_VERDICTS_KEY ||
          key === RENAMES_STORAGE_KEY ||
          key === ANNOTATIONS_STORAGE_KEY ||
          key === BOOKMARKS_STORAGE_KEY ||
          key === CFG_STATE_KEY ||
          key === SOURCE_COMMENTS_KEY)
      ) {
        const local = localStorage.getItem(key);
        if (key === CFG_STATE_KEY) {
          localStorage.setItem(key, mergeCfgStateJson(local, raw));
        } else if (key === SOURCE_COMMENTS_KEY) {
          localStorage.setItem(key, mergeSourceCommentsJson(local, raw));
        } else {
          const mapField = key === SECURITY_VERDICTS_KEY ? 'verdicts' : null;
          localStorage.setItem(key, mergeAnalysisEntriesJson(local, raw, mapField));
        }
      } else {
        localStorage.setItem(key, raw);
      }
      applied.push(key);
    } catch (e) {
      warn('analysis import failed for', key, e);
    }
  }
  if (!applied.length) throw new Error('No recognized analysis keys in export');
  applyImportedAnalysisState();
  return applied;
}

async function promptImportAnalysisFile(file) {
  if (!file) return;
  let text;
  try {
    text = await file.text();
  } catch (e) {
    reportStorageIoStatus('Reload failed — could not read file');
    return;
  }
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (e) {
    reportStorageIoStatus('Reload failed — invalid JSON');
    return;
  }
  if (!window.confirm('Load this file into localStorage?')) {
    reportStorageIoStatus('Reload cancelled');
    return;
  }
  const merge = window.confirm(
    'Merge with existing localStorage?\n\n' +
    'OK = merge (recommended — keeps local TP/FP, scans, comments)\n' +
    'Cancel = replace only the keys present in this file'
  );
  const mode = merge ? 'merge' : 'replace';
  try {
    const applied = importAnalysisLocalStorage(payload, mode);
    const short = applied.map((k) => k.replace(/^droid2web-/, '')).join(', ');
    reportStorageIoStatus(`Reloaded (${mode}) · ${applied.length} key(s): ${short}`);
  } catch (e) {
    reportStorageIoStatus('Reload failed — ' + (e?.message || e));
  }
}

function saveSecurityCache() {
  const fp = securityFileFingerprint();
  if (!fp) return false;
  if (!securityVulnFindings.length && !securitySemgrepFindings.length && !securityMtReport) return false;
  const store = readSecurityCacheStore();
  store.entries[fp] = {
    version: 1,
    fingerprint: fp,
    filename: loadedDexFiles.length > 1
      ? loadedDexFiles.map((d) => d.name).join(' + ')
      : (currentFilename || ''),
    savedAt: Date.now(),
    vulns: securityVulnFindings,
    semgrep: securitySemgrepFindings,
    mt: securityMtReport,
  };
  const keys = Object.keys(store.entries)
    .map((k) => ({ k, at: store.entries[k]?.savedAt || 0 }))
    .sort((a, b) => b.at - a.at);
  while (keys.length > SECURITY_CACHE_MAX_ENTRIES) {
    const drop = keys.pop();
    delete store.entries[drop.k];
  }
  const ok = writeSecurityCacheStore(store);
  if (ok) {
    securityFromCache = true;
    securityCacheSavedAt = store.entries[fp].savedAt;
  }
  return ok;
}

function clearSecurityCacheForCurrent() {
  const fp = securityFileFingerprint();
  if (!fp) {
    setSecurityStatus('Nothing to clear');
    return;
  }
  const store = readSecurityCacheStore();
  if (store.entries[fp]) {
    delete store.entries[fp];
    writeSecurityCacheStore(store);
  }
  securityVulnFindings = [];
  securitySemgrepFindings = [];
  securityMtReport = null;
  securityFromCache = false;
  securityCacheSavedAt = 0;
  securityCategoryFilter = '';
  securitySourceFilter = '';
  securitySeverityFilter = '';
  securityVerdictFilter = '';
  securityScansRun = { vuln: false, semgrep: false, mt: false };
  securityGroupCollapseState.clear();
  loadSecurityVerdictsForCurrent();
  renderSecurityPanel();
  setSecurityStatus('Cache cleared for this file — run a scan again');
}

function clearSecurityResultsInMemory() {
  securityVulnFindings = [];
  securitySemgrepFindings = [];
  securityMtReport = null;
  securityFromCache = false;
  securityCacheSavedAt = 0;
  securityCategoryFilter = '';
  securitySourceFilter = '';
  securitySeverityFilter = '';
  securityVerdictFilter = '';
  securityScansRun = { vuln: false, semgrep: false, mt: false };
  securityGroupCollapseState.clear();
  loadSecurityVerdictsForCurrent();
}

function applySecurityCacheEntry(entry) {
  securityVulnFindings = filterLibraryVulnFindings(Array.isArray(entry?.vulns) ? entry.vulns : []);
  securitySemgrepFindings = Array.isArray(entry?.semgrep) ? entry.semgrep : [];
  securityMtReport = entry?.mt || null;
  securityFromCache = true;
  securityCacheSavedAt = entry?.savedAt || 0;
  securityScansRun = {
    vuln: entry?.vulns != null,
    semgrep: entry?.semgrep != null,
    mt: entry?.mt != null,
  };
  loadSecurityVerdictsForCurrent();
  renderSecurityPanel();
  const age = securityCacheSavedAt
    ? ` · cached ${formatRelativeTime(securityCacheSavedAt)}`
    : '';
  setSecurityStatus(
    `Restored from localStorage — ${securityVulnFindings.length} vuln(s), ${securitySemgrepFindings.length} Semgrep, ${securityMtReport?.issues?.length || 0} MT issue(s)${age}`
  );
}

function securityCacheEntryCounts(entry) {
  const vulns = Array.isArray(entry?.vulns) ? entry.vulns.length : 0;
  const semgrep = Array.isArray(entry?.semgrep) ? entry.semgrep.length : 0;
  const mt = Array.isArray(entry?.mt?.issues) ? entry.mt.issues.length : 0;
  return { vulns, semgrep, mt };
}

function closeSecurityCacheModal(choice) {
  const resolve = securityCachePromptResolver;
  securityCachePromptResolver = null;

  if (securityCacheModal) {
    const active = document.activeElement;
    if (active && securityCacheModal.contains(active)) {
      const returnTo = securityCacheModalReturnFocus;
      if (returnTo && typeof returnTo.focus === 'function' && document.contains(returnTo)) {
        returnTo.focus({ preventScroll: true });
      } else {
        active.blur();
        document.getElementById('btn-upload')?.focus({ preventScroll: true });
      }
    }
    securityCacheModalReturnFocus = null;
    securityCacheModal.hidden = true;
    securityCacheModal.setAttribute('aria-hidden', 'true');
    securityCacheModal.inert = true;
  }

  if (resolve) resolve(choice === 'clear' ? 'clear' : 'keep');
}

function promptSecurityCacheDecision(entry) {
  return new Promise((resolve) => {
    if (!securityCacheModal) {
      resolve('keep');
      return;
    }
    if (securityCachePromptResolver) {
      securityCachePromptResolver('keep');
      securityCachePromptResolver = null;
    }
    securityCachePromptResolver = resolve;
    const { vulns, semgrep, mt } = securityCacheEntryCounts(entry);
    const age = entry?.savedAt ? formatRelativeTime(entry.savedAt) : 'earlier';
    const name = entry?.filename
      || (loadedDexFiles.length > 1 ? `${loadedDexFiles.length} DEX files` : null)
      || currentFilename
      || 'this file';
    if (securityCacheModalBody) {
      securityCacheModalBody.textContent =
        `"${name}" already has security results in localStorage ` +
        `(${vulns} vuln(s), ${semgrep} Semgrep, ${mt} MT · ${age}). ` +
        `Keep them, or clear localStorage for this file and start fresh?`;
    }
    securityCacheModal.hidden = false;
    securityCacheModal.setAttribute('aria-hidden', 'false');
    securityCacheModal.inert = false;
    securityCacheModalReturnFocus = document.activeElement;
    document.getElementById('security-cache-keep')?.focus();
  });
}

function tryRestoreSecurityCache() {
  const fp = securityFileFingerprint();
  clearSecurityResultsInMemory();
  if (!fp) {
    renderSecurityPanel();
    setSecurityStatus('Load a DEX or APK, then run a scan');
    return false;
  }
  const entry = loadSecurityCacheEntry(fp);
  if (!entry) {
    renderSecurityPanel();
    setSecurityStatus('No cached scan — click Scan');
    return false;
  }
  applySecurityCacheEntry(entry);
  return true;
}

/** After load: if this APK/DEX has cached scans, ask keep vs clear. */
async function resetSecurityResults() {
  clearSecurityResultsInMemory();
  const fp = securityFileFingerprint();
  if (!fp) {
    renderSecurityPanel();
    setSecurityStatus('Load a DEX or APK, then run a scan');
    return;
  }
  const entry = loadSecurityCacheEntry(fp);
  if (!entry) {
    renderSecurityPanel();
    setSecurityStatus('No cached scan — click Scan');
    return;
  }
  renderSecurityPanel();
  setSecurityStatus('Cached security results found — choose Keep or Clear…');
  const choice = await promptSecurityCacheDecision(entry);
  if (choice === 'clear') {
    clearSecurityCacheForCurrent();
  } else {
    applySecurityCacheEntry(entry);
  }
}

function formatRelativeTime(ts) {
  const sec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (sec < 60) return 'just now';
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function securityCategoryClass(cat) {
  return String(cat || 'vuln').toLowerCase().replace(/[^a-z0-9]+/g, '_');
}

function securitySeverityClass(catOrSev) {
  const s = String(catOrSev || '').toLowerCase().trim();
  if (s === 'high' || s === 'critical' || s === 'error') return 'sev-high';
  if (s === 'medium' || s === 'med' || s === 'warning') return 'sev-med';
  if (s === 'low') return 'sev-low';
  if (s === 'info' || s === 'informational') return 'sev-info';
  const c = securityCategoryClass(catOrSev);
  if (/rce|code.?exec|sql|command|spoof|pending|path.?trav|deserial/.test(c)) return 'sev-high';
  if (/webview|intent|ipc|injection/.test(c)) return 'sev-med';
  if (/secret|hardcoded|crypto|ssl|cert|logging/.test(c)) return 'sev-low';
  return 'sev-info';
}

function vulnFindingSeverityClass(f) {
  if (f?.severity) return securitySeverityClass(f.severity);
  return securitySeverityClass(f?.category);
}

function formatCategoryLabel(cat) {
  return String(cat || 'other').replace(/_/g, ' ');
}

/** Collect DEX byte buffers to scan — extract only primary/capped DEXes (not every Facebook multidex). */
async function collectDexScanTargets() {
  await ensureMainWasm();
  const targets = [];

  // Standalone DEX session (single or multi-file upload)
  if (currentType === 'dex' && loadedDexFiles.length > 0) {
    for (const d of loadedDexFiles) {
      if (d?.bytes?.length) targets.push({ name: d.name || 'classes.dex', bytes: d.bytes });
    }
    if (targets.length) return prioritizeDexScanTargets(targets);
  }
  if (currentType === 'dex' && currentDexBytes?.length) {
    targets.push({ name: currentFilename || 'classes.dex', bytes: currentDexBytes });
    return prioritizeDexScanTargets(targets);
  }

  if (currentType === 'apk' && currentApkBytes && Array.isArray(currentData?.files)) {
    // Sort names first, then extract only until we have enough under the size/count caps.
    // Extracting every DEX from a huge APK on the main thread freezes the UI.
    const names = listApkDexNames(currentData.files);
    setUiActivity('scan-extract', 'Preparing scan', `0/${Math.min(names.length, SECURITY_MAX_DEX_FILES)} DEX`);
    try {
      for (let i = 0; i < names.length && targets.length < SECURITY_MAX_DEX_FILES; i++) {
        const name = names[i];
        setUiActivity('scan-extract', 'Preparing scan', `${targets.length + 1}/${SECURITY_MAX_DEX_FILES} · ${shortDexLabel(name)}`);
        let bytes;
        try {
          bytes = get_apk_file_content(currentApkBytes, name);
        } catch (e) {
          warn('[security] extract failed', name, e);
          await yieldToUi();
          continue;
        }
        await yieldToUi();
        if (!bytes?.length) continue;
        if (bytes.length > SECURITY_MAX_DEX_BYTES) {
          debug('[security] skip oversized', name, formatFileSize(bytes.length));
          continue;
        }
        targets.push({ name, bytes });
        await yieldToUi();
      }
    } finally {
      clearUiActivity('scan-extract');
    }
    return targets;
  }
  if (apkExtractedFile?.kind === 'dex' && apkExtractedFile.bytes?.length) {
    targets.push({ name: apkExtractedFile.name || 'classes.dex', bytes: apkExtractedFile.bytes });
  }
  return prioritizeDexScanTargets(targets);
}

/**
 * Prefer classes.dex / classes2.dex…, drop oversized DEXes, and cap count so Facebook-scale
 * multidex APKs finish instead of scanning 20+ DEX files forever.
 */
function prioritizeDexScanTargets(targets) {
  if (!targets.length) return targets;
  const dexNum = (name) => {
    const n = String(name || '').toLowerCase();
    if (n === 'classes.dex' || n.endsWith('/classes.dex')) return 1;
    const m = n.match(/classes(\d+)\.dex$/);
    return m ? parseInt(m[1], 10) : 999;
  };
  const sorted = [...targets].sort((a, b) => {
    const na = dexNum(a.name);
    const nb = dexNum(b.name);
    if (na !== nb) return na - nb;
    return (a.bytes?.length || 0) - (b.bytes?.length || 0);
  });
  const kept = [];
  const skipped = [];
  for (const t of sorted) {
    const size = t.bytes?.length || 0;
    if (size > SECURITY_MAX_DEX_BYTES) {
      skipped.push(`${t.name} (${formatFileSize(size)} > ${formatFileSize(SECURITY_MAX_DEX_BYTES)})`);
      continue;
    }
    if (kept.length >= SECURITY_MAX_DEX_FILES) {
      skipped.push(t.name);
      continue;
    }
    kept.push(t);
  }
  if (skipped.length) {
    debug(
      '[security] DEX scan limited to',
      kept.map((t) => t.name).join(', '),
      '· skipped',
      skipped.slice(0, 8).join(', '),
      skipped.length > 8 ? `+${skipped.length - 8} more` : ''
    );
  }
  return kept;
}

function isSecurityWorkerTimeoutError(err) {
  const msg = String(err?.message || err || '');
  return /timed out/i.test(msg);
}

function semgrepSeverityClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'ERROR' || s === 'CRITICAL') return 'sev-high';
  if (s === 'WARNING' || s === 'HIGH') return 'sev-med';
  if (s === 'LOW' || s === 'MEDIUM') return 'sev-low';
  return 'sev-info';
}

function securitySeverityRank(sevCls) {
  return ({ 'sev-high': 0, 'sev-med': 1, 'sev-low': 2, 'sev-info': 3 })[sevCls] ?? 4;
}

function securitySeverityLabel(sevCls) {
  return ({ 'sev-high': 'High', 'sev-med': 'Medium', 'sev-low': 'Low', 'sev-info': 'Info' })[sevCls] || 'Info';
}

function securityMatchesSeverity(sevCls) {
  if (!securitySeverityFilter) return true;
  return sevCls === securitySeverityFilter;
}

/** Severity counts for findings that pass the current source filter (ignore category/text). */
function collectSeverityCountsForSource() {
  const sev = { high: 0, med: 0, low: 0, info: 0 };
  const bump = (sevCls) => {
    const r = securitySeverityRank(sevCls);
    if (r === 0) sev.high++;
    else if (r === 1) sev.med++;
    else if (r === 2) sev.low++;
    else sev.info++;
  };
  if (securitySourceFilter !== 'semgrep' && securitySourceFilter !== 'mt') {
    for (const f of securityVulnFindings) bump(vulnFindingSeverityClass(f));
  }
  if (securitySourceFilter !== 'vuln' && securitySourceFilter !== 'mt') {
    for (const f of securitySemgrepFindings) bump(semgrepSeverityClass(f.severity));
  }
  if (securitySourceFilter !== 'vuln' && securitySourceFilter !== 'semgrep') {
    const n = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0;
    sev.med += n;
  }
  return sev;
}

function collectSecurityStats() {
  const vulnN = securityVulnFindings.length;
  const sgN = securitySemgrepFindings.length;
  const mtN = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0;
  const total = vulnN + sgN + mtN;
  const sev = { high: 0, med: 0, low: 0, info: 0 };
  for (const f of securityVulnFindings) {
    const r = securitySeverityRank(vulnFindingSeverityClass(f));
    if (r === 0) sev.high++;
    else if (r === 1) sev.med++;
    else if (r === 2) sev.low++;
    else sev.info++;
  }
  for (const f of securitySemgrepFindings) {
    const r = securitySeverityRank(semgrepSeverityClass(f.severity));
    if (r === 0) sev.high++;
    else if (r === 1) sev.med++;
    else if (r === 2) sev.low++;
    else sev.info++;
  }
  sev.med += mtN;
  const cats = new Set(securityVulnFindings.map((f) => securityCategoryClass(f.category)));
  const scansDone = (securityScansRun.vuln ? 1 : 0) + (securityScansRun.semgrep ? 1 : 0) + (securityScansRun.mt ? 1 : 0);
  const live = securityScanBusy || total > 0 || scansDone > 0;
  return { total, vulnN, sgN, mtN, sev, cats: cats.size, scansDone, live };
}

function vulnMatchesFilters(f) {
  if (securitySourceFilter === 'semgrep' || securitySourceFilter === 'mt') return false;
  if (securityCategoryFilter && securityCategoryClass(f.category) !== securityCategoryFilter) return false;
  if (!securityMatchesSeverity(vulnFindingSeverityClass(f))) return false;
  const q = (securityFilterQuery || '').trim().toLowerCase();
  if (!q) return true;
  const blob = [f.category, f.title, f.severity, f.message, f.problem, f.recommendation, f.cwe, f.class_name, f.method_name, f.source_desc, f.sink_desc, f.dex_file, ...(Array.isArray(f.trace) ? f.trace.map((t) => t.description) : [])].join(' ');
  return blob.toLowerCase().includes(q);
}

function mtMatchesFilters(iss) {
  if (securitySourceFilter === 'vuln' || securitySourceFilter === 'semgrep') return false;
  if (securityCategoryFilter) return false;
  if (!securityMatchesSeverity('sev-med')) return false;
  const q = (securityFilterQuery || '').trim().toLowerCase();
  if (!q) return true;
  const frames = (iss.trace || []).map((t) => `${t.class_name}#${t.method_name} ${t.description}`).join(' ');
  const blob = [iss.rule_name, iss.rule_code, iss.source_kind, iss.sink_kind, iss.callable, iss.description, frames, iss.dex_file].join(' ');
  return blob.toLowerCase().includes(q);
}

function semgrepMatchesFilters(f) {
  if (securitySourceFilter === 'vuln' || securitySourceFilter === 'mt') return false;
  if (securityCategoryFilter && securityCategoryFilter.startsWith('sg_')) {
    const want = securityCategoryFilter.slice(3);
    if (securityCategoryClass(f.vuln_class || f.rule_id || '') !== want && securityCategoryClass(f.rule_id || '') !== want) {
      return false;
    }
  } else if (securityCategoryFilter) {
    return false;
  }
  if (!securityMatchesSeverity(semgrepSeverityClass(f.severity))) return false;
  const q = (securityFilterQuery || '').trim().toLowerCase();
  if (!q) return true;
  const blob = [f.rule_id, f.severity, f.message, f.class_name, f.method_name, f.sink_desc, f.vuln_class, f.chain_tag, f.match_kind, f.dex_file].join(' ');
  return blob.toLowerCase().includes(q);
}

function renderSecurityOverview() {
  const stats = collectSecurityStats();
  const hasScans = stats.live;
  const hasFindings = stats.total > 0;

  if (securityOverviewEl) securityOverviewEl.hidden = !hasScans;
  if (securityFiltersEl) securityFiltersEl.hidden = !hasScans;

  if (!securityOverviewGrid) return;
  if (!hasScans) {
    securityOverviewGrid.innerHTML = '';
    if (securityOverviewBarWrap) securityOverviewBarWrap.hidden = true;
    if (securityOverviewScans) securityOverviewScans.innerHTML = '';
    return;
  }

  const cacheBit = securityFromCache && securityCacheSavedAt
    ? `<span class="security-overview-cache">Cached ${escapeHtml(formatRelativeTime(securityCacheSavedAt))}</span>`
    : '';
  const scanningBit = securityScanBusy
    ? `<span class="security-overview-cache">Scanning…</span>`
    : '';

  securityOverviewGrid.innerHTML = `
    <button type="button" class="security-stat-card security-stat-total${!securitySeverityFilter ? ' active' : ''}" data-sev="" title="Show all severities">
      <span class="security-stat-value">${stats.total}</span>
      <span class="security-stat-label">Total findings</span>
    </button>
    <button type="button" class="security-stat-card sev-high${securitySeverityFilter === 'sev-high' ? ' active' : ''}" data-sev="sev-high" title="Filter High severity">
      <span class="security-stat-value">${stats.sev.high}</span>
      <span class="security-stat-label">High</span>
    </button>
    <button type="button" class="security-stat-card sev-med${securitySeverityFilter === 'sev-med' ? ' active' : ''}" data-sev="sev-med" title="Filter Medium severity">
      <span class="security-stat-value">${stats.sev.med}</span>
      <span class="security-stat-label">Medium</span>
    </button>
    <button type="button" class="security-stat-card sev-low${securitySeverityFilter === 'sev-low' ? ' active' : ''}" data-sev="sev-low" title="Filter Low severity">
      <span class="security-stat-value">${stats.sev.low}</span>
      <span class="security-stat-label">Low</span>
    </button>
    <button type="button" class="security-stat-card sev-info${securitySeverityFilter === 'sev-info' ? ' active' : ''}" data-sev="sev-info" title="Filter Info severity">
      <span class="security-stat-value">${stats.sev.info}</span>
      <span class="security-stat-label">Info</span>
    </button>
    <div class="security-stat-card security-stat-meta">
      <span class="security-stat-value">${stats.scansDone}<span class="security-stat-dim">/3</span></span>
      <span class="security-stat-label">Scans run</span>
      ${cacheBit}${scanningBit}
    </div>
  `;

  if (securityOverviewBarWrap && securityOverviewBar && securityOverviewBarLegend) {
    if (hasFindings) {
      securityOverviewBarWrap.hidden = false;
      const sum = Math.max(1, stats.total);
      const pct = (n) => Math.max(n ? 4 : 0, Math.round((n / sum) * 100));
      const barSeg = (key, cls, n) => n
        ? `<button type="button" class="bar-seg ${cls}${securitySeverityFilter === key ? ' active' : ''}" style="width:${pct(n)}%" data-sev="${key}" title="Filter ${securitySeverityLabel(key)}"></button>`
        : '';
      securityOverviewBar.innerHTML =
        barSeg('sev-high', 'sev-high', stats.sev.high) +
        barSeg('sev-med', 'sev-med', stats.sev.med) +
        barSeg('sev-low', 'sev-low', stats.sev.low) +
        barSeg('sev-info', 'sev-info', stats.sev.info);
      const leg = (key, cls, label, n) => n
        ? `<button type="button" class="bar-key ${cls}${securitySeverityFilter === key ? ' active' : ''}" data-sev="${key}">${label} ${n}</button>`
        : '';
      securityOverviewBarLegend.innerHTML = [
        leg('sev-high', 'sev-high', 'High', stats.sev.high),
        leg('sev-med', 'sev-med', 'Medium', stats.sev.med),
        leg('sev-low', 'sev-low', 'Low', stats.sev.low),
        leg('sev-info', 'sev-info', 'Info', stats.sev.info),
      ].filter(Boolean).join('');
    } else {
      securityOverviewBarWrap.hidden = true;
    }
  }

  if (securityOverviewScans) {
    const active = (key) => securityScanBusy && securityScanPhaseState[key] === 'active';
    const pill = (key, label, count, done) => {
      const showCount = done || count > 0 || active(key);
      return `<button type="button" class="security-scan-pill${done ? ' done' : ''}${active(key) ? ' scanning' : ''}${securitySourceFilter === key ? ' active' : ''}" data-source="${escapeAttr(key)}">` +
        `<span class="security-scan-pill-k">${escapeHtml(label)}</span>` +
        `<span class="security-scan-pill-v">${showCount ? count : '—'}</span></button>`;
    };
    securityOverviewScans.innerHTML =
      pill('vuln', 'Vuln scan', stats.vulnN, securityScansRun.vuln) +
      pill('semgrep', 'Semgrep', stats.sgN, securityScansRun.semgrep) +
      pill('mt', 'MT taint', stats.mtN, securityScansRun.mt) +
      (stats.cats ? `<span class="security-scan-pill muted-pill">${stats.cats} vuln categor${stats.cats === 1 ? 'y' : 'ies'}</span>` : '');
  }
}

function renderSecuritySourceTabs() {
  if (!securitySourceTabsEl) return;
  const stats = collectSecurityStats();
  if (!stats.live) {
    securitySourceTabsEl.innerHTML = '';
    return;
  }
  const tabs = [
    ['', 'All', stats.total],
    ['vuln', 'Vuln', stats.vulnN],
    ['semgrep', 'Semgrep', stats.sgN],
    ['mt', 'MT taint', stats.mtN],
  ];
  securitySourceTabsEl.innerHTML = tabs.map(([key, label, n]) =>
    `<button type="button" class="security-source-tab${securitySourceFilter === key ? ' active' : ''}" data-source="${escapeAttr(key)}">` +
    `${escapeHtml(label)}<span class="chip-n">${n}</span></button>`
  ).join('');
}

function renderSecuritySevTabs() {
  if (!securitySevTabsEl) return;
  const stats = collectSecurityStats();
  if (!stats.live) {
    securitySevTabsEl.innerHTML = '';
    return;
  }
  const sev = collectSeverityCountsForSource();
  const total = sev.high + sev.med + sev.low + sev.info;
  const tabs = [
    ['', 'All levels', total, ''],
    ['sev-high', 'High', sev.high, 'sev-high'],
    ['sev-med', 'Medium', sev.med, 'sev-med'],
    ['sev-low', 'Low', sev.low, 'sev-low'],
    ['sev-info', 'Info', sev.info, 'sev-info'],
  ];
  securitySevTabsEl.innerHTML = tabs.map(([key, label, n, cls]) =>
    `<button type="button" class="security-sev-tab${cls ? ' ' + cls : ''}${securitySeverityFilter === key ? ' active' : ''}" data-sev="${escapeAttr(key)}"${n === 0 && key ? ' disabled' : ''}>` +
    `${escapeHtml(label)}<span class="chip-n">${n}</span></button>`
  ).join('');
}

function renderSecurityVerdictTabs() {
  if (!securityVerdictTabsEl) return;
  const stats = collectSecurityStats();
  if (!stats.live || !stats.total) {
    securityVerdictTabsEl.innerHTML = '';
    return;
  }
  const c = collectVerdictCounts();
  const total = c.unmarked + c.tp + c.fp;
  const tabs = [
    ['', 'All triage', total, ''],
    ['unmarked', 'Unmarked', c.unmarked, 'verdict-unmarked'],
    ['tp', 'TP', c.tp, 'verdict-tp'],
    ['fp', 'FP', c.fp, 'verdict-fp'],
  ];
  securityVerdictTabsEl.innerHTML = tabs.map(([key, label, n, cls]) =>
    `<button type="button" class="security-verdict-tab${cls ? ' ' + cls : ''}${securityVerdictFilter === key ? ' active' : ''}" data-verdict-filter="${escapeAttr(key)}">` +
    `${escapeHtml(label)}<span class="chip-n">${n}</span></button>`
  ).join('');
}

function renderSecurityChips() {
  if (!securityChipsEl) return;
  if (securitySourceFilter === 'semgrep' || securitySourceFilter === 'mt') {
    securityChipsEl.hidden = true;
    securityChipsEl.innerHTML = '';
    return;
  }
  const counts = new Map();
  for (const f of securityVulnFindings) {
    const key = securityCategoryClass(f.category);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  if (!counts.size) {
    securityChipsEl.hidden = true;
    securityChipsEl.innerHTML = '';
    return;
  }
  securityChipsEl.hidden = false;
  const parts = [
    `<button type="button" class="security-chip${!securityCategoryFilter ? ' active' : ''}" data-cat="">All vuln types<span class="chip-n">${securityVulnFindings.length}</span></button>`,
  ];
  const keys = [...counts.keys()].sort((a, b) => (counts.get(b) - counts.get(a)) || a.localeCompare(b));
  for (const key of keys) {
    parts.push(
      `<button type="button" class="security-chip${securityCategoryFilter === key ? ' active' : ''}" data-cat="${escapeAttr(key)}">${escapeHtml(formatCategoryLabel(key))}<span class="chip-n">${counts.get(key)}</span></button>`
    );
  }
  securityChipsEl.innerHTML = parts.join('');
}

function collectFilteredSecurityItems() {
  const items = [];
  for (const f of securityVulnFindings) {
    if (!vulnMatchesFilters(f)) continue;
    const findingId = securityVulnFindingId(f);
    if (!securityMatchesVerdict(findingId)) continue;
    const sevCls = vulnFindingSeverityClass(f);
    items.push({
      kind: 'vuln',
      sevCls,
      sevRank: securitySeverityRank(sevCls),
      className: f.class_name || '',
      methodName: f.method_name || '',
      dexFile: f.dex_file || '',
      html: renderVulnFindingCard(f, { groupedByClass: true, findingId }),
    });
  }
  for (const f of securitySemgrepFindings) {
    if (!semgrepMatchesFilters(f)) continue;
    const findingId = securitySemgrepFindingId(f);
    if (!securityMatchesVerdict(findingId)) continue;
    const sevCls = semgrepSeverityClass(f.severity);
    items.push({
      kind: 'semgrep',
      sevCls,
      sevRank: securitySeverityRank(sevCls),
      className: f.class_name || '',
      methodName: f.method_name || '',
      dexFile: f.dex_file || '',
      html: renderSemgrepFindingCard(f, { groupedByClass: true, findingId }),
    });
  }
  const issues = Array.isArray(securityMtReport?.issues) ? securityMtReport.issues : [];
  issues.forEach((iss, idx) => {
    if (!mtMatchesFilters(iss)) return;
    const findingId = securityMtFindingId(iss, idx);
    if (!securityMatchesVerdict(findingId)) return;
    const sevCls = 'sev-med';
    const nav = securityMtNavTarget(iss);
    items.push({
      kind: 'mt',
      sevCls,
      sevRank: securitySeverityRank(sevCls),
      className: nav.className || '',
      methodName: nav.methodName || '',
      dexFile: nav.dexFile || iss.dex_file || '',
      html: renderMtFindingCard(iss, idx, { groupedByClass: true, findingId }),
    });
  });
  items.sort((a, b) => a.sevRank - b.sevRank || String(a.className).localeCompare(String(b.className)));
  return items;
}

function securityClassSimpleName(className) {
  const n = String(className || '').trim();
  if (!n || n === '(unknown class)') return n || '?';
  const parts = n.split('.');
  return parts[parts.length - 1] || n;
}

function securityClassPackageName(className) {
  const n = String(className || '').trim();
  const i = n.lastIndexOf('.');
  return i > 0 ? n.slice(0, i) : '';
}

function renderUnifiedSecurityFindings(items) {
  if (!items.length) return '';
  const byClass = new Map();
  for (const item of items) {
    const key = String(item.className || '').trim() || '(unknown class)';
    if (!byClass.has(key)) byClass.set(key, []);
    byClass.get(key).push(item);
  }
  const classKeys = [...byClass.keys()].sort((a, b) => {
    const ia = byClass.get(a);
    const ib = byClass.get(b);
    const ra = Math.min(...ia.map((i) => i.sevRank));
    const rb = Math.min(...ib.map((i) => i.sevRank));
    if (ra !== rb) return ra - rb;
    if (ib.length !== ia.length) return ib.length - ia.length;
    return a.localeCompare(b);
  });
  // Many classes → start collapsed so the user clicks a class to inspect its findings.
  const defaultCollapsed = classKeys.length > 8;

  return classKeys.map((className) => {
    const groupItems = byClass.get(className).slice().sort((a, b) =>
      a.sevRank - b.sevRank || String(a.methodName).localeCompare(String(b.methodName))
    );
    const groupKey = 'class:' + className;
    const collapsed = isSecurityGroupCollapsed(groupKey, defaultCollapsed);
    const dexFile = groupItems.find((i) => i.dexFile)?.dexFile || '';
    const sevCounts = { 'sev-high': 0, 'sev-med': 0, 'sev-low': 0, 'sev-info': 0 };
    for (const i of groupItems) sevCounts[i.sevCls] = (sevCounts[i.sevCls] || 0) + 1;
    const sevBits = ['sev-high', 'sev-med', 'sev-low', 'sev-info']
      .filter((k) => sevCounts[k])
      .map((k) => `<span class="security-group-sev ${k}">${sevCounts[k]}</span>`)
      .join('');
    const simple = securityClassSimpleName(className);
    const pkg = securityClassPackageName(className);
    const dexHint = dexFile ? `<span class="muted security-group-dex">${escapeHtml(shortDexLabel(dexFile))}</span>` : '';
    return `<div class="security-group security-group-class${collapsed ? ' collapsed' : ''}" data-group="${escapeAttr(groupKey)}">
      <div class="security-group-header-row">
        <button type="button" class="security-group-header" data-group-toggle="${escapeAttr(groupKey)}" data-group-default-collapsed="${defaultCollapsed ? '1' : '0'}" title="${escapeAttr(className)}">
          <span class="arrow">${collapsed ? '▶' : '▼'}</span>
          <span class="security-group-class-name">${escapeHtml(simple)}</span>
          ${pkg ? `<span class="muted security-group-pkg">${escapeHtml(pkg)}</span>` : ''}
          <span class="muted security-group-count">${groupItems.length}</span>
          ${sevBits}
          ${dexHint}
        </button>
        <button type="button" class="security-group-open" data-open-class="${escapeAttr(className)}" data-dex="${escapeAttr(dexFile)}" title="Open class in Code">Open</button>
      </div>
      <div class="security-group-body security-list">${groupItems.map((i) => i.html).join('')}</div>
    </div>`;
  }).join('');
}

function renderSecurityFindingsList() {
  if (!securityFindingsList) return;
  const stats = collectSecurityStats();
  const scrollTop = securityFindingsList.scrollTop || 0;

  if (!stats.live) {
    securityFindingsList.innerHTML = '';
    if (securityFindingsCount) securityFindingsCount.textContent = '';
    return;
  }

  const items = collectFilteredSecurityItems();
  const totalAvailable = stats.total;
  if (securityFindingsCount) {
    if (!items.length) {
      if (securityScanBusy && !totalAvailable) {
        securityFindingsCount.textContent = 'Scanning — findings appear as they are found';
      } else if (stats.scansDone && !totalAvailable) {
        securityFindingsCount.textContent = 'Scans complete — no issues found';
      } else {
        securityFindingsCount.textContent = 'No matches';
      }
    } else {
      const classCount = new Set(items.map((i) => String(i.className || '').trim() || '(unknown class)')).size;
      let countText = items.length === totalAvailable
        ? `${items.length} finding${items.length === 1 ? '' : 's'}`
        : `${items.length} of ${totalAvailable} shown`;
      countText += ` · ${classCount} class${classCount === 1 ? '' : 'es'}`;
      if (securitySeverityFilter) countText += ` · ${securitySeverityLabel(securitySeverityFilter)}`;
      if (securityVerdictFilter === 'tp') countText += ' · TP';
      else if (securityVerdictFilter === 'fp') countText += ' · FP';
      else if (securityVerdictFilter === 'unmarked') countText += ' · unmarked';
      if (securityScanBusy) countText += ' · live';
      if (securitySourceFilter === 'mt' && securityMtReport?.stats) {
        const s = securityMtReport.stats;
        countText += ` · ${s.methods_analyzed ?? 0} methods, ${s.call_edges ?? 0} edges`;
      }
      securityFindingsCount.textContent = countText;
    }
  }

  if (!items.length) {
    const msg = totalAvailable
      ? 'No findings match the current filter'
      : (securityScanBusy
        ? 'Waiting for the first finding…'
        : 'All scans completed — no security issues detected');
    securityFindingsList.innerHTML = `<div class="code-empty"><div class="code-empty-title">${totalAvailable ? 'No matches' : (securityScanBusy ? 'Scanning' : 'All clear')}</div><div class="code-empty-hint muted">${msg}</div></div>`;
    return;
  }

  securityFindingsList.innerHTML = renderUnifiedSecurityFindings(items);
  securityFindingsList.scrollTop = scrollTop;
}

let securityLiveRefreshTimer = 0;
let securityLiveRefreshQueued = false;
/** Refresh findings UI during an in-progress scan (throttled — full re-render is expensive). */
function refreshSecurityFindingsLive() {
  securityLiveRefreshQueued = true;
  if (securityLiveRefreshTimer) return;
  securityLiveRefreshTimer = setTimeout(() => {
    securityLiveRefreshTimer = 0;
    if (!securityLiveRefreshQueued) return;
    securityLiveRefreshQueued = false;
    // Avoid rebuilding the whole overview on every worker tick — list + status only.
    try {
      renderSecurityFindingsList();
      updateStatusBar();
    } catch (e) {
      warn('[security] live refresh failed', e);
    }
  }, 450);
}

let pendingSecurityBytecodeHighlight = null;

function formatSecHexOffset(off) {
  const n = Number(off) >>> 0;
  return '0x' + n.toString(16).padStart(4, '0');
}

function parseSecurityCallable(callable) {
  const s = String(callable || '').trim();
  const hash = s.lastIndexOf('#');
  if (hash <= 0) return { className: s, methodName: '' };
  return { className: s.slice(0, hash), methodName: s.slice(hash + 1) };
}

function normalizeClassLookupName(name) {
  return String(name || '').trim();
}

function classNamesEquivalent(a, b) {
  const x = normalizeClassLookupName(a);
  const y = normalizeClassLookupName(b);
  if (!x || !y) return false;
  if (x === y) return true;
  if (x.replace(/\$/g, '.') === y.replace(/\$/g, '.')) return true;
  return x.replace(/\./g, '$') === y.replace(/\./g, '$');
}

function findClassIndexInDex(classes, className) {
  if (!Array.isArray(classes) || !className) return -1;
  let idx = classes.findIndex((c) => c?.name === className);
  if (idx >= 0) return idx;
  idx = classes.findIndex((c) => classNamesEquivalent(c?.name, className));
  return idx;
}

function findMethodIndexInClass(methods, methodName, hintText = '') {
  if (!methodName || !Array.isArray(methods)) return -1;
  const want = String(methodName);
  const matches = [];
  for (let i = 0; i < methods.length; i++) {
    const n = methods[i]?.name || '';
    if (n === want || (want === '<init>' && n === 'constructor')) matches.push(i);
  }
  if (!matches.length) return -1;
  if (matches.length === 1) return matches[0];
  const hint = String(hintText || '').toLowerCase();
  if (hint) {
    for (const idx of matches) {
      const desc = String(methods[idx]?.descriptor || '').toLowerCase();
      if (desc && hint.includes(desc.slice(0, 24))) return idx;
    }
    for (const idx of matches) {
      const desc = String(methods[idx]?.descriptor || '').toLowerCase();
      const tokens = hint.match(/L[\w/$]+;|\([^)]*\)/g) || [];
      if (tokens.some((t) => desc.includes(t.toLowerCase()))) return idx;
    }
  }
  return matches[0];
}

function queueSecurityBytecodeHighlight(offset) {
  if (offset == null || Number.isNaN(Number(offset))) {
    pendingSecurityBytecodeHighlight = null;
    return;
  }
  pendingSecurityBytecodeHighlight = Number(offset) >>> 0;
}

function clearSecurityBytecodeHighlight() {
  pendingSecurityBytecodeHighlight = null;
  bytecodeListing?.querySelectorAll('.bytecode-line.security-finding-highlight').forEach((el) => {
    el.classList.remove('security-finding-highlight');
  });
}

function applySecurityBytecodeHighlight() {
  if (pendingSecurityBytecodeHighlight == null || !bytecodeListing) return;
  const target = pendingSecurityBytecodeHighlight;
  const lines = [...bytecodeListing.querySelectorAll('.bytecode-line')];
  if (!lines.length) return;
  pendingSecurityBytecodeHighlight = null;
  lines.forEach((el) => el.classList.remove('security-finding-highlight'));
  let hit = lines.find((el) => parseInt(el.getAttribute('data-offset'), 10) === target);
  if (!hit) {
    hit = lines.filter((el) => {
      const off = parseInt(el.getAttribute('data-offset'), 10);
      return !Number.isNaN(off) && off <= target;
    }).pop();
  }
  if (hit) {
    hit.classList.add('security-finding-highlight');
    scrollBytecodeLineIntoView(hit, { block: 'center', behavior: 'smooth' });
    const cfgNode = getCfgNodeForOffset(target);
    if (cfgNode != null) requestAnimationFrame(() => highlightCfgBlock(cfgNode, target));
  } else {
    setSecurityStatus(`Jumped to method — bytecode offset ${formatSecHexOffset(target)} not in listing`);
  }
}

function getCfgNodeForOffset(offset) {
  const ctx = getCodeViewContext();
  if (!ctx || codeViewMethodIdx == null) return null;
  const method = ctx.classes[codeViewClassIdx]?.methods?.[codeViewMethodIdx];
  const nodes = method?.cfgNodes || method?.cfg_nodes || [];
  const off = Number(offset) >>> 0;
  for (const n of nodes) {
    const start = n.startOffset ?? n.start_offset ?? 0;
    const endRaw = n.endOffset ?? n.end_offset ?? 0;
    const end = endRaw === 0xFFFFFFFF ? Infinity : endRaw;
    if (off >= start && off < end) return { id: n.id, startOffset: start, endOffset: endRaw };
  }
  return null;
}

function securityMtNavTarget(iss) {
  const parsed = parseSecurityCallable(iss.callable);
  const frames = Array.isArray(iss.trace) ? iss.trace : [];
  let sinkFrame = null;
  for (let i = frames.length - 1; i >= 0; i--) {
    if (frames[i]?.offset != null) {
      sinkFrame = frames[i];
      break;
    }
  }
  if (!sinkFrame && frames.length) sinkFrame = frames[frames.length - 1];
  return {
    className: sinkFrame?.class_name || parsed.className,
    methodName: sinkFrame?.method_name || parsed.methodName,
    offset: sinkFrame?.offset ?? null,
    dexFile: iss.dex_file || '',
  };
}

function isXmlSecurityFinding(className, methodName) {
  return methodName === '(xml)' || /\.xml$/i.test(String(className || ''));
}

function navigateToXmlSecurityFinding(className) {
  switchToCenterTab('manifest-tab');
  setSecurityStatus(`Manifest / XML finding — see ${className || 'Manifest'} tab`);
}

function readSecurityFindingNav(el) {
  const kind = el.getAttribute('data-kind') || '';
  const className = el.getAttribute('data-class') || '';
  const methodName = el.getAttribute('data-method') || '';
  const dexFile = el.getAttribute('data-dex') || '';
  const offsetRaw = el.getAttribute('data-offset');
  const offset = offsetRaw != null && offsetRaw !== '' ? parseInt(offsetRaw, 10) : null;
  const hint = el.getAttribute('data-hint') || '';
  return { kind, className, methodName, dexFile, offset, hint };
}

function renderScannerTag(scanner) {
  const labels = { vuln: 'Vuln', semgrep: 'Semgrep', mt: 'MT' };
  const label = labels[scanner] || scanner;
  return `<span class="security-scanner-tag scanner-${escapeAttr(scanner)}">${escapeHtml(label)}</span>`;
}

function renderVulnFindingCard(f, opts = {}) {
  const grouped = !!opts.groupedByClass;
  const findingId = opts.findingId || securityVulnFindingId(f);
  const verdict = getFindingVerdict(findingId);
  const methodBit = f.method_name || '?';
  const loc = grouped
    ? `#${methodBit}`
    : `${f.class_name || '?'}#${methodBit}`;
  const sinkOff = f.sink_offset != null ? Number(f.sink_offset) : null;
  const srcOff = f.source_offset != null ? Number(f.source_offset) : null;
  const sinkHex = sinkOff != null ? formatSecHexOffset(sinkOff) : '';
  const srcHex = srcOff != null ? formatSecHexOffset(srcOff) : '';
  const sinkDesc = f.sink_desc || '';
  const srcDesc = f.source_desc || '';
  const sinkReg = f.sink_reg != null ? `v${f.sink_reg}` : '';
  const srcReg = f.source_reg != null ? `v${f.source_reg}` : '';
  const dexHint = (!grouped && f.dex_file) ? `<span class="muted">${escapeHtml(f.dex_file)}</span>` : '';
  const cat = f.category || 'vuln';
  const catCls = securityCategoryClass(cat);
  const sev = vulnFindingSeverityClass(f);
  const title = f.title || formatCategoryLabel(cat);
  const message = f.message || '';
  const problem = f.problem || '';
  const recommendation = f.recommendation || '';
  const cwe = f.cwe || '';
  const frames = Array.isArray(f.trace) ? f.trace : [];
  const evidence = Array.isArray(f.evidence_offsets) ? f.evidence_offsets : [];
  const hint = problem || message || sinkDesc || srcDesc || '';
  const tip = [title, problem || message, `${f.class_name || '?'}#${methodBit}`, sinkHex && `sink ${sinkHex}`, sinkDesc, cwe].filter(Boolean).join(' · ');
  const detailLines = [];
  if (problem) {
    detailLines.push(`<div class="security-finding-msg"><span class="security-finding-k">Problem</span> ${escapeHtml(problem)}</div>`);
  } else if (message) {
    detailLines.push(`<div class="security-finding-msg">${escapeHtml(message)}</div>`);
  }
  if (sinkOff != null || sinkDesc) {
    detailLines.push(`<div class="security-finding-detail"><span class="security-finding-k">Sink</span> ${sinkHex ? `<code>${escapeHtml(sinkHex)}</code> ` : ''}${sinkReg ? `<code>${escapeHtml(sinkReg)}</code> ` : ''}${escapeHtml(sinkDesc || '(no description)')}</div>`);
  }
  if (srcOff != null || srcDesc) {
    detailLines.push(`<div class="security-finding-detail"><span class="security-finding-k">Source</span> ${srcHex ? `<code>${escapeHtml(srcHex)}</code> ` : ''}${srcReg ? `<code>${escapeHtml(srcReg)}</code> ` : ''}${escapeHtml(srcDesc || '(tainted flow origin)')}</div>`);
  }
  if (frames.length) {
    const traceId = `vuln-trace-${securityCategoryClass(cat)}-${sinkOff ?? 0}-${Math.abs(hashStr(`${f.class_name}|${f.method_name}|${srcOff}|${sinkOff}|${frames.length}`))}`;
    detailLines.push(
      `<button type="button" class="security-trace-toggle" data-trace-toggle="${traceId}">Show execution path (${frames.length})</button>` +
      `<ol class="security-trace" id="${traceId}" hidden>${frames.map((t) => {
        const off = t.offset != null ? ` @ ${formatSecHexOffset(t.offset)}` : '';
        const reg = t.reg != null ? ` v${t.reg}` : '';
        return `<li data-offset="${t.offset != null ? t.offset : ''}"><strong>${escapeHtml(t.kind || 'step')}</strong><code>${escapeHtml(off)}${escapeHtml(reg)}</code> ${escapeHtml(t.description || '')}</li>`;
      }).join('')}</ol>`
    );
  }
  if (evidence.length > 1) {
    detailLines.push(`<div class="security-finding-detail muted"><span class="security-finding-k">Evidence</span> ${evidence.map((o) => `<code>${escapeHtml(formatSecHexOffset(o))}</code>`).join(' ')}</div>`);
  }
  if (recommendation) {
    detailLines.push(`<div class="security-finding-detail"><span class="security-finding-k">Fix</span> ${escapeHtml(recommendation)}</div>`);
  }
  if (cwe) {
    detailLines.push(`<div class="security-finding-detail"><span class="security-finding-k">CWE</span> ${escapeHtml(cwe)}</div>`);
  }
  if (message && problem && message !== problem) {
    detailLines.push(`<div class="security-finding-detail muted"><span class="security-finding-k">Details</span> ${escapeHtml(message)}</div>`);
  }
  const verdictCls = verdict ? ` verdict-${verdict}` : '';
  return `<div class="security-finding ${sev}${verdictCls}" role="button" tabindex="0" data-kind="vuln" data-finding-id="${escapeAttr(findingId)}" data-class="${escapeAttr(f.class_name || '')}" data-method="${escapeAttr(f.method_name || '')}" data-dex="${escapeAttr(f.dex_file || '')}"${sinkOff != null ? ` data-offset="${sinkOff}"` : ''} data-hint="${escapeAttr(hint)}" title="${escapeAttr(tip)}">
    <div class="security-finding-top">${renderScannerTag('vuln')}<span class="security-badge ${sev}">${escapeHtml(securitySeverityLabel(sev))}</span><span class="security-badge cat-${escapeAttr(catCls)}">${escapeHtml(title)}</span>${cwe ? `<span class="security-badge muted">${escapeHtml(cwe)}</span>` : ''}${dexHint}<span class="security-finding-loc">${escapeHtml(loc)}${sinkHex ? ` @ ${escapeHtml(sinkHex)}` : ''}</span>${renderFindingVerdictControls(findingId)}</div>
    ${detailLines.join('')}
  </div>`;
}

function hashStr(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return h;
}

function renderMtFindingCard(iss, idx, opts = {}) {
  const grouped = !!opts.groupedByClass;
  const findingId = opts.findingId || securityMtFindingId(iss, idx);
  const verdict = getFindingVerdict(findingId);
  const nav = securityMtNavTarget(iss);
  const loc = grouped
    ? (nav.methodName ? `#${nav.methodName}` : (iss.callable || 'unknown'))
    : (nav.className && nav.methodName ? `${nav.className}#${nav.methodName}` : (iss.callable || 'unknown'));
  const sinkHex = nav.offset != null ? formatSecHexOffset(nav.offset) : '';
  const frames = Array.isArray(iss.trace) ? iss.trace : [];
  const traceId = `mt-trace-${idx}`;
  const traceHtml = frames.length
    ? `<button type="button" class="security-trace-toggle" data-trace-toggle="${traceId}">Show trace (${frames.length})</button>
       <ol class="security-trace" id="${traceId}" hidden>${frames.map((t) => {
         const off = t.offset != null ? ` @ ${formatSecHexOffset(t.offset)}` : '';
         return `<li><strong>${escapeHtml(t.class_name || '')}#${escapeHtml(t.method_name || '')}</strong><code>${escapeHtml(off)}</code> <span class="muted">[${escapeHtml(t.kind || '')}]</span> ${escapeHtml(t.description || '')}</li>`;
       }).join('')}</ol>`
    : '';
  const dexHint = (!grouped && iss.dex_file) ? `<span class="muted">${escapeHtml(iss.dex_file)}</span>` : '';
  const title = [iss.rule_name, nav.className && nav.methodName ? `${nav.className}#${nav.methodName}` : iss.callable, sinkHex, iss.description].filter(Boolean).join(' · ');
  const verdictCls = verdict ? ` verdict-${verdict}` : '';
  return `<div class="security-finding sev-med${verdictCls}" role="button" tabindex="0" data-kind="mt" data-finding-id="${escapeAttr(findingId)}" data-class="${escapeAttr(nav.className)}" data-method="${escapeAttr(nav.methodName)}" data-dex="${escapeAttr(nav.dexFile)}"${nav.offset != null ? ` data-offset="${nav.offset}"` : ''} data-hint="${escapeAttr(iss.callable || '')}" title="${escapeAttr(title)}">
    <div class="security-finding-top">${renderScannerTag('mt')}<span class="security-badge mt">MT ${escapeHtml(String(iss.rule_code ?? ''))}</span>${dexHint}<span class="security-finding-loc">${escapeHtml(loc)}${sinkHex ? ` @ ${escapeHtml(sinkHex)}` : ''}</span>${renderFindingVerdictControls(findingId)}</div>
    <div class="security-finding-detail"><span class="security-finding-k">Rule</span> ${escapeHtml(iss.rule_name || 'rule')}</div>
    <div class="security-finding-detail"><span class="security-finding-k">Flow</span> ${escapeHtml(iss.source_kind || '?')} → ${escapeHtml(iss.sink_kind || '?')}</div>
    ${iss.description ? `<div class="security-finding-detail muted">${escapeHtml(iss.description)}</div>` : ''}
    ${traceHtml}
  </div>`;
}

function renderSemgrepFindingCard(f, opts = {}) {
  const grouped = !!opts.groupedByClass;
  const findingId = opts.findingId || securitySemgrepFindingId(f);
  const verdict = getFindingVerdict(findingId);
  const isXml = isXmlSecurityFinding(f.class_name, f.method_name);
  const loc = isXml
    ? (f.class_name || 'AndroidManifest.xml')
    : (grouped ? `#${f.method_name || '?'}` : `${f.class_name || '?'}#${f.method_name || '?'}`);
  const sinkOff = f.sink_offset != null ? Number(f.sink_offset) : null;
  const sinkHex = sinkOff != null ? formatSecHexOffset(sinkOff) : '';
  const dexHint = (!grouped && f.dex_file) ? `<span class="muted">${escapeHtml(f.dex_file)}</span>` : '';
  const sev = String(f.severity || '').toUpperCase();
  const sevCls = sev === 'ERROR' ? 'sev-high' : (sev === 'WARNING' ? 'sev-med' : 'sev-info');
  const hint = f.sink_desc || f.message || '';
  const title = [f.rule_id, `${f.class_name || '?'}#${f.method_name || '?'}`, sinkHex, f.message, f.sink_desc].filter(Boolean).join(' · ');
  const meta = [
    f.match_kind ? `match: ${f.match_kind}` : '',
    f.vuln_class ? `class: ${f.vuln_class}` : '',
    f.chain_tag ? `chain: ${f.chain_tag}` : '',
  ].filter(Boolean);
  const detailLines = [
    `<div class="security-finding-detail">${escapeHtml(f.message || f.sink_desc || '(no message)')}</div>`,
  ];
  if (f.sink_desc && f.message && f.sink_desc !== f.message) {
    detailLines.push(`<div class="security-finding-detail muted"><span class="security-finding-k">Match</span> ${escapeHtml(f.sink_desc)}</div>`);
  }
  if (meta.length) {
    detailLines.push(`<div class="security-finding-detail muted">${escapeHtml(meta.join(' · '))}</div>`);
  }
  const navAttrs = isXml
    ? `data-kind="semgrep-xml" data-class="${escapeAttr(f.class_name || f.dex_file || '')}" data-method="(xml)"`
    : `data-kind="semgrep" data-class="${escapeAttr(f.class_name || '')}" data-method="${escapeAttr(f.method_name || '')}" data-dex="${escapeAttr(f.dex_file || '')}"${sinkOff != null ? ` data-offset="${sinkOff}"` : ''} data-hint="${escapeAttr(hint)}"`;
  const verdictCls = verdict ? ` verdict-${verdict}` : '';
  return `<div class="security-finding ${sevCls}${verdictCls}" role="button" tabindex="0" data-finding-id="${escapeAttr(findingId)}" ${navAttrs} title="${escapeAttr(title)}">
    <div class="security-finding-top">${renderScannerTag('semgrep')}<span class="security-badge semgrep">${escapeHtml(sev || 'INFO')}</span><span class="security-badge cat-semgrep">${escapeHtml(f.rule_id || 'rule')}</span>${dexHint}<span class="security-finding-loc">${escapeHtml(loc)}${sinkHex ? ` @ ${escapeHtml(sinkHex)}` : ''}</span>${renderFindingVerdictControls(findingId)}</div>
    ${detailLines.join('')}
  </div>`;
}

function renderSecurityPanel() {
  renderSecurityOverview();
  renderSecuritySourceTabs();
  renderSecuritySevTabs();
  renderSecurityVerdictTabs();
  renderSecurityChips();
  renderSecurityFindingsList();
  updateStatusBar();
}

async function navigateToSecurityFinding(className, methodName, dexFile, navOpts = {}) {
  const offset = navOpts.offset != null ? Number(navOpts.offset) : null;
  const hint = navOpts.hint || '';

  if (isXmlSecurityFinding(className, methodName)) {
    navigateToXmlSecurityFinding(className);
    return;
  }
  if (!className) {
    setSecurityStatus('Finding has no class — cannot jump to source');
    return;
  }

  clearSecurityBytecodeHighlight();
  if (offset != null && !Number.isNaN(offset)) queueSecurityBytecodeHighlight(offset);
  switchToCenterTab('bytecode-tab');

  if (currentType === 'apk') {
    await ensureApkClassIndex();
    let file = dexFile;
    let classIdx = null;
    const hit = lookupApkClass(className, apkClassToDex);
    if (hit) {
      file = hit.file;
      classIdx = hit.classIdx;
    }
    if (!file) {
      setSecurityStatus('Class not found in APK index: ' + className);
      return;
    }
    await showApkFile(file);
    if (apkLeftMode !== 'classes') {
      apkLeftMode = 'classes';
      updateApkLeftModeButtons();
    }
    if (classIdx == null) {
      const classes = apkExtractedFile?.data?.classes || [];
      classIdx = findClassIndexInDex(classes, className);
    }
    if (classIdx < 0) {
      setSecurityStatus('Class not in DEX: ' + className);
      return;
    }
    const methods = apkExtractedFile?.data?.classes?.[classIdx]?.methods || [];
    let methodIdx = methodName ? findMethodIndexInClass(methods, methodName, hint) : -1;
    if (methodIdx < 0) methodIdx = null;
    // Use selectCodeViewMethod so package/toolbar stay aligned with the jump target.
    selectCodeViewMethod(classIdx, methodIdx, { expandCfg: methodIdx != null });
    renderApkClassTree();
    if (methodIdx == null && methodName) {
      setSecurityStatus(`Opened class ${className} — method "${methodName}" not found`);
    } else if (methodIdx == null) {
      setSecurityStatus(`Opened class ${className}`);
    } else if (offset != null) {
      setSecurityStatus(`Jumped to ${className}#${methodName || '?'} @ ${formatSecHexOffset(offset)}`);
    } else {
      setSecurityStatus(`Jumped to ${className}#${methodName || '?'}`);
    }
    return;
  }
  if (currentType === 'dex') {
    if (loadedDexFiles.length > 1 && dexFile) {
      const want = String(dexFile).toLowerCase();
      let idx = loadedDexFiles.findIndex((d) => (d.name || '').toLowerCase() === want);
      if (idx < 0) {
        idx = loadedDexFiles.findIndex((d) => {
          const n = (d.name || '').toLowerCase();
          return n.endsWith('/' + want) || n.endsWith('\\' + want) || n.includes(want);
        });
      }
      if (idx >= 0 && idx !== activeDexIndex) switchActiveDex(idx);
    }
    if (!Array.isArray(currentData?.classes)) {
      setSecurityStatus('No DEX classes loaded');
      return;
    }
    let classIdx = findClassIndexInDex(currentData.classes, className);
    if (classIdx < 0 && loadedDexFiles.length > 1) {
      for (let i = 0; i < loadedDexFiles.length; i++) {
        if (i === activeDexIndex) continue;
        const classes = loadedDexFiles[i]?.data?.classes;
        const found = Array.isArray(classes) ? findClassIndexInDex(classes, className) : -1;
        if (found >= 0) {
          switchActiveDex(i);
          classIdx = found;
          break;
        }
      }
    }
    if (classIdx < 0) {
      setSecurityStatus('Class not found: ' + className);
      return;
    }
    const methods = currentData.classes[classIdx]?.methods || [];
    let methodIdx = methodName ? findMethodIndexInClass(methods, methodName, hint) : -1;
    if (methodIdx < 0) methodIdx = null;
    selectCodeViewMethod(classIdx, methodIdx, { expandCfg: methodIdx != null });
    if (methodIdx == null && methodName) {
      setSecurityStatus(`Opened class ${className} — method "${methodName}" not found`);
    } else if (methodIdx == null) {
      setSecurityStatus(`Opened class ${className}`);
    } else if (offset != null) {
      setSecurityStatus(`Jumped to ${className}#${methodName || '?'} @ ${formatSecHexOffset(offset)}`);
    } else {
      setSecurityStatus(`Jumped to ${className}#${methodName || '?'}`);
    }
  }
}

/** Normalize WASM return values: plain object, JSON string, or Map → plain object. */
function normalizeWasmResult(raw) {
  if (raw == null) return null;
  if (typeof raw === 'string') {
    try { return JSON.parse(raw); } catch (_) { return { ok: false, error: raw }; }
  }
  if (typeof Map !== 'undefined' && raw instanceof Map) {
    const o = {};
    for (const [k, v] of raw.entries()) {
      o[k] = (typeof Map !== 'undefined' && v instanceof Map) ? normalizeWasmResult(v)
        : (Array.isArray(v) ? v.map((x) => (x && typeof x === 'object' ? normalizeWasmResult(x) : x)) : v);
    }
    return o;
  }
  return raw;
}

async function runSecurityVulnScan(opts = {}) {
  const embedded = !!opts.embedded;
  if (!embedded && securityScanBusy) return;
  const targets = await collectDexScanTargets();
  if (!targets.length) {
    if (!embedded) setSecurityStatus('No DEX loaded — open a DEX or APK first');
    return false;
  }
  const scanT0 = performance.now();
  if (!embedded) {
    beginSecurityScan(`Vulnerability scan — 0/${targets.length}`, {
      phases: { vuln: 'active', semgrep: 'skipped', mt: 'skipped' },
    });
    securityVulnFindings = [];
    securityFromCache = false;
  } else {
    setSecurityScanPhases({ vuln: 'active' });
  }
  const phaseBase = opts.phaseBase ?? 0;
  const phaseSpan = opts.phaseSpan ?? 100;
  const totalBytes = targets.reduce((n, t) => n + (t.bytes?.length || 0), 0);
  try {
    for (let i = 0; i < targets.length; i++) {
      throwIfSecurityScanAborted();
      const t = targets[i];
      const fileSize = t.bytes?.length || 0;
      const label = embedded
        ? `Security scan — Vuln ${i + 1}/${targets.length}: ${t.name}`
        : `Vulns ${i + 1}/${targets.length}: ${t.name}`;
      const localPct = (i / targets.length) * phaseSpan;
      const detail = `Running vulnerability detectors on ${t.name}`;
      const extra = `DEX ${i + 1}/${targets.length} · ${formatFileSize(fileSize)} · ${formatFileSize(totalBytes)} total`;
      const stats = [
        ...securityFindingsSoFarChips(),
        formatScanElapsed(performance.now() - scanT0),
        'phase: Vuln',
      ];
      if (embedded) {
        updateSecurityProgressWeighted(phaseBase + localPct, 100, label, detail, stats, {
          extra,
          phases: { vuln: 'active' },
        });
      } else {
        updateSecurityProgress(i, targets.length, label, detail, stats, { extra });
      }
      setSecurityStatus(label + '…');
      await yieldToUi();
      throwIfSecurityScanAborted();

      const fileT0 = performance.now();
      showSecurityProgress(label, {
        indeterminate: true,
        detail: `Worker: detectors on ${t.name} (${formatFileSize(fileSize)})`,
        extra,
        stats,
        phases: { vuln: 'active' },
      });
      await yieldToUi();

      let heartbeat = setInterval(() => {
        showSecurityProgress(label, {
          indeterminate: true,
          detail: `Still scanning ${t.name}… ${formatScanElapsed(performance.now() - fileT0)}`,
          extra,
          stats: [
            ...securityFindingsSoFarChips(),
            formatScanElapsed(performance.now() - scanT0),
            'phase: Vuln',
          ],
          phases: { vuln: 'active' },
        });
      }, 1000);
      const baseline = securityVulnFindings.length;
      let lastPartialApply = 0;
      const applyVulnPartial = (partial, force = false) => {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        if (!force && now - lastPartialApply < 500) return;
        lastPartialApply = now;
        const findings = filterLibraryVulnFindings(Array.isArray(partial) ? partial : []);
        securityVulnFindings = securityVulnFindings.slice(0, baseline);
        for (const f of findings) {
          securityVulnFindings.push({ ...f, dex_file: targets.length > 1 ? t.name : (f.dex_file || t.name) });
        }
        refreshSecurityFindingsLive();
      };
      let raw;
      try {
        raw = await scanVulnsInWorker(t.bytes, (prog) => {
          if (prog && prog.findings) applyVulnPartial(prog.findings, false);
        });
      } catch (scanErr) {
        clearInterval(heartbeat);
        if (isSecurityWorkerTimeoutError(scanErr) || isSecurityScanAbortError(scanErr)) {
          if (isSecurityScanAbortError(scanErr)) throw scanErr;
          warn('[vuln] timed out on', t.name, '— keeping', securityVulnFindings.length - baseline, 'partial finding(s)');
          setSecurityStatus(`Vuln: ${t.name} timed out — kept partial results, continuing…`);
          await yieldToUi();
          continue;
        }
        throw scanErr;
      } finally {
        clearInterval(heartbeat);
      }
      throwIfSecurityScanAborted();
      const result = normalizeWasmResult(raw);
      if (!result?.ok) throw new Error(result?.error || 'scan_vulns failed');
      const findings = filterLibraryVulnFindings(Array.isArray(result.findings) ? result.findings : []);
      applyVulnPartial(findings, true);
      const doneLocal = ((i + 1) / targets.length) * phaseSpan;
      const doneDetail = `+${findings.length} from ${t.name} (${securityVulnFindings.length} total) · ${formatScanElapsed(performance.now() - fileT0)}`;
      if (embedded) {
        updateSecurityProgressWeighted(phaseBase + doneLocal, 100,
          `Security scan — Vuln done ${i + 1}/${targets.length}`,
          doneDetail,
          [...securityFindingsSoFarChips(), formatScanElapsed(performance.now() - scanT0)],
          { extra, phases: { vuln: 'active' } }
        );
      } else {
        updateSecurityProgress(i + 1, targets.length, `Vulns done ${i + 1}/${targets.length}: ${t.name}`, doneDetail,
          [...securityFindingsSoFarChips(), formatScanElapsed(performance.now() - scanT0)],
          { extra });
      }
    }
    securityScansRun.vuln = true;
    setSecurityScanPhases({ vuln: 'done' });
    refreshSecurityFindingsLive();
    if (!embedded) {
      const cached = saveSecurityCache();
      setSecurityStatus(
        `Vulnerability scan done — ${securityVulnFindings.length} finding(s) across ${targets.length} DEX · ${formatScanElapsed(performance.now() - scanT0)}` +
        (cached ? ' · saved to localStorage' : '')
      );
      renderSecurityPanel();
    }
    return true;
  } catch (e) {
    if (isSecurityScanAbortError(e)) {
      setSecurityScanPhases({ vuln: 'error' });
      if (!embedded) {
        const total = securityVulnFindings.length;
        saveSecurityCache();
        showSecurityProgress('Scan stopped', {
          indeterminate: false,
          detail: `Stopped during Vuln · kept ${total} finding(s)`,
          extra: `Elapsed ${formatScanElapsed(performance.now() - scanT0)}`,
          stats: securityFindingsSoFarChips().concat([formatScanElapsed(performance.now() - scanT0)]),
          stoppable: false,
        });
        setSecurityStatus(`Scan stopped — ${total} vuln finding(s) kept`);
        renderSecurityPanel();
      }
      throw e;
    }
    if (!embedded) {
      warn('scan_vulns', e);
      setSecurityStatus('Scan failed: ' + (e?.message || e));
    }
    setSecurityScanPhases({ vuln: 'error' });
    throw e;
  } finally {
    if (!embedded) endSecurityScan({ aborted: securityScanAbortRequested, keepProgressMs: securityScanAbortRequested ? 0 : 1600 });
  }
}

async function runSecurityTaintSolve(opts = {}) {
  const embedded = !!opts.embedded;
  if (!embedded && securityScanBusy) return;
  const targets = await collectDexScanTargets();
  if (!targets.length) {
    if (!embedded) setSecurityStatus('No DEX loaded — open a DEX or APK first');
    return false;
  }
  const scanT0 = performance.now();
  if (!embedded) {
    beginSecurityScan(`MT taint solve — 0/${targets.length}`, {
      phases: { vuln: 'skipped', semgrep: 'skipped', mt: 'active' },
    });
  } else {
    setSecurityScanPhases({ mt: 'active' });
  }
  const allIssues = [];
  let methods = 0, edges = 0, iterations = 0;
  if (!embedded) securityFromCache = false;
  const phaseBase = opts.phaseBase ?? 0;
  const phaseSpan = opts.phaseSpan ?? 100;
  const totalBytes = targets.reduce((n, t) => n + (t.bytes?.length || 0), 0);
  try {
    for (let i = 0; i < targets.length; i++) {
      throwIfSecurityScanAborted();
      const t = targets[i];
      const fileSize = t.bytes?.length || 0;
      // MT is the heaviest phase — only run on the first (primary) DEX for large APKs.
      if (i > 0 && fileSize > 4 * 1024 * 1024) {
        warn('[mt] skip large secondary DEX', t.name, formatFileSize(fileSize));
        continue;
      }
      if (i > 0 && targets.length > 2) {
        // Prefer a single MT pass on classes.dex when scanning many DEXes.
        debug('[mt] limited to primary DEX for multidex APK');
        break;
      }
      const label = embedded
        ? `Security scan — MT taint ${i + 1}/${targets.length}: ${t.name}`
        : `MT taint ${i + 1}/${targets.length}: ${t.name}`;
      const localPct = (i / targets.length) * phaseSpan;
      const detail = `Global taint analysis on ${t.name}`;
      const extra = `DEX ${i + 1}/${targets.length} · ${formatFileSize(fileSize)} · ${formatFileSize(totalBytes)} total`;
      const stats = [
        ...securityFindingsSoFarChips(),
        `${allIssues.length} MT so far`,
        formatScanElapsed(performance.now() - scanT0),
        'phase: MT',
      ];
      if (embedded) {
        updateSecurityProgressWeighted(phaseBase + localPct, 100, label, detail, stats, {
          extra,
          phases: { mt: 'active' },
        });
      } else {
        updateSecurityProgress(i, targets.length, label, detail, stats, { extra });
      }
      setSecurityStatus(label + '…');
      await yieldToUi();
      throwIfSecurityScanAborted();

      const fileT0 = performance.now();
      showSecurityProgress(label, {
        indeterminate: true,
        detail: `Worker: MT taint on ${t.name} (${formatFileSize(fileSize)})`,
        extra,
        stats,
        phases: { mt: 'active' },
      });
      await yieldToUi();

      let heartbeat = setInterval(() => {
        showSecurityProgress(label, {
          indeterminate: true,
          detail: `Still solving ${t.name}… ${formatScanElapsed(performance.now() - fileT0)} · ${methods} methods analyzed so far`,
          extra,
          stats: [
            ...securityFindingsSoFarChips(),
            formatScanElapsed(performance.now() - scanT0),
            'phase: MT',
          ],
          phases: { mt: 'active' },
        });
      }, 1000);
      let raw;
      try {
        raw = await taintSolveInWorker(t.bytes);
      } catch (scanErr) {
        clearInterval(heartbeat);
        if (isSecurityScanAbortError(scanErr)) throw scanErr;
        if (isSecurityWorkerTimeoutError(scanErr)) {
          warn('[mt] timed out on', t.name, '— skipping remaining MT for this DEX');
          setSecurityStatus(`MT: ${t.name} timed out — continuing…`);
          await yieldToUi();
          continue;
        }
        throw scanErr;
      } finally {
        clearInterval(heartbeat);
      }
      throwIfSecurityScanAborted();
      const result = normalizeWasmResult(raw);
      if (!result?.ok) throw new Error(result?.error || 'taint_solve failed');
      const report = result.report || {};
      const issues = Array.isArray(report.issues) ? report.issues : [];
      for (const iss of issues) {
        allIssues.push({ ...iss, dex_file: targets.length > 1 ? t.name : t.name });
      }
      methods += report.stats?.methods_analyzed || 0;
      edges += report.stats?.call_edges || 0;
      iterations = Math.max(iterations, report.stats?.iterations || 0);
      securityMtReport = {
        tool: 'dex-decompiler-mt',
        version: '0.1',
        issues: allIssues.slice(),
        stats: {
          methods_analyzed: methods,
          call_edges: edges,
          issues: allIssues.length,
          iterations,
        },
      };
      refreshSecurityFindingsLive();
      const doneLocal = ((i + 1) / targets.length) * phaseSpan;
      const doneDetail = `+${issues.length} issues · ${methods} methods · ${edges} edges · ${formatScanElapsed(performance.now() - fileT0)}`;
      if (embedded) {
        updateSecurityProgressWeighted(phaseBase + doneLocal, 100,
          `Security scan — MT done ${i + 1}/${targets.length}`,
          doneDetail,
          [...securityFindingsSoFarChips(), `${methods} methods`, formatScanElapsed(performance.now() - scanT0)],
          { extra, phases: { mt: 'active' } }
        );
      } else {
        updateSecurityProgress(i + 1, targets.length, `MT done ${i + 1}/${targets.length}: ${t.name}`, doneDetail,
          [...securityFindingsSoFarChips(), `${methods} methods`, formatScanElapsed(performance.now() - scanT0)],
          { extra });
      }
    }
    securityMtReport = {
      tool: 'dex-decompiler-mt',
      version: '0.1',
      issues: allIssues,
      stats: {
        methods_analyzed: methods,
        call_edges: edges,
        issues: allIssues.length,
        iterations,
      },
    };
    securityScansRun.mt = true;
    setSecurityScanPhases({ mt: 'done' });
    refreshSecurityFindingsLive();
    if (!embedded) {
      const cached = saveSecurityCache();
      setSecurityStatus(
        `MT solve done — ${allIssues.length} issue(s) across ${targets.length} DEX · ${formatScanElapsed(performance.now() - scanT0)}` +
        (cached ? ' · saved to localStorage' : '')
      );
      renderSecurityPanel();
    }
    return true;
  } catch (e) {
    if (isSecurityScanAbortError(e)) {
      if (allIssues.length) {
        securityMtReport = {
          tool: 'dex-decompiler-mt',
          version: '0.1',
          issues: allIssues,
          stats: {
            methods_analyzed: methods,
            call_edges: edges,
            issues: allIssues.length,
            iterations,
            partial: true,
          },
        };
      }
      setSecurityScanPhases({ mt: 'error' });
      if (!embedded) {
        saveSecurityCache();
        showSecurityProgress('Scan stopped', {
          indeterminate: false,
          detail: `Stopped during MT · kept ${allIssues.length} issue(s)`,
          extra: `Elapsed ${formatScanElapsed(performance.now() - scanT0)}`,
          stats: securityFindingsSoFarChips().concat([formatScanElapsed(performance.now() - scanT0)]),
          stoppable: false,
        });
        setSecurityStatus(`Scan stopped — ${allIssues.length} MT issue(s) kept`);
        renderSecurityPanel();
      }
      throw e;
    }
    if (!embedded) {
      warn('taint_solve', e);
      setSecurityStatus('MT solve failed: ' + (e?.message || e));
    }
    setSecurityScanPhases({ mt: 'error' });
    throw e;
  } finally {
    if (!embedded) endSecurityScan({ aborted: securityScanAbortRequested, keepProgressMs: securityScanAbortRequested ? 0 : 1600 });
  }
}

function preloadSemgrepBuiltinRules() {
  if (securitySemgrepBuiltinRuleInfos.length) return;
  try {
    const raw = get_semgrep_builtin_rules();
    const result = normalizeWasmResult(raw);
    if (result?.ok) {
      securitySemgrepBuiltinRuleInfos = Array.isArray(result.rules) ? result.rules : [];
    }
  } catch (e) {
    warn('[semgrep] builtin rules preload failed', e);
  }
}

/** Fast rule-count estimate from YAML (no WASM) — used when summaries aren't cached yet. */
function estimateSemgrepRuleCount(yaml) {
  if (!yaml || typeof yaml !== 'string') return 0;
  const matches = yaml.match(/^\s*-\s+id:/gm);
  return matches ? matches.length : 0;
}

function semgrepRuleLangCounts(rules) {
  let javaRules = 0;
  let xmlRules = 0;
  let nativeRules = 0;
  for (const r of rules) {
    const langs = (r.languages || []).map((l) => String(l).toLowerCase());
    if (langs.some((l) => l === 'xml' || l.includes('xml'))) xmlRules += 1;
    else javaRules += 1;
    if (r.hasNative || r.has_native) nativeRules += 1;
  }
  return { javaRules, xmlRules, nativeRules };
}

/** Progress metadata for Semgrep — never parses YAML in WASM (scan does that once). */
function buildSemgrepScanContext(rulesArg) {
  const source = rulesArg ? 'Custom YAML' : 'All (built-in)';
  let rules = [];
  if (rulesArg) {
    if (securitySemgrepRulesYaml === rulesArg && securitySemgrepRuleInfos.length) {
      rules = securitySemgrepRuleInfos;
    }
  } else if (securitySemgrepBuiltinRuleInfos.length) {
    rules = securitySemgrepBuiltinRuleInfos;
  }
  let ruleCount = rules.length;
  let estimated = false;
  if (!ruleCount) {
    if (rulesArg) {
      ruleCount = estimateSemgrepRuleCount(rulesArg);
      estimated = ruleCount > 0;
    } else {
      ruleCount = securitySemgrepBuiltinRuleInfos.length;
    }
  }
  const { javaRules, xmlRules, nativeRules } = rules.length
    ? semgrepRuleLangCounts(rules)
    : { javaRules: 0, xmlRules: 0, nativeRules: 0 };
  const sampleRuleIds = rules.slice(0, 8).map((r) => r.id || r.rule_id).filter(Boolean);
  const severities = { ERROR: 0, WARNING: 0, INFO: 0, other: 0 };
  for (const r of rules) {
    const s = String(r.severity || '').toUpperCase();
    if (s === 'ERROR' || s === 'CRITICAL') severities.ERROR += 1;
    else if (s === 'WARNING' || s === 'HIGH' || s === 'MEDIUM') severities.WARNING += 1;
    else if (s === 'INFO' || s === 'LOW') severities.INFO += 1;
    else severities.other += 1;
  }
  return { source, rules, ruleCount, javaRules, xmlRules, nativeRules, estimated, sampleRuleIds, severities };
}

/** Top rule_id counts from a findings list (for progress detail). */
function summarizeSemgrepRuleHits(findings, limit = 3) {
  const counts = new Map();
  for (const f of findings || []) {
    const id = f.rule_id || f.id || '(rule)';
    counts.set(id, (counts.get(id) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([id, n]) => (n > 1 ? `${id}×${n}` : id));
}

function formatSemgrepThroughput(bytes, ms) {
  if (!bytes || ms < 50) return '';
  const bps = bytes / (ms / 1000);
  if (bps >= 1024 * 1024) return `${(bps / (1024 * 1024)).toFixed(1)} MB/s`;
  if (bps >= 1024) return `${Math.round(bps / 1024)} KB/s`;
  return `${Math.round(bps)} B/s`;
}

function estimateSemgrepEta(doneWeight, totalWeight, elapsedMs) {
  if (doneWeight <= 0 || elapsedMs < 400 || totalWeight <= doneWeight) return '';
  const rate = doneWeight / elapsedMs;
  const remainMs = (totalWeight - doneWeight) / rate;
  if (!Number.isFinite(remainMs) || remainMs < 500) return '';
  return `~${formatScanElapsed(remainMs)} left`;
}

/** Files completed vs remaining in the Semgrep queue. */
function semgrepQueueProgress(filesDone = 0, fileTotal = 0) {
  const total = Math.max(0, fileTotal | 0);
  if (!total) return { done: 0, current: 0, left: 0, total: 0 };
  const done = Math.max(0, Math.min(filesDone | 0, total));
  const left = Math.max(0, total - done);
  const current = left > 0 ? done + 1 : total;
  return { done, current, left, total };
}

/**
 * Global Semgrep work units: each file × applicable rules.
 * DEX files use Java/native rules; XML files use XML rules (fallback: all rules).
 */
function semgrepCheckProgress(ctx, {
  filesDone = 0,
  fileTotal = 0,
  dexFileCount = 0,
  xmlFileCount = 0,
  currentKind = '',
} = {}) {
  const ruleCount = Math.max(0, ctx?.ruleCount | 0);
  const javaRules = Math.max(0, (ctx?.javaRules | 0) || ruleCount);
  const xmlRules = Math.max(0, ctx?.xmlRules | 0);
  const dexN = Math.max(0, dexFileCount | 0);
  const xmlN = Math.max(0, xmlFileCount | 0);
  const totalFiles = Math.max(fileTotal | 0, dexN + xmlN);
  let totalChecks = 0;
  if (dexN || xmlN) {
    totalChecks = dexN * Math.max(javaRules, 1) + xmlN * Math.max(xmlRules || ruleCount, 1);
  } else {
    totalChecks = totalFiles * Math.max(ruleCount, 1);
  }
  const q = semgrepQueueProgress(filesDone, totalFiles || fileTotal);
  let doneChecks = 0;
  const completed = q.done;
  if (dexN || xmlN) {
    const dexDone = Math.min(completed, dexN);
    const xmlDone = Math.max(0, completed - dexN);
    doneChecks = dexDone * Math.max(javaRules, 1) + xmlDone * Math.max(xmlRules || ruleCount, 1);
  } else {
    doneChecks = completed * Math.max(ruleCount, 1);
  }
  const leftChecks = Math.max(0, totalChecks - doneChecks);
  const currentRules = currentKind === 'XML'
    ? Math.max(xmlRules || ruleCount, 1)
    : Math.max(javaRules, 1);
  return {
    done: doneChecks,
    left: leftChecks,
    total: totalChecks,
    currentRules,
    ruleCount,
    files: q,
  };
}

function formatSemgrepChecksChip(checks) {
  if (!checks?.total) return '';
  if (checks.left <= 0) {
    return `<strong>${checks.total}/${checks.total}</strong> checks`;
  }
  return `<strong>${checks.done}/${checks.total}</strong> checks · <strong>${checks.left}</strong> left`;
}

function formatSemgrepQueueChip(filesDone, fileTotal) {
  const q = semgrepQueueProgress(filesDone, fileTotal);
  if (!q.total) return '';
  if (q.left <= 0) return `<strong>${q.total}/${q.total}</strong> files`;
  return `<strong>${q.done}/${q.total}</strong> files · <strong>${q.left}</strong> left`;
}

function formatSemgrepQueueExtra(filesDone, fileTotal, remainingNames = [], checks = null) {
  const q = semgrepQueueProgress(filesDone, fileTotal);
  if (!q.total && !checks?.total) return '';
  const parts = [];
  if (checks?.total) {
    parts.push(
      checks.left <= 0
        ? `Checks ${checks.total}/${checks.total}`
        : `Checks ${checks.done}/${checks.total} · ${checks.left} left`
    );
  }
  if (q.total) {
    parts.push(
      q.left <= 0
        ? `files ${q.total}/${q.total}`
        : `files ${q.done}/${q.total} · ${q.left} left (now ${q.current}/${q.total})`
    );
  }
  if (checks?.ruleCount) {
    parts.push(`${checks.ruleCount} rules`);
  }
  let head = parts.join(' · ');
  if (!remainingNames.length || q.left <= 0) return head;
  const shown = remainingNames.slice(0, 4).map((n) => (n.length > 22 ? `${n.slice(0, 20)}…` : n));
  const more = remainingNames.length > shown.length ? ` +${remainingNames.length - shown.length} more` : '';
  return `${head} · still: ${shown.join(', ')}${more}`;
}

function semgrepProgressStats(ctx, {
  findings = 0,
  elapsedMs = 0,
  payloadBytes = 0,
  phase = '',
  filesDone = 0,
  fileTotal = 0,
  doneWeight = 0,
  totalWeight = 0,
  newFindings = null,
  targetName = '',
  dexFileCount = 0,
  xmlFileCount = 0,
  currentKind = '',
} = {}) {
  const chips = [];
  const checks = semgrepCheckProgress(ctx, {
    filesDone,
    fileTotal,
    dexFileCount,
    xmlFileCount,
    currentKind,
  });
  const checksChip = formatSemgrepChecksChip(checks);
  if (checksChip) chips.push(checksChip);
  const queueChip = formatSemgrepQueueChip(filesDone, fileTotal);
  if (queueChip) chips.push(queueChip);
  if (ctx?.ruleCount) {
    chips.push(`<strong>${ctx.ruleCount}${ctx.estimated ? '+' : ''}</strong> rules`);
    if (ctx.javaRules || ctx.xmlRules) {
      chips.push(`${ctx.javaRules} Java · ${ctx.xmlRules} XML`);
    }
    if (ctx.nativeRules) chips.push(`${ctx.nativeRules} native`);
  }
  if (ctx?.source) chips.push(escapeHtml(ctx.source));
  if (fileTotal > 0) {
    const q = semgrepQueueProgress(filesDone, fileTotal);
    chips.push(`file ${q.current}/${q.total}`);
  }
  if (targetName) chips.push(escapeHtml(targetName.length > 28 ? targetName.slice(0, 26) + '…' : targetName));
  if (phase) chips.push(escapeHtml(phase));
  if (payloadBytes > 0) chips.push(formatFileSize(payloadBytes));
  if (totalWeight > 0) {
    const pct = Math.min(100, Math.round((doneWeight / totalWeight) * 100));
    chips.push(`${pct}%`);
  }
  const rate = formatSemgrepThroughput(doneWeight, elapsedMs);
  if (rate) chips.push(rate);
  const eta = estimateSemgrepEta(doneWeight, totalWeight, elapsedMs);
  if (eta) chips.push(eta);
  chips.push(`<strong>${findings}</strong> finding${findings === 1 ? '' : 's'}`);
  if (newFindings != null && newFindings > 0) chips.push(`+${newFindings} this file`);
  if (elapsedMs > 0) chips.push(formatScanElapsed(elapsedMs));
  return chips;
}

/** Rotating live detail — always lead with global checks (rules × files). */
function semgrepHeartbeatDetail({
  ctx,
  targetName,
  fileSize,
  fileElapsedMs,
  totalElapsedMs,
  findings,
  kind = 'DEX',
  tick = 0,
  filesDone = 0,
  fileTotal = 1,
  doneWeight = 0,
  totalWeight = 0,
  dexFileCount = 0,
  xmlFileCount = 0,
}) {
  const checks = semgrepCheckProgress(ctx, {
    filesDone,
    fileTotal,
    dexFileCount,
    xmlFileCount,
    currentKind: kind,
  });
  const q = checks.files;
  const checksBit = checks.total
    ? (checks.left <= 0
      ? `Checks ${checks.total}/${checks.total}`
      : `Checks ${checks.done}/${checks.total} · ${checks.left} left`)
    : '';
  const filesBit = q.total
    ? `files ${q.done}/${q.total} · ${q.left} left`
    : '';
  const rulesBit = ctx?.ruleCount
    ? `${ctx.ruleCount}${ctx.estimated ? '+' : ''} rules`
    : 'rules';
  const hits = summarizeSemgrepRuleHits(
    kind === 'DEX' || kind === 'XML' ? securitySemgrepFindings : [],
    2
  );
  const hitsBit = hits.length ? ` · hits: ${hits.join(', ')}` : '';
  const rate = formatSemgrepThroughput(doneWeight, totalElapsedMs);
  const eta = estimateSemgrepEta(doneWeight, totalWeight, totalElapsedMs);
  const pct = totalWeight > 0 ? Math.min(100, Math.round((doneWeight / totalWeight) * 100)) : 0;
  const head = [checksBit, filesBit].filter(Boolean).join(' · ');
  const lines = [
    `${head || 'Scanning'} · matching ${kind} ${targetName} (${formatFileSize(fileSize)}) · ${formatScanElapsed(fileElapsedMs)}`,
    `${head || 'Scanning'} · ${rulesBit} on this file` +
      (checks.currentRules ? ` (${checks.currentRules} applicable)` : '') +
      ` · ${findings} finding${findings === 1 ? '' : 's'}${hitsBit}`,
    `${head || 'Scanning'} · ${pct}% · ${formatFileSize(doneWeight)}/${formatFileSize(totalWeight)}` +
      (rate ? ` · ${rate}` : '') +
      (eta ? ` · ${eta}` : ''),
  ];
  return lines[tick % lines.length];
}

async function runSecuritySemgrepScan(opts = {}) {
  const embedded = !!opts.embedded;
  if (!embedded && securityScanBusy) return;
  const targets = await collectDexScanTargets();
  if (!targets.length) {
    if (!embedded) setSecurityStatus('No DEX loaded — open a DEX or APK first');
    return false;
  }
  let yaml = securitySemgrepRulesYaml;
  if (!yaml) {
    try { yaml = localStorage.getItem(SECURITY_RULES_KEY); } catch (_) {}
  }
  if (yaml && yaml.trim() && !securitySemgrepRulesYaml) {
    securitySemgrepRulesYaml = yaml;
  }
  const rulesArg = yaml && yaml.trim() ? yaml : undefined;
  const xmlCandidates = [];
  if (apkManifestXml && typeof apkManifestXml === 'string' && !apkManifestXml.startsWith('(') && !apkManifestXml.startsWith('No ')) {
    xmlCandidates.push({ xml: apkManifestXml, label: 'AndroidManifest.xml' });
  } else if (currentType === 'axml' && currentData?.xml) {
    xmlCandidates.push({ xml: currentData.xml, label: currentFilename || 'manifest.xml' });
  }

  const scanT0 = performance.now();
  if (!embedded) {
    beginSecurityScan('Semgrep — preparing', {
      phases: { vuln: 'skipped', semgrep: 'active', mt: 'skipped' },
    });
    securitySemgrepFindings = [];
    securityFromCache = false;
  } else {
    setSecurityScanPhases({ semgrep: 'active' });
  }

  const phaseBase = opts.phaseBase ?? 0;
  const phaseSpan = opts.phaseSpan ?? 100;
  const mapSemgrepPct = (doneWeight, totalWeight) =>
    phaseBase + (doneWeight / Math.max(1, totalWeight)) * phaseSpan;

  try {
    throwIfSecurityScanAborted();
    await ensureMainWasm();
    preloadSemgrepBuiltinRules();

    showSecurityProgress(embedded ? 'Security scan — Semgrep (preparing)' : 'Semgrep — preparing', {
      indeterminate: true,
      detail: 'Preparing scan targets…',
      extra: `${targets.length} DEX · ${xmlCandidates.length} XML candidate(s)`,
      stats: [`${targets.length} DEX`, xmlCandidates.length ? `${xmlCandidates.length} XML` : null, ...securityFindingsSoFarChips()].filter(Boolean),
      phases: { semgrep: 'active' },
    });
    setSecurityStatus(embedded ? 'Security scan — Semgrep preparing…' : 'Semgrep — preparing…');
    await yieldToUi();
    throwIfSecurityScanAborted();

    const ctx = buildSemgrepScanContext(rulesArg);
    if (ctx.ruleCount >= 80 || (rulesArg && rulesArg.length > 20000)) {
      setSecurityStatus(
        `Semgrep — large ruleset (${ctx.ruleCount || estimateSemgrepRuleCount(rulesArg)} rules) · running in worker…`
      );
      await yieldToUi();
    }
    const dexBytesTotal = targets.reduce((n, t) => n + (t.bytes?.length || 0), 0);
    const xmlBytesTotal = xmlCandidates.reduce((n, c) => n + (c.xml?.length || 0), 0);
    const totalWeight = Math.max(1, dexBytesTotal + xmlBytesTotal);
    let doneWeight = 0;
    const fileTotal = targets.length + xmlCandidates.length;
    const queueNames = [
      ...targets.map((t) => t.name),
      ...xmlCandidates.map((c) => c.label),
    ];
    const remainingNamesFrom = (filesDone) => queueNames.slice(Math.max(0, filesDone));
    const dexFileCount = targets.length;
    const xmlFileCount = xmlCandidates.length;
    const checksAt = (filesDone, kind = '') => semgrepCheckProgress(ctx, {
      filesDone,
      fileTotal,
      dexFileCount,
      xmlFileCount,
      currentKind: kind,
    });
    const queueExtra = (filesDone, kind = '') => formatSemgrepQueueExtra(
      filesDone,
      fileTotal,
      remainingNamesFrom(filesDone),
      checksAt(filesDone, kind)
    );
    const sgStats = (filesDone, kind, extra = {}) => semgrepProgressStats(ctx, {
      findings: securitySemgrepFindings.length,
      fileTotal,
      filesDone,
      dexFileCount,
      xmlFileCount,
      currentKind: kind,
      ...extra,
    });

    const countLabel = ctx.ruleCount
      ? `${ctx.ruleCount}${ctx.estimated ? '+' : ''} rules`
      : 'rules';
    const langLabel = ctx.rules.length
      ? ` (${ctx.javaRules} Java · ${ctx.xmlRules} XML${ctx.nativeRules ? ` · ${ctx.nativeRules} native` : ''})`
      : '';
    const sevLabel = ctx.rules.length
      ? ` · ${ctx.severities.ERROR} ERROR / ${ctx.severities.WARNING} WARNING / ${ctx.severities.INFO} INFO`
      : '';
    const sampleLabel = ctx.sampleRuleIds?.length
      ? ` · sample: ${ctx.sampleRuleIds.slice(0, 4).join(', ')}`
      : '';
    const rulesDetail = `${ctx.source} · ${countLabel}${langLabel}${sevLabel}${sampleLabel}`;

    showSecurityProgress(embedded ? 'Security scan — Semgrep' : 'Semgrep — ready', {
      indeterminate: false,
      pct: Math.round(mapSemgrepPct(0, totalWeight)),
      detail: (() => {
        const c = checksAt(0);
        return `${c.total} checks (${ctx.ruleCount || 0} rules × ${fileTotal} file(s)) · ${targets.length} DEX (${formatFileSize(dexBytesTotal)})${xmlCandidates.length ? ` · ${xmlCandidates.length} XML (${formatFileSize(xmlBytesTotal)})` : ''} · ${rulesDetail}`;
      })(),
      extra: queueExtra(0),
      stats: sgStats(0, '', { elapsedMs: 0, phase: 'init', totalWeight }),
      phases: { semgrep: 'active' },
    });
    {
      const c0 = checksAt(0);
      setSecurityStatus(embedded
        ? `Security scan — Semgrep · ${c0.total} checks (${ctx.ruleCount || '?'} rules × ${fileTotal} files)…`
        : `Semgrep — ${c0.total} checks queued (${ctx.ruleCount || '?'} rules × ${fileTotal} files)…`);
    }
    await yieldToUi();

    for (let i = 0; i < targets.length; i++) {
      throwIfSecurityScanAborted();
      const t = targets[i];
      const fileSize = t.bytes?.length || 0;
      const q = semgrepQueueProgress(i, fileTotal);
      const stepLabel = embedded
        ? `Security scan — Semgrep DEX ${i + 1}/${targets.length}: ${t.name}`
        : `Semgrep DEX ${i + 1}/${targets.length}: ${t.name}`;
      const chk = checksAt(i, 'DEX');
      const prepDetail = `[DEX ${i + 1}/${targets.length}] ${t.name} · ${formatFileSize(fileSize)} · checks ${chk.done}/${chk.total} (${chk.left} left) · applying ${ctx.ruleCount || '?'} rules`;
      const etaNow = estimateSemgrepEta(doneWeight, totalWeight, performance.now() - scanT0);
      const extra = queueExtra(i, 'DEX') +
        ` · ${formatFileSize(doneWeight)} / ${formatFileSize(totalWeight)}` +
        (etaNow ? ` · ${etaNow}` : '');

      updateSecurityProgressWeighted(mapSemgrepPct(doneWeight, totalWeight), 100, stepLabel, prepDetail,
        sgStats(i, 'DEX', {
          elapsedMs: performance.now() - scanT0,
          payloadBytes: fileSize,
          phase: 'DEX prepare',
          doneWeight,
          totalWeight,
          targetName: t.name,
        }),
        { extra, phases: { semgrep: 'active' } }
      );
      setSecurityStatus(`${stepLabel} — checks ${chk.done}/${chk.total} · ${chk.left} left · preparing…`);
      await yieldToUi();
      throwIfSecurityScanAborted();

      const fileT0 = performance.now();
      let hbTick = 0;
      const pushHeartbeat = () => {
        const fileElapsed = performance.now() - fileT0;
        const totalElapsed = performance.now() - scanT0;
        const detail = semgrepHeartbeatDetail({
          ctx,
          targetName: t.name,
          fileSize,
          fileElapsedMs: fileElapsed,
          totalElapsedMs: totalElapsed,
          findings: securitySemgrepFindings.length,
          kind: 'DEX',
          tick: hbTick++,
          filesDone: i,
          fileTotal,
          doneWeight,
          totalWeight,
          dexFileCount,
          xmlFileCount,
        });
        const rate = formatSemgrepThroughput(doneWeight, totalElapsed);
        const etaHb = estimateSemgrepEta(doneWeight, totalWeight, totalElapsed);
        const chkHb = checksAt(i, 'DEX');
        // Keep overall % visible (completed payload); current file is still matching.
        showSecurityProgress(stepLabel, {
          indeterminate: false,
          pct: Math.round(mapSemgrepPct(doneWeight, totalWeight)),
          detail,
          extra: queueExtra(i, 'DEX') +
            ` · ${formatFileSize(doneWeight)}/${formatFileSize(totalWeight)}` +
            (rate ? ` · ${rate}` : '') +
            (etaHb ? ` · ${etaHb}` : ''),
          stats: sgStats(i, 'DEX', {
            elapsedMs: totalElapsed,
            payloadBytes: fileSize,
            phase: `DEX matching ${i + 1}/${targets.length}`,
            doneWeight,
            totalWeight,
            targetName: t.name,
          }),
          phases: { semgrep: 'active' },
        });
        setSecurityStatus(`${stepLabel} — checks ${chkHb.done}/${chkHb.total} · ${chkHb.left} left · ${formatScanElapsed(fileElapsed)} · ${securitySemgrepFindings.length} finding(s)`);
      };
      pushHeartbeat();
      await yieldToUi();

      let heartbeat = setInterval(pushHeartbeat, 700);
      const baseline = securitySemgrepFindings.length;
      let lastPartialApply = 0;
      const applySemgrepPartial = (partial, force = false) => {
        const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
        if (!force && now - lastPartialApply < 500) return;
        lastPartialApply = now;
        const findings = Array.isArray(partial) ? partial : [];
        securitySemgrepFindings = securitySemgrepFindings.slice(0, baseline);
        for (const f of findings) {
          securitySemgrepFindings.push({ ...f, dex_file: targets.length > 1 ? t.name : (f.dex_file || t.name) });
        }
        refreshSecurityFindingsLive();
      };
      let raw;
      try {
        raw = await scanSemgrepInWorker(t.bytes, rulesArg, (prog) => {
          if (prog && prog.findings) applySemgrepPartial(prog.findings, false);
        });
      } catch (scanErr) {
        clearInterval(heartbeat);
        if (isSecurityScanAbortError(scanErr)) throw scanErr;
        if (isSecurityWorkerTimeoutError(scanErr)) {
          warn('[semgrep] timed out on', t.name, '— keeping', securitySemgrepFindings.length - baseline, 'partial finding(s)');
          setSecurityStatus(`Semgrep: ${t.name} timed out — kept partial results, continuing…`);
          doneWeight += fileSize;
          await yieldToUi();
          continue;
        }
        throw scanErr;
      } finally {
        clearInterval(heartbeat);
      }
      throwIfSecurityScanAborted();
      const result = normalizeWasmResult(raw);
      if (!result?.ok) throw new Error(result?.error || 'scan_semgrep failed');
      const findings = Array.isArray(result.findings) ? result.findings : [];
      const newCount = findings.length;
      applySemgrepPartial(findings, true);

      doneWeight += fileSize;
      const fileMs = performance.now() - fileT0;
      const elapsed = performance.now() - scanT0;
      const topHits = summarizeSemgrepRuleHits(findings, 3);
      const hitsBit = topHits.length ? ` · top: ${topHits.join(', ')}` : '';
      const rate = formatSemgrepThroughput(fileSize, fileMs);
      const etaNext = estimateSemgrepEta(doneWeight, totalWeight, elapsed);
      const filesDone = i + 1;
      const chkDone = checksAt(filesDone, 'DEX');
      const doneDetail = `+${newCount} from ${t.name} (${securitySemgrepFindings.length} total)${hitsBit} · file ${formatScanElapsed(fileMs)}${rate ? ` · ${rate}` : ''} · checks ${chkDone.done}/${chkDone.total} · ${chkDone.left} left`;

      updateSecurityProgressWeighted(mapSemgrepPct(doneWeight, totalWeight), 100,
        embedded ? `Security scan — Semgrep DEX done ${i + 1}/${targets.length}` : `Semgrep DEX done ${i + 1}/${targets.length}`,
        doneDetail,
        sgStats(filesDone, 'DEX', {
          elapsedMs: elapsed,
          payloadBytes: fileSize,
          phase: 'DEX ✓',
          doneWeight,
          totalWeight,
          newFindings: newCount,
          targetName: t.name,
        }),
        {
          extra: queueExtra(filesDone, 'DEX') +
            ` · ${formatFileSize(doneWeight)} / ${formatFileSize(totalWeight)}` +
            (etaNext ? ` · ${etaNext}` : ''),
          phases: { semgrep: 'active' },
        }
      );
      setSecurityStatus(`${stepLabel} — +${newCount} finding(s), ${securitySemgrepFindings.length} total · checks ${chkDone.done}/${chkDone.total} · ${chkDone.left} left · ${formatScanElapsed(fileMs)}`);
      await yieldToUi();
    }

    for (let i = 0; i < xmlCandidates.length; i++) {
      throwIfSecurityScanAborted();
      const c = xmlCandidates[i];
      const xmlLen = c.xml?.length || 0;
      const xmlIndex = targets.length + i;
      const q = semgrepQueueProgress(xmlIndex, fileTotal);
      const stepLabel = embedded
        ? `Security scan — Semgrep XML ${i + 1}/${xmlCandidates.length}: ${c.label}`
        : `Semgrep XML ${i + 1}/${xmlCandidates.length}: ${c.label}`;
      const chk = checksAt(xmlIndex, 'XML');
      const prepDetail = `[XML ${i + 1}/${xmlCandidates.length}] ${c.label} · ${formatFileSize(xmlLen)} · checks ${chk.done}/${chk.total} (${chk.left} left) · ${ctx.xmlRules || ctx.ruleCount} XML rules`;
      const extra = queueExtra(xmlIndex, 'XML') +
        ` · ${formatFileSize(doneWeight)} / ${formatFileSize(totalWeight)}`;

      updateSecurityProgressWeighted(mapSemgrepPct(doneWeight, totalWeight), 100, stepLabel, prepDetail,
        sgStats(xmlIndex, 'XML', {
          elapsedMs: performance.now() - scanT0,
          payloadBytes: xmlLen,
          phase: 'XML prepare',
          doneWeight,
          totalWeight,
          targetName: c.label,
        }),
        { extra, phases: { semgrep: 'active' } }
      );
      setSecurityStatus(`${stepLabel} — checks ${chk.done}/${chk.total} · ${chk.left} left · preparing…`);
      await yieldToUi();
      throwIfSecurityScanAborted();

      const fileT0 = performance.now();
      let hbTick = 0;
      const pushHeartbeat = () => {
        const fileElapsed = performance.now() - fileT0;
        const totalElapsed = performance.now() - scanT0;
        const detail = semgrepHeartbeatDetail({
          ctx,
          targetName: c.label,
          fileSize: xmlLen,
          fileElapsedMs: fileElapsed,
          totalElapsedMs: totalElapsed,
          findings: securitySemgrepFindings.length,
          kind: 'XML',
          tick: hbTick++,
          filesDone: xmlIndex,
          fileTotal,
          doneWeight,
          totalWeight,
          dexFileCount,
          xmlFileCount,
        });
        const etaHb = estimateSemgrepEta(doneWeight, totalWeight, totalElapsed);
        const chkHb = checksAt(xmlIndex, 'XML');
        showSecurityProgress(stepLabel, {
          indeterminate: false,
          pct: Math.round(mapSemgrepPct(doneWeight, totalWeight)),
          detail,
          extra: queueExtra(xmlIndex, 'XML') +
            ` · XML matcher · ${ctx.xmlRules || '?'} rules · ${formatFileSize(xmlLen)}` +
            (etaHb ? ` · ${etaHb}` : ''),
          stats: sgStats(xmlIndex, 'XML', {
            elapsedMs: totalElapsed,
            payloadBytes: xmlLen,
            phase: `XML matching ${i + 1}/${xmlCandidates.length}`,
            doneWeight,
            totalWeight,
            targetName: c.label,
          }),
          phases: { semgrep: 'active' },
        });
        setSecurityStatus(`${stepLabel} — checks ${chkHb.done}/${chkHb.total} · ${chkHb.left} left · ${formatScanElapsed(fileElapsed)}…`);
      };
      pushHeartbeat();
      await yieldToUi();

      let heartbeat = setInterval(pushHeartbeat, 700);
      let raw;
      try {
        raw = await scanSemgrepXmlInWorker(c.xml, c.label, rulesArg);
      } finally {
        clearInterval(heartbeat);
      }
      throwIfSecurityScanAborted();
      const result = normalizeWasmResult(raw);
      if (!result?.ok) throw new Error(result?.error || 'scan_semgrep_xml failed');
      const findings = Array.isArray(result.findings) ? result.findings : [];
      const newCount = findings.length;
      for (const f of findings) {
        securitySemgrepFindings.push({ ...f, dex_file: c.label });
      }
      refreshSecurityFindingsLive();

      doneWeight += Math.max(xmlLen, 1);
      const fileMs = performance.now() - fileT0;
      const elapsed = performance.now() - scanT0;
      const topHits = summarizeSemgrepRuleHits(findings, 3);
      const hitsBit = topHits.length ? ` · top: ${topHits.join(', ')}` : '';
      const filesDone = xmlIndex + 1;
      const chkDone = checksAt(filesDone, 'XML');
      const doneDetail = `+${newCount} from ${c.label} (${securitySemgrepFindings.length} total)${hitsBit} · ${formatScanElapsed(fileMs)} · checks ${chkDone.done}/${chkDone.total} · ${chkDone.left} left`;

      updateSecurityProgressWeighted(mapSemgrepPct(doneWeight, totalWeight), 100,
        embedded ? `Security scan — Semgrep XML done ${i + 1}/${xmlCandidates.length}` : `Semgrep XML done ${i + 1}/${xmlCandidates.length}`,
        doneDetail,
        sgStats(filesDone, 'XML', {
          elapsedMs: elapsed,
          payloadBytes: xmlLen,
          phase: 'XML ✓',
          doneWeight,
          totalWeight,
          newFindings: newCount,
          targetName: c.label,
        }),
        {
          extra: queueExtra(filesDone, 'XML') +
            ` · ${formatFileSize(doneWeight)} / ${formatFileSize(totalWeight)}`,
          phases: { semgrep: 'active' },
        }
      );
      setSecurityStatus(`${stepLabel} — +${newCount} finding(s) · checks ${chkDone.done}/${chkDone.total} · ${chkDone.left} left · ${formatScanElapsed(fileMs)}`);
      await yieldToUi();
    }

    const totalMs = performance.now() - scanT0;
    const allTop = summarizeSemgrepRuleHits(securitySemgrepFindings, 5);
    setSecurityScanPhases({ semgrep: 'done' });
    showSecurityProgress(embedded ? 'Security scan — Semgrep complete' : 'Semgrep complete', {
      indeterminate: false,
      pct: Math.round(mapSemgrepPct(totalWeight, totalWeight)),
      detail: (() => {
        const c = checksAt(fileTotal);
        return `${securitySemgrepFindings.length} finding(s) · checks ${c.done}/${c.total} · ${ctx.ruleCount} rules · ${targets.length} DEX + ${xmlCandidates.length} XML · ${formatScanElapsed(totalMs)}` +
          (allTop.length ? ` · top rules: ${allTop.join(', ')}` : '');
      })(),
      extra: `Finished Semgrep in ${formatScanElapsed(totalMs)}` +
        (formatSemgrepThroughput(dexBytesTotal + xmlBytesTotal, totalMs)
          ? ` · avg ${formatSemgrepThroughput(dexBytesTotal + xmlBytesTotal, totalMs)}`
          : '') +
        ` · ${checksAt(fileTotal).total} checks complete`,
      stats: sgStats(fileTotal, '', {
        elapsedMs: totalMs,
        payloadBytes: dexBytesTotal + xmlBytesTotal,
        phase: 'done',
        doneWeight: totalWeight,
        totalWeight,
      }),
      phases: { semgrep: 'done' },
      stoppable: embedded ? true : false,
    });

    securityScansRun.semgrep = true;
    refreshSecurityFindingsLive();
    if (!embedded) {
      const cached = saveSecurityCache();
      setSecurityStatus(
        `Semgrep done — ${securitySemgrepFindings.length} finding(s) · ${ctx.ruleCount} rules · ${formatScanElapsed(totalMs)}` +
        (allTop.length ? ` · ${allTop.slice(0, 2).join(', ')}` : '') +
        (cached ? ' · saved to localStorage' : '')
      );
      renderSecurityPanel();
      await yieldToUi();
    }
    return true;
  } catch (e) {
    if (isSecurityScanAbortError(e)) {
      setSecurityScanPhases({ semgrep: 'error' });
      if (!embedded) {
        saveSecurityCache();
        showSecurityProgress('Scan stopped', {
          indeterminate: false,
          detail: `Stopped during Semgrep · kept ${securitySemgrepFindings.length} finding(s)`,
          extra: `Elapsed ${formatScanElapsed(performance.now() - scanT0)}`,
          stats: securityFindingsSoFarChips().concat([formatScanElapsed(performance.now() - scanT0)]),
          stoppable: false,
        });
        setSecurityStatus(`Scan stopped — ${securitySemgrepFindings.length} Semgrep finding(s) kept`);
        renderSecurityPanel();
      }
      throw e;
    }
    if (!embedded) {
      warn('scan_semgrep', e);
      setSecurityStatus('Semgrep failed: ' + (e?.message || e));
    }
    setSecurityScanPhases({ semgrep: 'error' });
    throw e;
  } finally {
    if (!embedded) endSecurityScan({ aborted: securityScanAbortRequested, keepProgressMs: securityScanAbortRequested ? 0 : 1600 });
  }
}

async function runSecurityScan() {
  if (securityScanBusy) return;
  const targets = await collectDexScanTargets();
  if (!targets.length) {
    setSecurityStatus('No DEX loaded — open a DEX or APK first');
    return;
  }
  beginSecurityScan('Security scan — starting…', {
    phases: { vuln: 'pending', semgrep: 'pending', mt: 'pending' },
  });
  securityVulnFindings = [];
  securitySemgrepFindings = [];
  securityMtReport = null;
  securityFromCache = false;
  securityScansRun = { vuln: false, semgrep: false, mt: false };
  refreshSecurityFindingsLive();
  const scanT0 = performance.now();
  let aborted = false;
  try {
    showSecurityProgress('Security scan — Vuln', {
      indeterminate: false,
      pct: 0,
      detail: `Pipeline: Vuln → Semgrep → MT · ${targets.length} DEX`,
      extra: targets.map((t) => t.name).slice(0, 4).join(', ') + (targets.length > 4 ? ` (+${targets.length - 4} more)` : ''),
      stats: [`${targets.length} DEX`, ...securityFindingsSoFarChips()],
      phases: { vuln: 'active', semgrep: 'pending', mt: 'pending' },
    });
    await runSecurityVulnScan({ embedded: true, phaseBase: 0, phaseSpan: 33 });
    throwIfSecurityScanAborted();
    try {
      await runSecuritySemgrepScan({ embedded: true, phaseBase: 33, phaseSpan: 34 });
    } catch (sgErr) {
      if (isSecurityScanAbortError(sgErr)) throw sgErr;
      warn('security_scan semgrep', sgErr);
      setSecurityScanPhases({ semgrep: 'error' });
      setSecurityStatus('Semgrep failed — continuing with MT taint… (' + (sgErr?.message || sgErr) + ')');
      await yieldToUi();
    }
    throwIfSecurityScanAborted();
    try {
      await runSecurityTaintSolve({ embedded: true, phaseBase: 67, phaseSpan: 33 });
    } catch (mtErr) {
      if (isSecurityScanAbortError(mtErr)) throw mtErr;
      warn('security_scan mt', mtErr);
      setSecurityScanPhases({ mt: 'error' });
      setSecurityStatus('MT taint failed — keeping prior results… (' + (mtErr?.message || mtErr) + ')');
      await yieldToUi();
    }
    const cached = saveSecurityCache();
    const total = securityVulnFindings.length + securitySemgrepFindings.length +
      (Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0);
    showSecurityProgress('Security scan complete', {
      indeterminate: false,
      pct: 100,
      detail: `${total} finding(s) · Vuln ${securityVulnFindings.length} · Semgrep ${securitySemgrepFindings.length} · MT ${securityMtReport?.issues?.length || 0}`,
      extra: `Finished in ${formatScanElapsed(performance.now() - scanT0)}`,
      stats: [
        `<strong>${total}</strong> total`,
        `${securityVulnFindings.length} vuln`,
        `${securitySemgrepFindings.length} Semgrep`,
        `${securityMtReport?.issues?.length || 0} MT`,
        formatScanElapsed(performance.now() - scanT0),
      ],
      phases: {
        vuln: securityScansRun.vuln ? 'done' : 'error',
        semgrep: securityScansRun.semgrep ? 'done' : 'error',
        mt: securityScansRun.mt ? 'done' : 'error',
      },
      stoppable: false,
    });
    setSecurityStatus(
      `Security scan done — ${total} finding(s) · ${formatScanElapsed(performance.now() - scanT0)}` +
      (cached ? ' · saved to localStorage' : '')
    );
    renderSecurityPanel();
  } catch (e) {
    if (isSecurityScanAbortError(e)) {
      aborted = true;
      const total = securityVulnFindings.length + securitySemgrepFindings.length +
        (Array.isArray(securityMtReport?.issues) ? securityMtReport.issues.length : 0);
      saveSecurityCache();
      showSecurityProgress('Scan stopped', {
        indeterminate: false,
        pct: Number(securityProgressTrack?.getAttribute('aria-valuenow') || 0) || 0,
        detail: `Stopped after ${formatScanElapsed(performance.now() - scanT0)} · kept ${total} finding(s) so far`,
        extra: 'Click Scan to run again from the start',
        stats: securityFindingsSoFarChips().concat([formatScanElapsed(performance.now() - scanT0)]),
        phases: {
          vuln: securityScansRun.vuln ? 'done' : (securityScanPhaseState.vuln === 'active' ? 'error' : securityScanPhaseState.vuln),
          semgrep: securityScansRun.semgrep ? 'done' : (securityScanPhaseState.semgrep === 'active' ? 'error' : securityScanPhaseState.semgrep),
          mt: securityScansRun.mt ? 'done' : (securityScanPhaseState.mt === 'active' ? 'error' : securityScanPhaseState.mt),
        },
        stoppable: false,
      });
      setSecurityStatus(`Scan stopped — ${total} finding(s) kept · ${formatScanElapsed(performance.now() - scanT0)}`);
      renderSecurityPanel();
    } else {
      warn('security_scan', e);
      setSecurityStatus('Security scan failed: ' + (e?.message || e));
      renderSecurityPanel();
    }
  } finally {
    endSecurityScan({ aborted, keepProgressMs: aborted ? 0 : 2200 });
  }
}


function setSecurityRulesStatus(msg) {
  if (securityRulesStatus) securityRulesStatus.textContent = msg || '';
}

function persistSemgrepRulesYaml(yaml) {
  securitySemgrepRulesYaml = yaml;
  try {
    if (yaml && yaml.trim()) localStorage.setItem(SECURITY_RULES_KEY, yaml);
    else localStorage.removeItem(SECURITY_RULES_KEY);
  } catch (_) {}
}

function renderSemgrepRulesList(rules) {
  securitySemgrepRuleInfos = Array.isArray(rules) ? rules : [];
  if (securityRulesCount) {
    securityRulesCount.textContent = `${securitySemgrepRuleInfos.length} rule${securitySemgrepRuleInfos.length === 1 ? '' : 's'}`;
  }
  if (!securityRulesList) return;
  if (!securitySemgrepRuleInfos.length) {
    securityRulesList.innerHTML = '<div class="muted">No rules parsed</div>';
    return;
  }
  securityRulesList.innerHTML = securitySemgrepRuleInfos.map((r) => {
    const langs = (r.languages || []).join(', ') || 'java';
    const meta = [r.severity, langs, r.has_native ? 'native' : '', r.vuln_class || ''].filter(Boolean).join(' · ');
    return `<button type="button" class="security-rule-item" data-rule-id="${escapeAttr(r.id)}">
      <div class="security-rule-id">${escapeHtml(r.id)}</div>
      <div class="muted">${escapeHtml(meta)}</div>
      <div class="security-rule-msg">${escapeHtml(r.message || r.pattern_preview || '')}</div>
    </button>`;
  }).join('');
}

function validateYamlText(yaml) {
  const raw = parse_semgrep_rules(yaml);
  const result = normalizeWasmResult(raw);
  if (!result?.ok) throw new Error(result?.error || 'Invalid Semgrep YAML');
  return Array.isArray(result.rules) ? result.rules : [];
}

function validateSemgrepRulesEditor() {
  try {
    const yaml = securityRulesEditor?.value || '';
    const rules = validateYamlText(yaml);
    renderSemgrepRulesList(rules);
    setSecurityRulesStatus(`OK — ${rules.length} rule(s) parsed`);
  } catch (e) {
    setSecurityRulesStatus('Parse error: ' + (e?.message || e));
  }
}

function applySemgrepRulesFromEditor() {
  try {
    const yaml = securityRulesEditor?.value || '';
    const rules = validateYamlText(yaml);
    renderSemgrepRulesList(rules);
    persistSemgrepRulesYaml(yaml);
    setSecurityRulesStatus(`Applied ${rules.length} rule(s) — used by Scan`);
  } catch (e) {
    setSecurityRulesStatus('Apply failed: ' + (e?.message || e));
  }
}

function loadBuiltinSemgrepRules() {
  // WASM builtin is the full starter + MASTG set.
  const raw = get_semgrep_builtin_rules();
  const result = normalizeWasmResult(raw);
  if (!result?.ok) {
    setSecurityRulesStatus('Built-in All failed (' + (result?.error || 'unknown') + ') — trying rules/semgrep-all.yml…');
    // Fall through to fetch; caller may await loadAllSemgrepRulesFromFiles
    throw new Error(result?.error || 'builtin All parse failed');
  }
  const yaml = result.yaml || '';
  const rules = Array.isArray(result.rules) ? result.rules : [];
  securitySemgrepBuiltinRuleInfos = rules;
  if (securityRulesEditor) setSemgrepRulesEditorValue(yaml);
  renderSemgrepRulesList(rules);
  persistSemgrepRulesYaml(yaml);
  setSecurityRulesStatus(`Loaded All built-in (${rules.length} rules · starter + MASTG)`);
}

async function loadStarterSemgrepRules() {
  setSecurityRulesStatus('Loading starter rules…');
  try {
    const res = await fetch('rules/semgrep-mobhunt.yml');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const yaml = await res.text();
    const rules = validateYamlText(yaml);
    if (securityRulesEditor) setSemgrepRulesEditorValue(yaml);
    renderSemgrepRulesList(rules);
    persistSemgrepRulesYaml(yaml);
    setSecurityRulesStatus(`Loaded starter (${rules.length} rules)`);
  } catch (e) {
    setSecurityRulesStatus('Starter load failed: ' + (e?.message || e));
  }
}

async function loadMastgSemgrepRules() {
  setSecurityRulesStatus('Loading MASTG rules…');
  try {
    const res = await fetch('rules/semgrep-mastg.yml', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const yaml = await res.text();
    const rules = validateYamlText(yaml);
    if (securityRulesEditor) setSemgrepRulesEditorValue(yaml);
    renderSemgrepRulesList(rules);
    persistSemgrepRulesYaml(yaml);
    setSecurityRulesStatus(`Loaded MASTG (${rules.length} rules)`);
  } catch (e) {
    setSecurityRulesStatus('MASTG load failed: ' + (e?.message || e));
  }
}

async function loadAllSemgrepRulesFromFiles() {
  // Prefer WASM builtin (same content as semgrep-all.yml); fall back to fetch.
  try {
    loadBuiltinSemgrepRules();
    if ((securitySemgrepBuiltinRuleInfos?.length || 0) > 4) return;
  } catch (_) {}
  setSecurityRulesStatus('Loading All rules…');
  try {
    const res = await fetch('rules/semgrep-all.yml', { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const yaml = await res.text();
    const rules = validateYamlText(yaml);
    if (securityRulesEditor) setSemgrepRulesEditorValue(yaml);
    renderSemgrepRulesList(rules);
    persistSemgrepRulesYaml(yaml);
    setSecurityRulesStatus(`Loaded All (${rules.length} rules · starter + MASTG)`);
  } catch (e) {
    setSecurityRulesStatus('All rules load failed: ' + (e?.message || e));
  }
}

async function importSemgrepRulesFile(file) {
  try {
    const yaml = await file.text();
    const rules = validateYamlText(yaml);
    if (securityRulesEditor) setSemgrepRulesEditorValue(yaml);
    renderSemgrepRulesList(rules);
    persistSemgrepRulesYaml(yaml);
    setSecurityRulesStatus(`Imported ${file.name} — ${rules.length} rule(s)`);
  } catch (e) {
    setSecurityRulesStatus('Import failed: ' + (e?.message || e));
  }
}

function insertNewSemgrepRuleTemplate() {
  const tpl = `
  - id: custom.android.new-rule
    message: Describe the vulnerability / pattern match.
    severity: WARNING
    languages: [java]
    pattern: $OBJ.suspiciousApi($ARG);
    metadata:
      vuln_class: custom
    native:
      kind: invoke
      methods:
        - suspiciousApi
`;
  if (!securityRulesEditor) return;
  let text = securityRulesEditor.value || '';
  if (!/^\s*rules\s*:/m.test(text)) {
    text = 'rules:\n' + tpl;
  } else {
    text = text.replace(/\s*$/, '') + '\n' + tpl;
  }
  setSemgrepRulesEditorValue(text);
  setSecurityRulesStatus('Inserted new rule template — edit id/pattern, then Validate / Apply');
}

function toggleSecurityRulesPanel() {
  if (!securityRulesPanel) return;
  const open = securityRulesPanel.hidden;
  securityRulesPanel.hidden = !open;
  if (open) {
    if (!(securityRulesEditor?.value || '').trim()) {
      let saved = null;
      try { saved = localStorage.getItem(SECURITY_RULES_KEY); } catch (_) {}
      if (saved) {
        setSemgrepRulesEditorValue(saved);
        securitySemgrepRulesYaml = saved;
        try {
          renderSemgrepRulesList(validateYamlText(saved));
          setSecurityRulesStatus('Restored rules from localStorage');
        } catch (e) {
          setSecurityRulesStatus('Saved rules invalid — load All / Starter / MASTG or fix YAML: ' + (e?.message || e));
        }
      } else {
        loadBuiltinSemgrepRules();
      }
    } else {
      validateSemgrepRulesEditor();
    }
    refreshSemgrepRulesHighlight();
  }
}

document.getElementById('security-scan')?.addEventListener('click', () => runSecurityScan());
document.getElementById('security-progress-stop')?.addEventListener('click', () => requestSecurityScanStop());
document.getElementById('security-clear-cache')?.addEventListener('click', () => clearSecurityCacheForCurrent());
document.getElementById('security-export-storage')?.addEventListener('click', () => downloadAnalysisLocalStorageExport());
document.getElementById('security-import-storage')?.addEventListener('click', () => {
  document.getElementById('security-import-storage-file')?.click();
});
document.getElementById('security-import-storage-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  if (file) promptImportAnalysisFile(file);
  e.target.value = '';
});
document.getElementById('header-export-storage')?.addEventListener('click', () => downloadAnalysisLocalStorageExport());
document.getElementById('header-import-storage')?.addEventListener('click', () => {
  document.getElementById('header-import-storage-file')?.click();
});
document.getElementById('header-import-storage-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  if (file) promptImportAnalysisFile(file);
  e.target.value = '';
});
document.getElementById('settings-export-storage')?.addEventListener('click', () => downloadAnalysisLocalStorageExport());
document.getElementById('settings-import-storage')?.addEventListener('click', () => {
  document.getElementById('settings-import-storage-file')?.click();
});
document.getElementById('settings-import-storage-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  if (file) promptImportAnalysisFile(file);
  e.target.value = '';
});
document.getElementById('security-cache-keep')?.addEventListener('click', () => closeSecurityCacheModal('keep'));
document.getElementById('security-cache-clear')?.addEventListener('click', () => closeSecurityCacheModal('clear'));
securityCacheModal?.addEventListener('click', (e) => {
  const choice = e.target?.closest?.('[data-cache-choice]')?.getAttribute('data-cache-choice');
  if (choice) closeSecurityCacheModal(choice);
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!securityCacheModal || securityCacheModal.hidden) return;
  closeSecurityCacheModal('keep');
});
document.getElementById('security-rules-toggle')?.addEventListener('click', () => toggleSecurityRulesPanel());
document.getElementById('security-rules-all')?.addEventListener('click', () => loadAllSemgrepRulesFromFiles());
document.getElementById('security-rules-builtin')?.addEventListener('click', () => loadStarterSemgrepRules());
document.getElementById('security-rules-mastg')?.addEventListener('click', () => loadMastgSemgrepRules());
document.getElementById('security-rules-import')?.addEventListener('click', () => document.getElementById('security-rules-file')?.click());
document.getElementById('security-rules-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  if (file) importSemgrepRulesFile(file);
  e.target.value = '';
});
document.getElementById('security-rules-validate')?.addEventListener('click', () => validateSemgrepRulesEditor());
document.getElementById('security-rules-apply')?.addEventListener('click', () => applySemgrepRulesFromEditor());
document.getElementById('security-rules-new')?.addEventListener('click', () => insertNewSemgrepRuleTemplate());
if (securityRulesEditor && securityRulesHighlight) {
  securityRulesEditor.addEventListener('input', refreshSemgrepRulesHighlight);
  securityRulesEditor.addEventListener('scroll', syncSemgrepRulesEditorScroll);
  refreshSemgrepRulesHighlight();
}
securityFilterInput?.addEventListener('input', () => {
  securityFilterQuery = securityFilterInput.value || '';
  renderSecurityPanel();
});
document.getElementById('security-panel')?.addEventListener('click', (e) => {
  const verdictBtn = e.target.closest('[data-verdict][data-finding-id]');
  if (verdictBtn) {
    e.preventDefault();
    e.stopPropagation();
    setFindingVerdict(verdictBtn.getAttribute('data-finding-id') || '', verdictBtn.getAttribute('data-verdict') || '');
    return;
  }
  const verdictFilterBtn = e.target.closest('[data-verdict-filter]');
  if (verdictFilterBtn && !verdictFilterBtn.closest('.security-finding')) {
    const next = verdictFilterBtn.getAttribute('data-verdict-filter') || '';
    securityVerdictFilter = securityVerdictFilter === next && next ? '' : next;
    renderSecurityPanel();
    return;
  }
  const sevBtn = e.target.closest('[data-sev]');
  if (sevBtn && !sevBtn.closest('.security-finding')) {
    const next = sevBtn.getAttribute('data-sev') || '';
    // Toggle off when clicking the active severity again (except Total / All levels → clear).
    securitySeverityFilter = securitySeverityFilter === next && next ? '' : next;
    renderSecurityPanel();
    return;
  }
  const sourceTab = e.target.closest('[data-source]');
  if (sourceTab) {
    securitySourceFilter = sourceTab.getAttribute('data-source') || '';
    if (securitySourceFilter) securityCategoryFilter = '';
    renderSecurityPanel();
    return;
  }
  const chip = e.target.closest('.security-chip');
  if (chip) {
    securityCategoryFilter = chip.getAttribute('data-cat') || '';
    renderSecurityPanel();
    return;
  }
  const groupToggle = e.target.closest('[data-group-toggle]');
  if (groupToggle) {
    const key = groupToggle.getAttribute('data-group-toggle') || '';
    const defaultCollapsed = groupToggle.getAttribute('data-group-default-collapsed') === '1';
    toggleSecurityGroupCollapsed(key, defaultCollapsed);
    renderSecurityPanel();
    return;
  }
  const openClassBtn = e.target.closest('[data-open-class]');
  if (openClassBtn) {
    e.preventDefault();
    const className = openClassBtn.getAttribute('data-open-class') || '';
    const dexFile = openClassBtn.getAttribute('data-dex') || '';
    const groupEl = openClassBtn.closest('[data-group]');
    const groupKey = groupEl?.getAttribute('data-group') || '';
    if (groupKey) {
      securityGroupCollapseState.set(groupKey, false);
      renderSecurityPanel();
    }
    if (className && className !== '(unknown class)') {
      navigateToSecurityFinding(className, '', dexFile, { hint: '' });
    }
    return;
  }
  const ruleRow = e.target.closest('.security-rule-item');
  if (ruleRow) {
    const id = ruleRow.getAttribute('data-rule-id') || '';
    if (id && securityRulesEditor) {
      const text = securityRulesEditor.value || '';
      const idx = text.indexOf('id: ' + id);
      if (idx >= 0) {
        securityRulesEditor.focus();
        securityRulesEditor.setSelectionRange(idx, idx + id.length + 4);
        const line = text.slice(0, idx).split('\n').length;
        setSecurityRulesStatus(`Jumped to rule ${id} (near line ${line})`);
      }
    }
    return;
  }
  const traceToggle = e.target.closest('[data-trace-toggle]');
  if (traceToggle) {
    e.stopPropagation();
    const id = traceToggle.getAttribute('data-trace-toggle');
    const ol = id ? document.getElementById(id) : null;
    if (ol) {
      const show = ol.hasAttribute('hidden');
      if (show) ol.removeAttribute('hidden');
      else ol.setAttribute('hidden', '');
      const n = ol.children.length;
      const label = /execution path/i.test(traceToggle.textContent || '') ? 'execution path' : 'trace';
      traceToggle.textContent = show ? `Hide ${label} (${n})` : `Show ${label} (${n})`;
    }
    return;
  }
  const btn = e.target.closest('.security-finding');
  if (!btn) return;
  if (e.target.closest('.security-trace-toggle') || e.target.closest('.security-trace') || e.target.closest('.security-finding-verdict')) return;
  const nav = readSecurityFindingNav(btn);
  if (nav.kind === 'semgrep-xml' || isXmlSecurityFinding(nav.className, nav.methodName)) {
    navigateToXmlSecurityFinding(nav.className);
    return;
  }
  navigateToSecurityFinding(nav.className, nav.methodName, nav.dexFile, { offset: nav.offset, hint: nav.hint });
});
document.getElementById('security-panel')?.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' && e.key !== ' ') return;
  if (e.target.closest('.security-verdict-btn') || e.target.closest('.security-trace-toggle')) return;
  const btn = e.target.closest('.security-finding');
  if (!btn || e.target !== btn) return;
  e.preventDefault();
  const nav = readSecurityFindingNav(btn);
  if (nav.kind === 'semgrep-xml' || isXmlSecurityFinding(nav.className, nav.methodName)) {
    navigateToXmlSecurityFinding(nav.className);
    return;
  }
  navigateToSecurityFinding(nav.className, nav.methodName, nav.dexFile, { offset: nav.offset, hint: nav.hint });
});

try { updateStatusBar(); } catch (e) { console.warn("[droid2web] statusbar init", e); }

/**
 * Web Worker: runs WASM parse / security scans off the main thread
 * so the UI stays responsive.
 */
import initWasm, {
  parse_file,
  find_permission_usages,
  find_string_usages,
  find_method_callers,
  find_method_callees,
  find_field_xrefs,
  index_dex_classes,
  scan_semgrep,
  scan_semgrep_xml,
  scan_vulns,
  taint_solve,
  get_semgrep_builtin_rules,
} from './pkg/droid2web.js';

let wasmReady = false;
const pending = [];
const WASM_INIT_TIMEOUT_MS = 60000;

function toU8(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  return new Uint8Array(bytes || []);
}

function progressCb(id, op) {
  let lastSent = 0;
  let trailing = null;
  const MIN_MS = 800;
  const flush = (findings) => {
    try {
      // Send count + a capped sample so structured-clone doesn't stall both threads.
      const list = Array.isArray(findings) ? findings : [];
      const cap = 200;
      self.postMessage({
        type: 'progress',
        id,
        op,
        findings: list.length > cap ? list.slice(0, cap) : list,
        findingsTotal: list.length,
        partial: list.length > cap,
      });
    } catch (_) {
      /* ignore clone / closed worker errors */
    }
  };
  return (findings) => {
    const now = Date.now();
    if (now - lastSent >= MIN_MS) {
      lastSent = now;
      trailing = null;
      flush(findings);
      return;
    }
    trailing = findings;
    if (!progressCb._timers) progressCb._timers = new Map();
    if (progressCb._timers.has(id)) return;
    progressCb._timers.set(
      id,
      setTimeout(() => {
        progressCb._timers.delete(id);
        if (trailing == null) return;
        lastSent = Date.now();
        const f = trailing;
        trailing = null;
        flush(f);
      }, MIN_MS - (now - lastSent))
    );
  };
}

function handleJob(job) {
  const id = job.id;
  try {
    const op = job.op || 'parse_file';
    let raw;
    if (op === 'parse_file') {
      const u8 = toU8(job.bytes);
      raw = parse_file(u8, job.filename || 'file');
    } else if (op === 'index_dex_classes') {
      const u8 = toU8(job.bytes);
      raw = index_dex_classes(u8);
    } else if (op === 'find_permission_usages') {
      const u8 = toU8(job.bytes);
      const perms = Array.isArray(job.permissions) ? job.permissions : [];
      raw = find_permission_usages(u8, perms);
    } else if (op === 'find_string_usages') {
      const u8 = toU8(job.bytes);
      raw = find_string_usages(u8, Number(job.stringIndex) >>> 0);
    } else if (op === 'find_method_callers') {
      const u8 = toU8(job.bytes);
      raw = find_method_callers(
        u8,
        Number(job.classIdx) >>> 0,
        Number(job.methodIdx) >>> 0
      );
    } else if (op === 'find_method_callees') {
      const u8 = toU8(job.bytes);
      raw = find_method_callees(
        u8,
        Number(job.classIdx) >>> 0,
        Number(job.methodIdx) >>> 0
      );
    } else if (op === 'find_field_xrefs') {
      const u8 = toU8(job.bytes);
      raw = find_field_xrefs(u8, Number(job.fieldIdx) >>> 0);
    } else if (op === 'scan_semgrep') {
      const u8 = toU8(job.bytes);
      const yaml = job.rulesYaml && String(job.rulesYaml).trim() ? String(job.rulesYaml) : undefined;
      raw = scan_semgrep(u8, yaml, progressCb(id, op));
    } else if (op === 'scan_semgrep_xml') {
      const yaml = job.rulesYaml && String(job.rulesYaml).trim() ? String(job.rulesYaml) : undefined;
      raw = scan_semgrep_xml(String(job.xml || ''), String(job.pathLabel || 'xml'), yaml);
    } else if (op === 'scan_vulns') {
      const u8 = toU8(job.bytes);
      raw = scan_vulns(u8, progressCb(id, op));
    } else if (op === 'taint_solve') {
      const u8 = toU8(job.bytes);
      raw = taint_solve(u8);
    } else if (op === 'get_semgrep_builtin_rules') {
      raw = get_semgrep_builtin_rules();
    } else {
      throw new Error('Unknown worker op: ' + op);
    }
    self.postMessage({ type: 'result', id, op, raw });
  } catch (err) {
    self.postMessage({
      type: 'error',
      id,
      op: job.op || 'parse_file',
      error: String(err && err.message ? err.message : err),
    });
  }
}

const initTimeout = new Promise((_, reject) => {
  setTimeout(
    () => reject(new Error('Worker WASM init timed out after ' + (WASM_INIT_TIMEOUT_MS / 1000) + 's')),
    WASM_INIT_TIMEOUT_MS
  );
});

Promise.race([initWasm(), initTimeout])
  .then(() => {
    wasmReady = true;
    self.postMessage({ type: 'ready' });
    pending.forEach(handleJob);
    pending.length = 0;
  })
  .catch((err) => {
    const msg = String(err && err.message ? err.message : err);
    self.postMessage({ type: 'error', error: 'Worker WASM init failed: ' + msg });
    pending.forEach((job) => {
      self.postMessage({
        type: 'error',
        id: job.id,
        op: job.op || 'parse_file',
        error: 'Worker WASM init failed: ' + msg,
      });
    });
    pending.length = 0;
  });

self.onmessage = (e) => {
  const job = e.data || {};
  // Backward-compatible parse_file messages (no op / id)
  if (!job.op && job.bytes && job.filename) {
    job.op = 'parse_file';
  }
  if (!wasmReady) {
    pending.push(job);
    return;
  }
  handleJob(job);
};

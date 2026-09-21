/**
 * WebUSB ADB (webadb-rs) helper for the Device tab (goauld attach / inject).
 * One USB link, many ADB streams. A single reader demuxes packets so the
 * mirror and the goauld agent can stay open together. Calls are still
 * serialized: the transport is not concurrency-safe.
 *
 * Never call into the Wasm `Adb` object outside `enqueue` while a stream op
 * may be in flight — wasm-bindgen's `&mut self` lock yields
 * "recursive use of an object". Connection state is cached in JS.
 */

const ADB_USB_FILTERS = Object.freeze([
  { classCode: 0xff, subclassCode: 0x42, protocolCode: 0x01 },
]);

const DEVICE_DIR = '/data/local/tmp/goauld';
const DEVICE_INJECTOR = `${DEVICE_DIR}/goauld-injector`;
const DEVICE_AGENT = `${DEVICE_DIR}/libgoauld_agent.so`;
const TMP_APK = '/data/local/tmp/droid2web-patched.apk';

let wasmReady = null;
let AdbCtor = null;
let adb = null;
let deviceInfo = null;
/** Cached so UI never calls `adb.is_connected()` during a stream op. */
let phoneConnected = false;

let queue = Promise.resolve();
/** @type {Map<number, { queue: Uint8Array[], waiters: Array<(b: Uint8Array) => void>, closed: boolean }>} */
const lanes = new Map();
let pumpQueued = false;
/** Control / shell / push waiting — demux yields so they are not starved by video. */
let controlWaiters = 0;
/** True while any long device op is running (syscall trace, inject, …). */
let deviceBusy = false;

/** Kept so older callers can clear a stuck session. Streams are no longer exclusive. */
export function releaseStreamExclusive() {}

export function isStreamExclusive() {
  return false;
}

export function isDeviceBusy() {
  return deviceBusy;
}

export function setDeviceBusy(on) {
  deviceBusy = !!on;
}

/**
 * Serialize ALL Adb WASM calls. The transport is not concurrency-safe:
 * overlapping `&mut self` across `.await` → "recursive use of an object".
 */
function enqueue(label, fn) {
  const run = queue.then(async () => {
    try {
      return await fn();
    } catch (e) {
      const msg = e?.message || String(e);
      throw new Error(`${label}: ${msg}`);
    }
  });
  // Keep queue alive even if a step fails.
  queue = run.catch(() => {});
  return run;
}

function deliverLane(id, bytes, closed) {
  const lane = lanes.get(id);
  if (!lane) return;
  if (closed) {
    lane.closed = true;
    const waiter = lane.waiters.shift();
    if (waiter) waiter(new Uint8Array(0));
    else lane.queue.push(new Uint8Array(0));
    return;
  }
  const data = bytes instanceof Uint8Array ? new Uint8Array(bytes) : new Uint8Array(bytes || []);
  const waiter = lane.waiters.shift();
  if (waiter) waiter(data);
  else lane.queue.push(data);
}

function failLanes(err) {
  for (const lane of lanes.values()) {
    lane.closed = true;
    while (lane.waiters.length) lane.waiters.shift()(new Uint8Array(0));
  }
  if (err) console.error('adb demux', err);
}

function hasLaneWaiters() {
  for (const lane of lanes.values()) {
    if (lane.waiters.length) return true;
  }
  return false;
}

/**
 * One in-flight USB read, shared by every open stream.
 * Only runs while someone is blocked on `transport.read()` — never leave a
 * read pending on a quiet goauld socket or ScriptLoad / shell stall forever.
 */
function ensurePump() {
  if (
    pumpQueued ||
    !hasLaneWaiters() ||
    controlWaiters > 0 ||
    typeof adb?.readAny !== 'function'
  ) {
    return;
  }
  pumpQueued = true;
  enqueue('adb read', async () => {
    if (!hasLaneWaiters() || controlWaiters > 0) return null;
    return adb.readAny();
  }).then(
    (ev) => {
      pumpQueued = false;
      if (ev) {
        const id = Number(ev.id);
        if (ev.closed) deliverLane(id, null, true);
        else deliverLane(id, ev.data, false);
      }
      queueMicrotask(() => ensurePump());
    },
    (err) => {
      pumpQueued = false;
      failLanes(err);
    },
  );
}

/** Serialize shell/push/write ahead of the demux reader. */
function enqueueControl(label, fn) {
  controlWaiters++;
  return enqueue(label, fn).finally(() => {
    controlWaiters--;
    queueMicrotask(() => ensurePump());
  });
}

export function isWebUsbAvailable() {
  return typeof navigator !== 'undefined' && !!navigator.usb;
}

export function isAdbConnected() {
  // Do NOT call into Wasm here — it races with in-flight stream ops.
  return phoneConnected && !!adb;
}

export function getDeviceInfo() {
  return deviceInfo;
}

async function ensureWasm() {
  if (wasmReady) return wasmReady;
  wasmReady = (async () => {
    const mod = await import('./pkg-webadb/webadb_rs.js');
    await mod.default();
    AdbCtor = mod.Adb;
  })();
  return wasmReady;
}

async function requestAdbUsbDevice() {
  if (!isWebUsbAvailable()) {
    throw new Error('WebUSB unavailable — use Chrome/Edge on HTTPS or localhost');
  }
  return navigator.usb.requestDevice({ filters: ADB_USB_FILTERS });
}

/**
 * Must be called from a user-gesture handler (click).
 */
export async function connectAdb() {
  await ensureWasm();
  const usbDevice = await requestAdbUsbDevice();
  if (!adb) adb = new AdbCtor();
  await enqueue('connect', async () => {
    if (phoneConnected) {
      try {
        await adb.disconnect();
      } catch {
        /* ignore */
      }
      phoneConnected = false;
    }
    deviceInfo = await adb.connectWithUsbDevice(usbDevice);
    phoneConnected = true;
  });
  return deviceInfo;
}

export async function disconnectAdb() {
  if (!adb) return;
  await enqueue('disconnect', async () => {
    try {
      await adb.disconnect();
    } finally {
      phoneConnected = false;
      deviceInfo = null;
      for (const lane of lanes.values()) {
        lane.closed = true;
        while (lane.waiters.length) lane.waiters.shift()(new Uint8Array(0));
      }
      lanes.clear();
    }
  });
}

export async function adbShell(cmd, timeoutMs = 60000) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  return enqueueControl(`shell ${cmd}`, async () => {
    if (typeof adb.shell_with_timeout === 'function') {
      return adb.shell_with_timeout(cmd, timeoutMs);
    }
    return adb.shell(cmd);
  });
}

export async function adbPush(bytes, remotePath) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return enqueueControl(`push ${remotePath}`, () => adb.push_file(data, remotePath));
}

export async function adbLogcat(lines = 200) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  return enqueue('logcat', () => adb.logcat(lines));
}

export async function adbLogcatClear() {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  return enqueue('logcat -c', () => adb.logcat_clear());
}

export async function adbLogcatGoauld(lines = 400) {
  const raw = await adbShell(`logcat -d -t ${Math.max(50, lines | 0)} -s goauld:D AndroidRuntime:E`, 90000);
  return String(raw || '');
}

/**
 * Push APK and `pm install -r -t`.
 */
export async function installApk(apkBytes, remotePath = TMP_APK) {
  await adbPush(apkBytes, remotePath);
  const out = await adbShell(`pm install -r -t ${remotePath}`, 180000);
  const text = String(out || '');
  if (!/Success/i.test(text) && !/success/i.test(text)) {
    throw new Error(`pm install failed:\n${text.trim() || '(empty)'}`);
  }
  return text.trim();
}

/**
 * Launch package via monkey LAUNCHER (no activity name needed).
 */
export async function launchPackage(packageName) {
  const pkg = String(packageName || '').trim();
  if (!pkg) throw new Error('package name required');
  return adbShell(
    `monkey -p ${pkg} -c android.intent.category.LAUNCHER 1`,
    60000,
  );
}

export async function forceStopPackage(packageName) {
  const pkg = String(packageName || '').trim();
  if (!pkg) throw new Error('package name required');
  return adbShell(`am force-stop ${pkg}`);
}

export async function pidOf(packageName) {
  const pkg = String(packageName || '').trim();
  if (!pkg) throw new Error('package name required');
  const out = String(await adbShell(`pidof -s ${pkg}`) || '').trim();
  return out || null;
}

/**
 * Deploy arm_goauld injector + agent to the device (desktop goauld-host parity).
 */
export async function deployGoauld(injectorBytes, agentBytes) {
  if (!injectorBytes?.length) throw new Error('goauld-injector bytes required');
  if (!agentBytes?.length) throw new Error('libgoauld_agent.so bytes required');
  await adbShell(`mkdir -p ${DEVICE_DIR}`);
  await adbPush(injectorBytes, DEVICE_INJECTOR);
  await adbPush(agentBytes, DEVICE_AGENT);
  await adbShell(`chmod 755 ${DEVICE_INJECTOR}`);
  await adbShell(`chmod 644 ${DEVICE_AGENT}`);
  return { injector: DEVICE_INJECTOR, agent: DEVICE_AGENT };
}

/**
 * Ptrace-inject agent into a running package (needs root / su on device).
 * @param {{ packageName?: string, pid?: number|string, stageIntoApp?: boolean, via?: string }} [opts]
 */
export async function injectGoauldLive({ packageName, pid, stageIntoApp = false, via = '' } = {}) {
  let remote = `${DEVICE_INJECTOR} inject --so ${DEVICE_AGENT}`;
  const pkg = String(packageName || '').trim();
  if (pkg) remote += ` --package ${pkg}`;
  if (pid != null && pid !== '') remote += ` --pid ${Number(pid)}`;
  if (!pkg && (pid == null || pid === '')) {
    throw new Error('pass packageName or pid');
  }
  if (stageIntoApp) remote += ' --stage-into-app';

  const { out, via: used } = await runAsRoot(remote, 120000, { via });
  return `via ${used}\n${out}`;
}

export async function listPackages(filter = '') {
  const out = String(await adbShell('pm list packages') || '');
  const lines = out
    .split('\n')
    .map((l) => l.replace(/^package:/, '').trim())
    .filter(Boolean);
  if (!filter) return lines;
  const f = filter.toLowerCase();
  return lines.filter((p) => p.toLowerCase().includes(f));
}

/**
 * List installed packages with process rows from `ps`.
 * @returns {Promise<Array<{ package: string, pid: number|null, running: boolean, user: string, processes: Array<{pid:number, ppid:number|null, user:string, state:string, name:string}> }>>}
 */
export async function listAppsWithPids({ thirdPartyOnly = false } = {}) {
  const cmd = thirdPartyOnly ? 'pm list packages -3' : 'pm list packages';
  // Sequential — never Promise.all two Adb ops (aliasing / take races).
  const pkgOut = await adbShell(cmd, 90000);
  let psOut = await adbShell('ps -A -o PID,PPID,USER,S,NAME', 60000).catch(() => '');
  if (!/\bPID\b/.test(psOut) || !/\bNAME\b/.test(psOut)) {
    psOut = await adbShell('ps -A', 60000).catch(() => '');
  }
  const packages = String(pkgOut || '')
    .split('\n')
    .map((l) => l.replace(/^package:/, '').trim())
    .filter(Boolean);
  const procs = parsePs(psOut);

  return packages
    .map((pkg) => {
      const processes = procs
        .filter((p) => p.name === pkg || p.name.startsWith(`${pkg}:`))
        .sort((a, b) => {
          const am = a.name === pkg ? 0 : 1;
          const bm = b.name === pkg ? 0 : 1;
          if (am !== bm) return am - bm;
          return a.pid - b.pid;
        });
      const main = processes[0] || null;
      return {
        package: pkg,
        pid: main ? main.pid : null,
        user: main?.user || '',
        running: !!main,
        processes,
      };
    })
    .sort((a, b) => {
      if (a.running !== b.running) return a.running ? -1 : 1;
      return a.package.localeCompare(b.package);
    });
}

function parsePs(text) {
  const lines = String(text || '').split('\n').map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const header = lines[0].split(/\s+/);
  const col = (name) => header.findIndex((h) => h.toUpperCase() === name);
  const iPid = col('PID');
  const iName = col('NAME');
  if (iPid >= 0 && iName >= 0) {
    const iPpid = col('PPID');
    const iUser = col('USER');
    const iState = header.findIndex((h) => h === 'S' || h.toUpperCase() === 'STAT');
    const rows = [];
    for (const line of lines.slice(1)) {
      const parts = line.split(/\s+/);
      const pid = Number(parts[iPid]);
      if (!pid) continue;
      rows.push({
        pid,
        ppid: iPpid >= 0 ? Number(parts[iPpid]) || null : null,
        user: iUser >= 0 ? parts[iUser] || '' : '',
        state: iState >= 0 ? parts[iState] || '' : '',
        name: parts.slice(iName).join(' '),
      });
    }
    return rows;
  }
  const rows = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    let pid = null;
    const name = parts[parts.length - 1];
    if (/^\d+$/.test(parts[1])) pid = Number(parts[1]);
    else if (/^\d+$/.test(parts[0])) pid = Number(parts[0]);
    if (pid && name && name !== 'NAME' && name !== 'CMD') {
      rows.push({ pid, ppid: null, user: /^\d+$/.test(parts[0]) ? '' : parts[0], state: '', name });
    }
  }
  return rows;
}

/**
 * Open `localabstract:<name>` (goauld agent or droidmirror).
 * Several of these can stay open: one reader fans packets out by stream id.
 *
 * @returns {Promise<{ id: number, socket: string, write: Function, read: Function, close: Function }>}
 */
async function openAdbStream(destination) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  if (typeof adb.openStream !== 'function') {
    throw new Error('webadb openStream missing — rebuild pkg-webadb');
  }
  const dest = String(destination || '');
  const id = await enqueue(`open ${dest}`, () => adb.openStream(dest));
  if (typeof adb.readAny !== 'function') {
    try { await enqueue(`close ${dest}`, () => adb.closeStream(id)); } catch { /* ignore */ }
    throw new Error('webadb readAny missing — hard-reload so the new pkg-webadb is loaded');
  }
  const lane = { queue: [], waiters: [], closed: false };
  lanes.set(id, lane);
  // Do not start the demux pump here — only when someone calls read().

  const transport = {
    id,
    socket: dest,
    async write(data) {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      return enqueueControl(`write ${dest}`, () => adb.writeStream(id, bytes));
    },
    async read() {
      if (lane.queue.length) return lane.queue.shift();
      if (lane.closed) return new Uint8Array(0);
      return new Promise((resolve) => {
        lane.waiters.push(resolve);
        ensurePump();
      });
    },
    async close() {
      lane.closed = true;
      lanes.delete(id);
      while (lane.waiters.length) lane.waiters.shift()(new Uint8Array(0));
      try {
        await enqueueControl(`close ${dest}`, () => adb.closeStream(id));
      } catch {
        /* ignore */
      } finally {
        queueMicrotask(() => ensurePump());
      }
    },
  };
  return transport;
}

/**
 * Open `localabstract:<name>` (goauld agent or droidmirror).
 * Several of these can stay open: one reader fans packets out by stream id.
 */
export async function openAbstractStream(socketName) {
  const name = String(socketName || '').replace(/^localabstract:/, '');
  return openAdbStream(`localabstract:${name}`);
}

function appendBytes(buf, chunk) {
  const next = new Uint8Array(buf.length + chunk.length);
  next.set(buf);
  next.set(chunk, buf.length);
  return next;
}

/**
 * ADB shell v2 frames: [u8 id][u32 le len][payload].
 * id 1 = stdout, 2 = stderr, 3 = exit. A PTY makes injector stdout line-buffered.
 * Returns null if this buffer is not v2 (caller should treat bytes as raw text).
 */
function pullShellV2(state, chunk, onText) {
  state.buf = appendBytes(state.buf, chunk);
  if (!state.mode) {
    if (state.buf.length < 5) return;
    const id = state.buf[0];
    const len = new DataView(state.buf.buffer, state.buf.byteOffset, state.buf.byteLength).getUint32(1, true);
    state.mode = id <= 5 && len <= 1024 * 1024 ? 'v2' : 'raw';
    if (state.mode === 'raw') {
      onText(new TextDecoder().decode(state.buf));
      state.buf = new Uint8Array(0);
      return;
    }
  }
  if (state.mode === 'raw') {
    onText(new TextDecoder().decode(chunk));
    state.buf = new Uint8Array(0);
    return;
  }
  const decoder = new TextDecoder();
  while (state.buf.length >= 5) {
    const id = state.buf[0];
    const len = new DataView(state.buf.buffer, state.buf.byteOffset, state.buf.byteLength).getUint32(1, true);
    if (len > 1024 * 1024 || state.buf.length < 5 + len) break;
    const payload = state.buf.subarray(5, 5 + len);
    state.buf = state.buf.slice(5 + len);
    if ((id === 1 || id === 2) && payload.length) onText(decoder.decode(payload, { stream: true }));
  }
}

/**
 * Run a shell command and invoke `onLine` as soon as each line arrives.
 * Uses `shell,v2` (a PTY) so a block-buffered injector still flushes each line.
 */
export async function shellStream(command, { onLine, timeoutMs = 120000 } = {}) {
  const cmd = String(command || '');
  let transport;
  try {
    transport = await openAdbStream(`shell,v2:${cmd}`);
  } catch {
    transport = await openAdbStream(`shell:${cmd}`);
  }
  const decoder = new TextDecoder();
  let pending = '';
  let out = '';
  const v2 = { buf: new Uint8Array(0), mode: '' };
  const emit = (text) => {
    if (!text) return;
    out += text;
    if (!onLine) return;
    pending += text;
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() ?? '';
    for (const line of lines) onLine(line);
  };
  const timer = setTimeout(() => {
    transport.close().catch(() => {});
  }, timeoutMs);
  try {
    while (true) {
      const chunk = await transport.read();
      if (!chunk || !chunk.length) break;
      pullShellV2(v2, chunk, emit);
    }
    const tail = decoder.decode();
    if (tail) emit(tail);
    if (onLine && pending) onLine(pending);
  } finally {
    clearTimeout(timer);
    try { await transport.close(); } catch { /* already closed */ }
  }
  return out;
}

function wrapRoot(via, inner) {
  const quoted = shSingleQuote(inner);
  if (via === 'su -c') return `su -c ${quoted}`;
  if (via === 'su root') return `su root sh -c ${quoted}`;
  if (via === 'id' || via === 'sh' || via === 'sh (no su)') return `sh -c ${quoted}`;
  return `su 0 sh -c ${quoted}`;
}

/**
 * Attach to goauld agent for a PID (opens abstract socket, does not parse Hello).
 */
export async function openGoauldTransport(pid) {
  const { socketNameForPid } = await import('./goauld-protocol.js');
  return openAbstractStream(socketNameForPid(pid));
}

/**
 * Wait until pidof returns a pid for package (after launch / cold start).
 */
export async function waitForPackagePid(packageName, { timeoutMs = 20000, intervalMs = 400 } = {}) {
  const pkg = String(packageName || '').trim();
  if (!pkg) throw new Error('package name required');
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await pidOf(pkg);
    if (last) return String(last).trim();
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`timeout waiting for pid of ${pkg}${last ? '' : ' (not running)'}`);
}

/**
 * Open goauld abstract socket with retries — agent ctor may listen a bit after process start
 * (embedded ContentProvider / live inject).
 */
export async function openGoauldTransportRetry(pid, { attempts = 20, delayMs = 350 } = {}) {
  const { socketNameForPid } = await import('./goauld-protocol.js');
  const name = socketNameForPid(pid);
  let lastErr = null;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await openAbstractStream(name);
    } catch (e) {
      lastErr = e;
      releaseStreamExclusive();
      if (i < attempts) await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error(
    `agent not listening on localabstract:${name} after ${attempts} tries: ${lastErr?.message || lastErr}`,
  );
}

/** Single-quote for embedding in `sh -c '…'`. */
function shSingleQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/**
 * Deploy injector only (for syscall tracing — no agent .so required).
 * Verifies the remote binary is present and executable.
 */
export async function deployInjectorOnly(injectorBytes) {
  if (!injectorBytes?.length) throw new Error('goauld-injector bytes required');
  await adbShell(`mkdir -p ${DEVICE_DIR}`);
  await adbPush(injectorBytes, DEVICE_INJECTOR);
  await adbShell(`chmod 755 ${DEVICE_INJECTOR}`);
  const check = await adbShell(
    `ls -l ${DEVICE_INJECTOR}; test -x ${DEVICE_INJECTOR} && echo __GOAULD_INJECTOR_OK__`,
    15000,
  );
  if (!String(check).includes('__GOAULD_INJECTOR_OK__')) {
    throw new Error(`injector missing or not executable after push:\n${check}`);
  }
  return DEVICE_INJECTOR;
}

/**
 * Probe whether we can run as root via Magisk/su.
 * @returns {Promise<{ ok: boolean, via: string, out: string }>}
 */
export async function probeRoot() {
  const probes = [
    { via: 'su 0', cmd: 'su 0 id' },
    { via: 'su -c', cmd: "su -c 'id'" },
    { via: 'su root', cmd: 'su root id' },
    { via: 'id', cmd: 'id' },
  ];
  let last = '';
  for (const p of probes) {
    try {
      const out = String(await adbShell(p.cmd, 12000));
      last = out;
      if (/uid=0\b/.test(out)) return { ok: true, via: p.via, out };
    } catch (e) {
      last = String(e?.message || e);
    }
  }
  return { ok: false, via: '', out: last };
}

/**
 * Run a shell command as root. Tries Magisk-style `su 0`, then `su -c`, then bare.
 * Wraps with `timeout` when available so a hung ptrace cannot block forever
 * (webadb shell_with_timeout only checks between reads).
 *
 * @param {string} command
 * @param {number} [timeoutMs]
 * @param {{ via?: string }} [opts] Prefer a known-good root path from probeRoot().
 * @returns {Promise<{ out: string, via: string }>}
 */
export async function runAsRoot(command, timeoutMs = 60000, opts = {}) {
  const cmd = String(command || '').trim();
  if (!cmd) throw new Error('empty command');
  const budgetSec = Math.max(5, Math.ceil(timeoutMs / 1000) + 5);
  const inner = `${cmd}; echo __GOAULD_EXIT:$?`;
  const preferred = String(opts.via || '').trim();

  /** Prefer the probeRoot path first so a later failure (e.g. staging EACCES)
   * is not mistaken for "su failed" and retried without root. */
  const variants = [];
  const push = (via, shellCmd) => {
    if (!variants.some((v) => v.via === via)) variants.push({ via, cmd: shellCmd });
  };
  if (preferred === 'su 0' || preferred === 'su 0 + timeout' || !preferred) {
    push('su 0 + timeout', `timeout ${budgetSec} su 0 sh -c ${shSingleQuote(inner)}`);
    push('su 0', wrapRoot('su 0', inner));
  }
  if (preferred === 'su -c' || preferred === 'su -c + timeout' || !preferred) {
    push('su -c + timeout', `timeout ${budgetSec} su -c ${shSingleQuote(inner)}`);
    push('su -c', wrapRoot('su -c', inner));
  }
  if (preferred === 'su root' || !preferred) {
    push('su root', wrapRoot('su root', inner));
  }
  if (preferred === 'id' || preferred === 'sh' || preferred === 'sh (no su)') {
    push(preferred || 'sh (no su)', wrapRoot('sh', inner));
  } else if (!preferred) {
    push('timeout (no su)', `timeout ${budgetSec} sh -c ${shSingleQuote(inner)}`);
    push('sh (no su)', wrapRoot('sh', inner));
  }

  // If prefer was set, still keep a single fallback of the same family only —
  // never silently drop to non-root after a successful probeRoot.
  if (preferred && !/^(id|sh)/.test(preferred)) {
    // already pushed preferred family above
  }

  let lastOut = '';
  let lastVia = '';
  for (const v of variants) {
    try {
      const out = String(await adbShell(v.cmd, timeoutMs + 15000));
      lastOut = out;
      lastVia = v.via;
      // Skip variants where `timeout` itself is missing.
      if (/timeout:\s*not found|No such file.*timeout/i.test(out) && /timeout/.test(v.via)) {
        continue;
      }
      // Only skip when *su itself* failed to elevate — not when the command
      // printed Permission denied (e.g. staging into the app mount namespace).
      if (
        /(?:^|\n)\s*(?:\/system\/bin\/)?su:\s|not allowed to su|Can't get|No su|su: invalid|su: failed/i.test(
          out,
        ) &&
        !/__GOAULD_EXIT:/.test(out)
      ) {
        continue;
      }
      return { out, via: v.via };
    } catch (e) {
      lastOut = String(e?.message || e);
      lastVia = v.via;
    }
  }
  throw new Error(`root shell failed (${lastVia}): ${lastOut}`);
}

/**
 * On-device syscall trace via goauld-injector (root / su).
 * Pass either pid or packageName — not both (clap conflicts_with).
 * Caller should detach any agent abstract stream first.
 */
export async function traceSyscalls({
  pid,
  packageName,
  durationSecs = 15,
  maxEvents = 400,
  filter = '',
  enterOnly = false,
  via = 'su 0',
  onLine = null,
} = {}) {
  const secs = Number(durationSecs) || 15;
  const max = Number(maxEvents) || 400;
  // Prefer --pid when known (package lookup needs /proc walk as root anyway).
  let remote = `${DEVICE_INJECTOR} trace-syscalls --duration-secs ${secs} --max-events ${max}`;
  if (pid != null && pid !== '') {
    remote += ` --pid ${Number(pid)}`;
  } else if (packageName) {
    remote += ` --package ${String(packageName).trim()}`;
  } else {
    throw new Error('pass pid or packageName');
  }
  const filt = String(filter || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .join(',');
  if (filt) remote += ` --filter ${filt}`;
  if (enterOnly) remote += ' --enter-only';

  const inner = `${remote}; echo __GOAULD_EXIT:$?`;
  const cmd = wrapRoot(via, inner);
  const out = await shellStream(cmd, {
    timeoutMs: Math.max(30000, secs * 1000 + 25000),
    onLine,
  });
  return { out, via, command: remote };
}

export { DEVICE_DIR, DEVICE_INJECTOR, DEVICE_AGENT, TMP_APK };

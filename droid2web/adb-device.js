/**
 * WebUSB ADB (webadb-rs) helper for the Device tab (goauld attach / inject).
 * Single-flight op queue — the transport is not concurrency-safe.
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

let queue = Promise.resolve();
/** When a goauld abstract stream is open, shell/sync ops wait. */
let streamExclusive = false;
/** True while any long device op is running (syscall trace, inject, …). */
let deviceBusy = false;

/** Clear exclusive lock (e.g. after a failed attach that never got a session.close). */
export function releaseStreamExclusive() {
  streamExclusive = false;
}

export function isStreamExclusive() {
  return streamExclusive;
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
function enqueue(label, fn, { ignoreExclusive = false } = {}) {
  const run = queue.then(async () => {
    if (!ignoreExclusive) {
      while (streamExclusive) {
        await new Promise((r) => setTimeout(r, 40));
      }
    }
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

export function isWebUsbAvailable() {
  return typeof navigator !== 'undefined' && !!navigator.usb;
}

export function isAdbConnected() {
  return !!(adb && adb.is_connected && adb.is_connected());
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
  if (adb.is_connected()) {
    try {
      await adb.disconnect();
    } catch {
      /* ignore */
    }
  }
  deviceInfo = await adb.connectWithUsbDevice(usbDevice);
  return deviceInfo;
}

export async function disconnectAdb() {
  if (!adb) return;
  await enqueue('disconnect', async () => {
    await adb.disconnect();
    deviceInfo = null;
  });
}

export async function adbShell(cmd, timeoutMs = 60000) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  return enqueue(`shell ${cmd}`, async () => {
    if (typeof adb.shell_with_timeout === 'function') {
      return adb.shell_with_timeout(cmd, timeoutMs);
    }
    return adb.shell(cmd);
  });
}

export async function adbPush(bytes, remotePath) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return enqueue(`push ${remotePath}`, () => adb.push_file(data, remotePath));
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
 */
export async function injectGoauldLive({ packageName, pid, stageIntoApp = false } = {}) {
  let remote = `${DEVICE_INJECTOR} inject --so ${DEVICE_AGENT}`;
  if (pid != null && pid !== '') {
    remote += ` --pid ${Number(pid)}`;
  } else if (packageName) {
    remote += ` --package ${String(packageName).trim()}`;
  } else {
    throw new Error('pass packageName or pid');
  }
  if (stageIntoApp) remote += ' --stage-into-app';

  const { out, via } = await runAsRoot(remote, 120000);
  return `via ${via}\n${out}`;
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
 * List installed packages with best-effort PIDs from `ps -A`.
 * @returns {Promise<Array<{ package: string, pid: number|null, running: boolean }>>}
 */
export async function listAppsWithPids({ thirdPartyOnly = false } = {}) {
  const cmd = thirdPartyOnly ? 'pm list packages -3' : 'pm list packages';
  // Sequential — never Promise.all two Adb ops (aliasing / take races).
  const pkgOut = await adbShell(cmd, 90000);
  const psOut = await adbShell('ps -A', 60000).catch(() => '');
  const packages = String(pkgOut || '')
    .split('\n')
    .map((l) => l.replace(/^package:/, '').trim())
    .filter(Boolean);

  /** @type {Map<string, number>} */
  const pidByName = new Map();
  for (const line of String(psOut || '').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    // Formats vary: USER PID … NAME  OR  PID … NAME
    let pid = null;
    let name = parts[parts.length - 1];
    if (/^\d+$/.test(parts[1])) {
      pid = Number(parts[1]);
    } else if (/^\d+$/.test(parts[0])) {
      pid = Number(parts[0]);
    }
    if (pid && name && name !== 'NAME' && name !== 'CMD') {
      // Prefer first pid for a name (main process).
      if (!pidByName.has(name)) pidByName.set(name, pid);
    }
  }

  return packages
    .map((pkg) => {
      const pid = pidByName.get(pkg) ?? null;
      return { package: pkg, pid, running: pid != null };
    })
    .sort((a, b) => {
      if (a.running !== b.running) return a.running ? -1 : 1;
      return a.package.localeCompare(b.package);
    });
}

/**
 * Open `localabstract:<name>` for goauld protocol I/O.
 * Holds exclusive ADB access until `close()` — do not shell/push while attached.
 *
 * @returns {Promise<{ id: number, socket: string, write: Function, read: Function, close: Function }>}
 */
export async function openAbstractStream(socketName) {
  if (!isAdbConnected()) throw new Error('ADB not connected');
  if (typeof adb.openStream !== 'function') {
    throw new Error('webadb openStream missing — rebuild pkg-webadb');
  }
  const name = String(socketName || '').replace(/^localabstract:/, '');
  const dest = `localabstract:${name}`;

  const id = await enqueue(`open ${dest}`, () => adb.openStream(dest));
  streamExclusive = true;

  const transport = {
    id,
    socket: name,
    async write(data) {
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      // ignoreExclusive: stream owns the Adb slot while attached.
      return enqueue(`write ${dest}`, () => adb.writeStream(id, bytes), { ignoreExclusive: true });
    },
    async read() {
      return enqueue(`read ${dest}`, () => adb.readStream(id), { ignoreExclusive: true });
    },
    async close() {
      try {
        await enqueue(`close ${dest}`, () => adb.closeStream(id), { ignoreExclusive: true });
      } catch {
        /* ignore */
      } finally {
        streamExclusive = false;
      }
    },
  };
  return transport;
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
 * @returns {Promise<{ out: string, via: string }>}
 */
export async function runAsRoot(command, timeoutMs = 60000) {
  const cmd = String(command || '').trim();
  if (!cmd) throw new Error('empty command');
  const budgetSec = Math.max(5, Math.ceil(timeoutMs / 1000) + 5);
  const inner = `${cmd}; echo __GOAULD_EXIT:$?`;
  const quoted = shSingleQuote(inner);

  const variants = [
    { via: 'su 0 + timeout', cmd: `timeout ${budgetSec} su 0 sh -c ${quoted}` },
    { via: 'su 0', cmd: `su 0 sh -c ${quoted}` },
    { via: 'su -c + timeout', cmd: `timeout ${budgetSec} su -c ${quoted}` },
    { via: 'su -c', cmd: `su -c ${quoted}` },
    { via: 'timeout (no su)', cmd: `timeout ${budgetSec} sh -c ${quoted}` },
    { via: 'sh (no su)', cmd: `sh -c ${quoted}` },
  ];

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
      // Skip failed su / no-root attempts when we still have other variants.
      if (
        /(?:^|\n)\s*(?:\/system\/bin\/)?su:\s|Permission denied|not allowed to su|Can't get|No su|su: invalid/i.test(
          out,
        ) &&
        v.via !== 'sh (no su)'
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

  const timeoutMs = Math.max(90000, secs * 1000 + 45000);
  const { out, via } = await runAsRoot(remote, timeoutMs);
  return { out, via, command: remote };
}

export { DEVICE_DIR, DEVICE_INJECTOR, DEVICE_AGENT, TMP_APK };

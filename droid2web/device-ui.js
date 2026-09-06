/**
 * Dedicated Device tab — WebUSB ADB + goauld attach / protocol console.
 */

import * as adbDevice from './adb-device.js';
import {
  getBundledGoauldMeta,
  resolveGoauldBinary,
} from './goauld-assets.js';
import {
  DEFAULT_SMOKE_SCRIPT,
  GoauldSession,
  MsgType,
  socketNameForPid,
} from './goauld-protocol.js';
import { highlightGoauldScript } from './goauld-script-highlight.js';
import { SCRIPT_PRESETS, presetById, buildJavaApiTraceScript } from './goauld-script-presets.js';

let session = null;
let selectedPkg = null;
let apps = [];
let filterText = '';
let scriptHighlightRaf = 0;
let getApkBytes = () => null;
let getApkName = () => 'app.apk';
let getPackageHint = () => null;
let activePresetId = 'smoke';
let customScript = '';
let suppressScriptInput = false;
let consoleLineCount = 0;
/** UI source of truth for USB/ADB link (is_connected can lag during stream ops). */
let phoneLinked = false;
let phoneLabel = '';
let attachInFlight = false;

function $(id) {
  return document.getElementById(id);
}

function isPhoneConnected() {
  return phoneLinked || adbDevice.isAdbConnected();
}

function isAttached() {
  return !!(session && (session._alive || session.hello));
}

function setEnabled(id, on) {
  const el = $(id);
  if (el) el.disabled = !on;
}

function setStatus(msg, kind = '') {
  const el = $('device-status');
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('is-connected', 'is-busy', 'is-error', 'is-attached');
  if (kind === 'attached') el.classList.add('is-attached');
  else if (kind === 'ok' || kind === 'connected') el.classList.add('is-connected');
  else if (kind === 'busy') el.classList.add('is-busy');
  else if (kind === 'err' || kind === 'error') el.classList.add('is-error');
  else if (isAttached()) el.classList.add('is-attached');
  else if (isPhoneConnected() && !/not connected|failed|error|disconnected/i.test(String(msg))) {
    el.classList.add('is-connected');
  }
}

function updateLinkChips() {
  const phoneChip = $('device-phone-chip');
  const agentChip = $('device-agent-chip');
  const connected = isPhoneConnected();
  const attached = isAttached();

  if (phoneChip) {
    if (attachInFlight && connected) {
      phoneChip.dataset.state = 'busy';
      phoneChip.textContent = `Phone · connected${phoneLabel ? ` · ${phoneLabel}` : ''}`;
    } else if (connected) {
      phoneChip.dataset.state = 'on';
      phoneChip.textContent = `Phone · connected${phoneLabel ? ` · ${phoneLabel}` : ''}`;
    } else {
      phoneChip.dataset.state = 'off';
      phoneChip.textContent = 'Phone · disconnected';
    }
  }

  if (agentChip) {
    if (attachInFlight) {
      agentChip.dataset.state = 'busy';
      agentChip.textContent = 'Agent · attaching…';
    } else if (attached) {
      const hello = session?.hello;
      const pid = hello?.pid || ($('device-pid')?.value || '').trim() || '?';
      const pkg = hello?.package || ($('device-package')?.value || '').trim() || 'goauld';
      agentChip.dataset.state = 'on';
      agentChip.textContent = `Agent · attached · ${pkg} · pid ${pid}`;
    } else {
      agentChip.dataset.state = 'off';
      agentChip.textContent = 'Agent · not attached';
    }
  }
}

function logKindFromClass(cls) {
  if (!cls) return 'info';
  if (cls.includes('device-log-ok')) return 'ok';
  if (cls.includes('device-log-err')) return 'err';
  if (cls.includes('device-log-muted')) return 'sys';
  if (cls.includes('device-log-msg')) return 'msg';
  if (cls.includes('device-log-api')) return 'api';
  return 'info';
}

function formatLogTime(d = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function updateConsoleChrome() {
  const countEl = $('device-console-count');
  if (countEl) countEl.textContent = String(consoleLineCount);
  const empty = $('device-console-empty');
  const consoleEl = $('device-console');
  const has = consoleLineCount > 0;
  if (empty) empty.hidden = has;
  if (consoleEl) consoleEl.hidden = !has;
}

function log(msg, cls = '') {
  const el = $('device-console');
  if (!el) return;
  const kind = logKindFromClass(cls);
  const row = document.createElement('div');
  row.className = `device-log device-log-${kind}${cls ? ` ${cls}` : ''}`;

  const time = document.createElement('span');
  time.className = 'device-log-time';
  time.textContent = formatLogTime();

  const tag = document.createElement('span');
  tag.className = 'device-log-tag';
  tag.textContent = kind;

  const body = document.createElement('span');
  body.className = 'device-log-body';
  body.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg);

  row.append(time, tag, body);
  el.appendChild(row);
  consoleLineCount += 1;
  updateConsoleChrome();

  const follow = $('device-console-autoscroll')?.checked !== false;
  if (follow) el.scrollTop = el.scrollHeight;
}

function clearConsole() {
  const el = $('device-console');
  if (el) el.replaceChildren();
  consoleLineCount = 0;
  updateConsoleChrome();
}

function syncWorkflowUi() {
  // Embedded-agent APKs: prefer manifest package so Attach is ready without picking the apps list.
  if (isPhoneConnected()) ensureEmbeddedAgentTarget();

  const connected = isPhoneConnected();
  const attached = isAttached();
  const busy = attachInFlight || !!adbDevice.isDeviceBusy?.();
  const pkg = ($('device-package')?.value || '').trim() || selectedPkg;
  const pid = ($('device-pid')?.value || '').trim();
  const hasTarget = !!(pkg || pid);
  const hasAnalyzedApk = !!getApkBytes?.()?.length;
  const analyzedPkg = (getPackageHint?.() || '').trim();

  updateLinkChips();

  const panel = $('device-panel');
  panel?.classList.toggle('is-connected', connected);
  panel?.classList.toggle('is-attached', attached);
  panel?.classList.toggle('is-busy', busy);

  const scriptCard = $('device-card-script');
  scriptCard?.classList.toggle('is-gated', connected && !attached);
  scriptCard?.classList.toggle('is-live', attached);

  const gate = $('device-script-gate');
  if (gate) {
    if (attached) {
      const hello = session?.hello;
      gate.textContent = `Live · pid ${hello?.pid || pid || '?'}`;
      gate.className = 'device-gate-hint is-live';
    } else if (connected) {
      gate.textContent = 'Attach agent first';
      gate.className = 'device-gate-hint';
    } else {
      gate.textContent = 'Connect phone first';
      gate.className = 'device-gate-hint';
    }
  }

  const chip = $('device-attach-chip');
  if (chip) {
    if (attached) {
      const hello = session?.hello;
      chip.textContent = `Attached · ${hello?.package || pkg || 'agent'} · pid ${hello?.pid || pid || '?'}`;
      chip.className = 'device-attach-chip is-on';
    } else if (connected && hasTarget) {
      chip.textContent = 'Ready to attach (embedded agent)';
      chip.className = 'device-attach-chip is-ready';
    } else {
      chip.textContent = 'Not attached';
      chip.className = 'device-attach-chip';
    }
  }

  const analyzedHint = $('device-analyzed-hint');
  if (analyzedHint) {
    if (analyzedPkg) {
      analyzedHint.hidden = false;
      analyzedHint.textContent = `Analyzed APK package: ${analyzedPkg}`;
    } else if (hasAnalyzedApk) {
      analyzedHint.hidden = false;
      analyzedHint.textContent = 'APK loaded — waiting for manifest package…';
    } else {
      analyzedHint.hidden = true;
      analyzedHint.textContent = '';
    }
  }

  // Workflow stepper
  const steps = {
    connect: connected,
    target: connected && hasTarget,
    attach: attached,
    act: attached,
  };
  let current = 'connect';
  if (!connected) current = 'connect';
  else if (!hasTarget) current = 'target';
  else if (!attached) current = 'attach';
  else current = 'act';
  $('device-flow')?.querySelectorAll('.device-flow-step').forEach((li) => {
    const key = li.dataset.step;
    li.classList.toggle('is-done', !!steps[key] && key !== current);
    li.classList.toggle('is-current', key === current);
  });

  setEnabled('device-connect', !busy);
  setEnabled('device-disconnect', connected && !busy);
  setEnabled('device-refresh-apps', connected && !busy);
  setEnabled('device-third-party', connected);
  setEnabled('device-install-apk', connected && !busy);
  setEnabled('device-launch', connected && hasTarget && !busy);
  setEnabled('device-stop', connected && hasTarget && !busy);
  // Live inject is optional (root). Attach is the primary path for embedded-agent APKs.
  setEnabled('device-inject', connected && hasTarget && !busy);
  setEnabled('device-trace-java', connected && hasTarget && !busy);
  setEnabled('device-trace-syscalls', connected && hasTarget && !busy);

  const attachBtn = $('device-attach');
  if (attachBtn) {
    const canAttach = connected && hasTarget && !busy;
    attachBtn.classList.toggle('is-attached', attached);
    attachBtn.classList.toggle('is-ready', canAttach && !attached);
    attachBtn.disabled = !canAttach;
    // Promote Attach as the main CTA for embedded-agent workflow.
    attachBtn.classList.toggle('btn-primary', canAttach && !attached);
    attachBtn.classList.toggle('btn-small', !(canAttach && !attached));
    if (attachInFlight) {
      attachBtn.textContent = 'Attaching…';
      attachBtn.title = 'Opening goauld agent socket…';
    } else if (adbDevice.isDeviceBusy?.()) {
      attachBtn.textContent = 'Attach agent';
      attachBtn.title = 'Wait for the current device op (syscall / inject) to finish';
    } else if (attached) {
      attachBtn.textContent = 'Re-attach';
      attachBtn.title = 'Detach and attach again to the current target';
    } else if (!connected) {
      attachBtn.textContent = 'Attach agent';
      attachBtn.title = 'Connect the phone first';
    } else if (!hasTarget) {
      attachBtn.textContent = 'Attach agent';
      attachBtn.title = 'Select an app or open an APK with a manifest package, then Attach';
    } else {
      attachBtn.textContent = 'Attach agent';
      attachBtn.title =
        'App already embeds goauld? Launch it and Attach. Stock apps (Calculator, …) need Live inject (root) first.';
    }
  }

  const detachBtn = $('device-detach');
  if (detachBtn) {
    detachBtn.disabled = !attached || busy;
    detachBtn.classList.toggle('is-active', attached);
  }

  // Protocol actions require an active attach
  for (const id of ['device-script-load', 'device-script-load-run', 'device-rpc-call', 'device-post']) {
    const el = $(id);
    if (!el) continue;
    el.disabled = !attached || busy;
    el.classList.toggle('is-live', attached);
    el.classList.toggle('needs-attach', connected && !attached);
  }
}

/** @deprecated use syncWorkflowUi */
function setConnectedUi(on) {
  if (!on) {
    // force-clear attach visuals when disconnecting
  }
  syncWorkflowUi();
}

function formatMsg(msg) {
  if (msg.type === MsgType.Hello) {
    return {
      text: `Hello pid=${msg.json?.pid} pkg=${msg.json?.package} abi=${msg.json?.abi} sdk=${msg.json?.sdk_int}`,
      cls: 'device-log-ok',
    };
  }
  if (msg.type === MsgType.Log) {
    return {
      text: `Log[${msg.json?.level || '?'}] ${msg.json?.message || ''}`,
      cls: 'device-log-muted',
    };
  }
  if (msg.type === MsgType.Send) {
    let payload = msg.payload_json;
    try {
      const parsed = typeof payload === 'string' ? JSON.parse(payload) : payload;
      if (parsed && typeof parsed === 'object') {
        if (parsed.type === 'android-api') {
          const cls = parsed.class || parsed.declaring_class || '';
          const method = parsed.method || parsed.name || '';
          const args = parsed.args != null ? JSON.stringify(parsed.args) : '';
          return {
            text: `${cls}.${method}${args ? ' ' + args : ''}`,
            cls: 'device-log-api',
          };
        }
        if (parsed.type === 'android-api-err' || parsed.type === 'java-api-err') {
          return {
            text: `${parsed.type}: ${parsed.err || JSON.stringify(parsed)}`,
            cls: 'device-log-err',
          };
        }
        if (parsed.type === 'trace-java-ready') {
          return {
            text: `trace-java-ready hook=${parsed.art_invoke_hook} filter=${parsed.filter}`,
            cls: 'device-log-ok',
          };
        }
        return { text: `Send ${JSON.stringify(parsed)}`, cls: 'device-log-msg' };
      }
    } catch {
      /* plain string payload */
    }
    return { text: `Send script=${msg.script_id} ${payload}`, cls: 'device-log-msg' };
  }
  if (msg.type === MsgType.RpcReply) {
    const err = msg.json?.error;
    return {
      text: `RpcReply id=${msg.json?.call_id} ${err ? 'ERR ' + err : msg.json?.result_json}`,
      cls: err ? 'device-log-err' : 'device-log-ok',
    };
  }
  return { text: `${msg.name}: ${JSON.stringify(msg.json ?? msg)}`, cls: 'device-log-msg' };
}

function logProtocolMsg(msg) {
  const formatted = formatMsg(msg);
  log(formatted.text, formatted.cls);
}

function renderApps() {
  const ul = $('device-app-list');
  if (!ul) return;
  ul.innerHTML = '';
  const f = filterText.toLowerCase();
  const list = apps.filter((a) => !f || a.package.toLowerCase().includes(f));
  for (const app of list) {
    const li = document.createElement('li');
    li.className = 'device-app-item' + (selectedPkg === app.package ? ' active' : '');
    li.dataset.package = app.package;
    li.innerHTML =
      `<span class="device-app-name">${escapeHtml(app.package)}</span>` +
      `<span class="device-app-meta">${app.running ? `pid ${app.pid}` : 'stopped'}</span>`;
    li.addEventListener('click', () => {
      selectedPkg = app.package;
      const pkgInput = $('device-package');
      if (pkgInput) pkgInput.value = app.package;
      const pidInput = $('device-pid');
      if (pidInput) pidInput.value = app.pid != null ? String(app.pid) : '';
      renderApps();
      syncWorkflowUi();
      setStatus(`${app.package}${app.pid != null ? ` · pid ${app.pid}` : ''}`, 'ok');
    });
    ul.appendChild(li);
  }
  if (!list.length) {
    ul.innerHTML = '<li class="muted">No packages</li>';
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function connect() {
  try {
    if (!adbDevice.isWebUsbAvailable()) {
      setStatus('WebUSB unavailable (Chrome/Edge + localhost/HTTPS)', 'err');
      return;
    }
    setStatus('Connecting… authorize on phone', 'busy');
    const info = await adbDevice.connectAdb();
    phoneLinked = true;
    phoneLabel = String(info?.serial || info?.product || info?.model || '').trim();
    applyPackageHint({ force: false });
    syncWorkflowUi();
    setStatus(`Phone connected${phoneLabel ? ` · ${phoneLabel}` : ''}`, 'ok');
    log(`Phone connected ${JSON.stringify(info)}`, 'device-log-ok');
    await refreshApps();
    applyPackageHint({ force: false });
    syncWorkflowUi();
    if (currentPackage()) {
      setStatus(`Phone connected — Attach ready for ${currentPackage()}`, 'ok');
    }
  } catch (e) {
    phoneLinked = false;
    phoneLabel = '';
    syncWorkflowUi();
    setStatus(`Connect failed: ${e.message || e}`, 'err');
    log(String(e.message || e), 'device-log-err');
  }
}

async function disconnect() {
  await detachSession();
  try {
    await adbDevice.disconnectAdb();
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
  }
  phoneLinked = false;
  phoneLabel = '';
  adbDevice.releaseStreamExclusive?.();
  syncWorkflowUi();
  setStatus('Phone disconnected', '');
  apps = [];
  renderApps();
  log('Phone disconnected', 'device-log-muted');
}

async function refreshApps() {
  try {
    setStatus('Listing packages…', 'busy');
    const third = $('device-third-party')?.checked ?? false;
    apps = await adbDevice.listAppsWithPids({ thirdPartyOnly: third });
    applyPackageHint({ force: false });
    renderApps();
    const running = apps.filter((a) => a.running).length;
    setStatus(`${apps.length} packages · ${running} running`, 'ok');
    syncWorkflowUi();
  } catch (e) {
    setStatus(`List failed: ${e.message || e}`, 'err');
    log(String(e.message || e), 'device-log-err');
  }
}

function currentPackage() {
  return ($('device-package')?.value || selectedPkg || '').trim();
}

function currentPid() {
  const v = ($('device-pid')?.value || '').trim();
  if (v) {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : null;
  }
  const app = apps.find((a) => a.package === currentPackage());
  return app?.pid ?? null;
}

async function launchSelected() {
  const pkg = currentPackage();
  if (!pkg) return setStatus('Select a package');
  try {
    log(await adbDevice.launchPackage(pkg));
    await new Promise((r) => setTimeout(r, 800));
    await refreshApps();
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
  }
}

async function stopSelected() {
  const pkg = currentPackage();
  if (!pkg) return setStatus('Select a package');
  try {
    log(await adbDevice.forceStopPackage(pkg));
    await refreshApps();
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
  }
}

function applyPackageHint({ force = false } = {}) {
  const hint = (getPackageHint?.() || '').trim() || null;
  const input = $('device-package');
  if (hint && input && (force || !input.value.trim())) {
    input.value = hint;
    selectedPkg = hint;
  }
  // If this package is already running on the phone, fill PID for Attach.
  const pkg = (input?.value || selectedPkg || hint || '').trim();
  if (pkg && apps.length) {
    const app = apps.find((a) => a.package === pkg);
    const pidInput = $('device-pid');
    if (app?.pid != null && pidInput && (!pidInput.value.trim() || force)) {
      pidInput.value = String(app.pid);
    }
  }
  return hint || currentPackage();
}

/**
 * Keep target filled from the APK open in the analyzer (embedded-agent flow).
 * Attach must not stay disabled just because the user has not clicked the apps list.
 */
function ensureEmbeddedAgentTarget() {
  const before = currentPackage();
  applyPackageHint({ force: false });
  const after = currentPackage();
  if (after && after !== before) {
    log(`Target from analyzed APK: ${after}`, 'device-log-muted');
  }
  return after;
}

async function installAnalyzedApk() {
  if (!adbDevice.isAdbConnected()) return setStatus('Connect a phone first');
  const bytes = getApkBytes?.();
  if (!bytes?.length) {
    setStatus('No APK loaded in the analyzer — open an APK first');
    log('Load an APK in the main view, then Install analyzed APK', 'device-log-err');
    return;
  }
  const name = getApkName?.() || 'app.apk';
  try {
    applyPackageHint();
    setStatus(`Installing ${name} (${bytes.length} bytes)…`);
    log(`pm install ← ${name} (${bytes.length} bytes)`);
    const out = await adbDevice.installApk(bytes);
    log(out || 'Success', 'device-log-ok');
    const pkg = applyPackageHint() || currentPackage();
    if (pkg && $('device-install-launch')?.checked) {
      await adbDevice.adbLogcatClear().catch(() => {});
      log(await adbDevice.launchPackage(pkg));
      await new Promise((r) => setTimeout(r, 800));
    }
    await refreshApps();
    applyPackageHint({ force: true });
    syncWorkflowUi();
    setStatus(pkg ? `Installed ${pkg} — Attach agent when ready` : `Installed ${name}`, 'ok');
    if (pkg) log(`Embedded agent flow: Launch (if needed) → Attach agent`, 'device-log-ok');
  } catch (e) {
    setStatus(`Install failed: ${e.message || e}`);
    log(String(e.message || e), 'device-log-err');
  }
}

function syncScriptHighlight() {
  const editor = $('device-script');
  const pre = $('device-script-highlight');
  if (!editor || !pre) return;
  pre.innerHTML = highlightGoauldScript(editor.value || '') + '\n';
  pre.scrollTop = editor.scrollTop;
  pre.scrollLeft = editor.scrollLeft;
}

function scheduleScriptHighlight() {
  if (scriptHighlightRaf) cancelAnimationFrame(scriptHighlightRaf);
  scriptHighlightRaf = requestAnimationFrame(() => {
    scriptHighlightRaf = 0;
    syncScriptHighlight();
  });
}

async function injectSelected() {
  const pkg = currentPackage();
  if (!pkg) return setStatus('Select a package', 'err');
  if (!isPhoneConnected()) return setStatus('Connect the phone first', 'err');
  if (adbDevice.isDeviceBusy?.()) {
    return setStatus('Device busy — wait for the current op to finish', 'err');
  }
  try {
    adbDevice.setDeviceBusy?.(true);
    syncWorkflowUi();
    if (session) {
      log('Detaching agent stream before live inject…', 'device-log-muted');
      await detachSession();
    }
    setStatus('Checking root (su)…', 'busy');
    const root = await adbDevice.probeRoot();
    if (!root.ok) {
      setStatus('No root — Magisk/su required for live inject', 'err');
      log(String(root.out || 'no uid=0').slice(0, 1500), 'device-log-err');
      return;
    }
    log(`Root OK via ${root.via}`, 'device-log-ok');

    setStatus('Loading goauld binaries…', 'busy');
    const inj = await resolveGoauldBinary($('device-injector-file'), 'injector');
    const agent = await resolveGoauldBinary($('device-agent-file'), 'agent');
    const usedOverride = !!(
      $('device-injector-file')?.files?.[0] || $('device-agent-file')?.files?.[0]
    );
    log(
      usedOverride
        ? `Deploy (override files) injector=${inj.length}B agent=${agent.length}B`
        : `Deploy bundled arm64 injector=${inj.length}B agent=${agent.length}B`,
    );
    setStatus('Deploying binaries…', 'busy');
    await adbDevice.deployGoauld(inj, agent);
    setStatus(`Injecting into ${pkg}…`, 'busy');
    const out = await adbDevice.injectGoauldLive({ packageName: pkg, stageIntoApp: true });
    log(String(out || '').slice(0, 8000), 'device-log-ok');
    await new Promise((r) => setTimeout(r, 1200));
    const pid = await adbDevice.pidOf(pkg);
    if (pid) {
      if ($('device-pid')) $('device-pid').value = pid;
      log(`pid ${pid} — agent should be listening; click Attach agent`, 'device-log-ok');
    }
    await refreshApps();
    setStatus('Inject done — click Attach agent', 'ok');
  } catch (e) {
    setStatus(`Inject failed: ${e.message || e}`, 'err');
    log(String(e.message || e), 'device-log-err');
  } finally {
    adbDevice.setDeviceBusy?.(false);
    syncWorkflowUi();
  }
}

async function detachSession() {
  if (!session) {
    adbDevice.releaseStreamExclusive?.();
    syncWorkflowUi();
    return;
  }
  const s = session;
  session = null;
  try {
    await s.close();
  } catch {
    /* ignore */
  } finally {
    adbDevice.releaseStreamExclusive?.();
  }
  log('Detached', 'device-log-muted');
  syncWorkflowUi();
  if (isPhoneConnected()) setStatus('Agent detached — Attach again for ScriptLoad', 'ok');
}

async function attachSelected() {
  if (attachInFlight) return false;
  if (!isPhoneConnected()) {
    setStatus('Connect the phone first', 'err');
    return false;
  }
  if (adbDevice.isDeviceBusy?.()) {
    setStatus('Device busy — wait for syscall trace / inject to finish', 'err');
    return false;
  }

  const pkg = currentPackage();
  let pid = currentPid();
  const doLaunch = $('device-attach-launch')?.checked ?? true;
  const doRetry = $('device-attach-retry')?.checked ?? true;
  let transport = null;

  attachInFlight = true;
  syncWorkflowUi();

  try {
    if (!pkg && !pid) {
      setStatus('Select a package (or enter PID), then Attach', 'err');
      return false;
    }

    if (pkg && doLaunch) {
      const running = pid || (await adbDevice.pidOf(pkg).catch(() => null));
      if (!running) {
        setStatus(`Launching ${pkg}…`, 'busy');
        log(`Launch ${pkg} (embedded agent needs a live process)`, 'device-log-muted');
        await adbDevice.launchPackage(pkg);
        setStatus(`Waiting for pid of ${pkg}…`, 'busy');
        pid = await adbDevice.waitForPackagePid(pkg, { timeoutMs: 20000 });
      } else {
        pid = running;
        log(`Process already running (pid ${running})`, 'device-log-muted');
      }
      if ($('device-pid')) $('device-pid').value = String(pid);
    } else if (!pid && pkg) {
      pid = await adbDevice.pidOf(pkg);
      if (!pid) {
        setStatus('App not running — enable “Launch before attach” or start it manually', 'err');
        return false;
      }
      if ($('device-pid')) $('device-pid').value = String(pid);
    }

    pid = Number(pid);
    if (!Number.isFinite(pid) || pid <= 0) {
      setStatus('Need a running PID', 'err');
      return false;
    }

    if (session?.hello && Number(session.hello.pid) === pid && session._alive) {
      setStatus(`Already attached · pid ${pid}`, 'attached');
      return true;
    }

    await detachSession();
    setStatus(`Attaching to ${socketNameForPid(pid)}…`, 'busy');
    log(`OPEN localabstract:${socketNameForPid(pid)}${doRetry ? ' (retry)' : ''}`, 'device-log-muted');

    transport = doRetry
      ? await adbDevice.openGoauldTransportRetry(pid, { attempts: 24, delayMs: 350 })
      : await adbDevice.openGoauldTransport(pid);

    session = new GoauldSession(transport, {
      onMessage: (msg) => logProtocolMsg(msg),
      onClose: (err) => {
        log(`Session closed: ${err?.message || err || 'ok'}`, 'device-log-muted');
        session = null;
        adbDevice.releaseStreamExclusive?.();
        syncWorkflowUi();
        setStatus('Agent session closed — Attach again', 'ok');
      },
    });
    transport = null; // owned by session now

    const hello = await session.attach();
    if (!session._alive) session._alive = true;
    if (!session.hello && hello) session.hello = hello;

    if (hello?.package && $('device-package') && !$('device-package').value.trim()) {
      $('device-package').value = hello.package;
    }
    setStatus(`Agent attached · pid ${hello?.pid || pid} · ${hello?.package || pkg || ''}`, 'attached');
    log('Agent Hello OK — ScriptLoad / Rpc / Post unlocked', 'device-log-ok');
    return true;
  } catch (e) {
    if (session) {
      await detachSession();
    } else if (transport) {
      try {
        await transport.close();
      } catch {
        /* ignore */
      }
      adbDevice.releaseStreamExclusive?.();
    } else {
      adbDevice.releaseStreamExclusive?.();
    }
    setStatus(`Attach failed: ${e.message || e}`, 'err');
    log(String(e.message || e), 'device-log-err');
    const msg = String(e.message || e);
    if (/recursive use|aliasing/i.test(msg)) {
      log(
        'ADB was busy (e.g. syscall trace still running). Wait for it to finish, then retry. Stock apps like Calculator need Live inject (root), not Attach.',
        'device-log-muted',
      );
    } else if (/not listening|open |CLOSED|connection refused/i.test(msg)) {
      log(
        `${pkg || 'This app'} has no goauld agent listening. Use Live inject (root) below, or install an APK that already embeds the agent and then Attach.`,
        'device-log-muted',
      );
      const adv = document.querySelector('.device-advanced');
      if (adv) adv.open = true;
    } else {
      log(
        'Embedded-agent apps: install/launch → Attach. Apps without the agent (e.g. Calculator): expand Live inject → Deploy + inject (root).',
        'device-log-muted',
      );
    }
    return false;
  } finally {
    attachInFlight = false;
    syncWorkflowUi();
  }
}

async function ensureAttached() {
  if (isAttached()) return true;
  return attachSelected();
}

async function traceJavaApi() {
  if (!isPhoneConnected()) return setStatus('Connect the phone first', 'err');
  const maxEvents = Math.max(1, Math.min(500, Number($('device-trace-max-events')?.value) || 40));
  const filter = ($('device-trace-api-filter')?.value || '').trim();
  try {
    setStatus('Attaching to embedded agent…', 'busy');
    const ok = await ensureAttached();
    if (!ok || !session) return;
    syncWorkflowUi();

    const source = buildJavaApiTraceScript({ filter, maxEvents: 0 });
    selectPreset('java-api', { force: true });
    const editor = $('device-script');
    if (editor) {
      editor.value = source;
      scheduleScriptHighlight();
    }

    setStatus('Installing Java/Android API tracer…');
    log(`ScriptLoad java-api trace (collect ${maxEvents} events) — use the app on the phone`, 'device-log-ok');
    await session.loadScript(source);
    await new Promise((r) => setTimeout(r, 300));
    await session.drain({ maxMessages: 4, untilAgentMessage: true });

    setStatus(`Collecting up to ${maxEvents} API events — interact with the app…`);
    let apiCount = 0;
    const frames = await session.collectMessages({
      maxMessages: maxEvents,
      onFrame: (msg, n, max) => {
        if (msg.type === MsgType.Send) {
          try {
            const p = JSON.parse(msg.payload_json);
            if (p?.type === 'android-api') apiCount++;
          } catch {
            /* ignore */
          }
        }
        setStatus(`Collecting… ${n}/${max} frames (${apiCount} android-api)`);
      },
    });
    setStatus(`Done — ${frames.length} frames · ${apiCount} android-api events`);
    log(`Trace finished: ${frames.length} frames, ${apiCount} android-api`, 'device-log-ok');
  } catch (e) {
    setStatus(`Java trace failed: ${e.message || e}`);
    log(String(e.message || e), 'device-log-err');
  }
}

async function traceSyscallsBtn() {
  if (!isPhoneConnected()) return setStatus('Connect the phone first', 'err');
  if (adbDevice.isDeviceBusy?.()) {
    return setStatus('Device busy — wait for the current op to finish', 'err');
  }
  const pkg = currentPackage();
  let pid = currentPid();
  const secs = Math.max(3, Math.min(120, Number($('device-trace-secs')?.value) || 15));
  const maxEvents = Math.max(
    1,
    Math.min(5000, Number($('device-trace-sys-max')?.value || $('device-trace-max-events')?.value) || 400),
  );
  const filter = ($('device-trace-sys-filter')?.value || '').trim();
  const enterOnly = !!$('device-trace-enter-only')?.checked;

  try {
    adbDevice.setDeviceBusy?.(true);
    syncWorkflowUi();
    if (session) {
      log('Detaching agent stream (syscall trace needs exclusive ADB + ptrace)…', 'device-log-muted');
      await detachSession();
      syncWorkflowUi();
    }
    if (!pid && pkg) {
      pid = await adbDevice.pidOf(pkg);
      if (!pid) {
        log(`Launching ${pkg}…`);
        await adbDevice.launchPackage(pkg);
        pid = await adbDevice.waitForPackagePid(pkg);
      }
      if ($('device-pid')) $('device-pid').value = String(pid);
    }
    if (!pid && !pkg) {
      setStatus('Select a package or PID for syscall trace', 'err');
      return;
    }

    setStatus('Checking root (su)…', 'busy');
    const root = await adbDevice.probeRoot();
    if (!root.ok) {
      log(String(root.out || 'no uid=0').slice(0, 2000), 'device-log-err');
      setStatus('No root — Magisk/su required for syscall trace', 'err');
      log(
        'Syscall tracing uses goauld-injector + PTRACE_SYSCALL. Grant root to the adb shell (Magisk: enable for shell), then retry.',
        'device-log-muted',
      );
      return;
    }
    log(`Root OK via ${root.via}: ${String(root.out).trim().split('\n').pop()}`, 'device-log-ok');

    setStatus('Deploying injector…', 'busy');
    const inj = await resolveGoauldBinary($('device-injector-file'), 'injector');
    await adbDevice.deployInjectorOnly(inj);
    log(`Pushed injector (${inj.byteLength || inj.length || '?'} bytes)`, 'device-log-muted');

    setStatus(`Tracing syscalls ${secs}s · max ${maxEvents} — use the app…`, 'busy');
    log(
      `trace-syscalls --pid ${pid || '(pkg)'} --duration-secs ${secs} --max-events ${maxEvents}` +
        (filter ? ` --filter ${filter}` : '') +
        (enterOnly ? ' --enter-only' : ''),
      'device-log-ok',
    );
    const result = await adbDevice.traceSyscalls({
      pid: pid || undefined,
      packageName: pid ? undefined : pkg,
      durationSecs: secs,
      maxEvents,
      filter,
      enterOnly,
    });
    const out = typeof result === 'string' ? result : result?.out || '';
    const via = typeof result === 'object' ? result.via : '';
    if (via) log(`ran via ${via}`, 'device-log-muted');
    log(String(out || '(empty)').slice(0, 12000));

    const exitMatch = String(out).match(/__GOAULD_EXIT:(\d+)/);
    const exitCode = exitMatch ? Number(exitMatch[1]) : null;
    const failed =
      (exitCode != null && exitCode !== 0) ||
      /goauld-injector error:|Permission denied|Operation not permitted|ptrace/i.test(out);

    if (failed) {
      setStatus(`Syscall trace failed${exitCode != null ? ` (exit ${exitCode})` : ''}`, 'err');
      log('Check Magisk grant, SELinux, and that the target PID is still alive.', 'device-log-muted');
    } else {
      const okLine = String(out)
        .split('\n')
        .map((l) => l.trim())
        .find((l) => /^OK traced\b/i.test(l));
      setStatus(okLine || 'Syscall trace finished', 'ok');
    }
  } catch (e) {
    setStatus(`Syscall trace failed: ${e.message || e}`, 'err');
    log(String(e.message || e), 'device-log-err');
  } finally {
    adbDevice.setDeviceBusy?.(false);
    syncWorkflowUi();
  }
}

async function loadScript() {
  if (!isAttached()) {
    setStatus('Attach agent first — then ScriptLoad', 'err');
    log('ScriptLoad blocked: no agent session', 'device-log-err');
    return null;
  }
  const source = $('device-script')?.value || DEFAULT_SMOKE_SCRIPT;
  try {
    const id = await session.loadScript(source);
    log(`ScriptLoad id=${id} (${activePresetId})`, 'device-log-ok');
    setStatus(`Script ${id} loaded`, 'attached');
    return id;
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
    return null;
  }
}

async function loadScriptAndWatch() {
  const id = await loadScript();
  if (id == null) return;
  // Give the agent a moment to run (toast / send) before reading — avoids overlapping ADB ops.
  log('Waiting briefly for agent Send…', 'device-log-muted');
  await new Promise((r) => setTimeout(r, 400));
  try {
    // Read a handful of frames (toast sends one). Stops after maxMessages.
    const msgs = await session.drain({ maxMessages: 8 });
    if (!msgs.length) log('(no frames yet — try again or check logcat)', 'device-log-muted');
    else setStatus(`Received ${msgs.length} frame(s)`);
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
  }
}

function renderScriptTabs() {
  const bar = $('device-script-tabs');
  if (!bar) return;
  bar.innerHTML = '';
  for (const p of SCRIPT_PRESETS) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'device-script-tab' + (p.id === activePresetId ? ' active' : '');
    btn.textContent = p.label;
    btn.title = p.title || p.label;
    btn.dataset.preset = p.id;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', p.id === activePresetId ? 'true' : 'false');
    btn.addEventListener('click', () => selectPreset(p.id));
    bar.appendChild(btn);
  }
}

function selectPreset(id, { force = false } = {}) {
  const editor = $('device-script');
  if (!editor) return;
  const next = presetById(id);
  if (!next) return;

  if (!force && activePresetId === 'custom' && id !== 'custom') {
    customScript = editor.value;
  } else if (!force && activePresetId !== 'custom' && id !== activePresetId) {
    // leaving a preset after edits → keep in custom automatically if changed
    const prev = presetById(activePresetId);
    if (prev && editor.value !== prev.source && id !== 'custom') {
      customScript = editor.value;
    }
  }

  activePresetId = id;
  suppressScriptInput = true;
  if (id === 'custom') {
    editor.value = customScript || DEFAULT_SMOKE_SCRIPT;
  } else {
    editor.value = next.source;
  }
  suppressScriptInput = false;
  renderScriptTabs();
  scheduleScriptHighlight();
}

function onScriptEdited() {
  if (suppressScriptInput) return;
  if (activePresetId !== 'custom') {
    const prev = presetById(activePresetId);
    if (prev && $('device-script')?.value !== prev.source) {
      customScript = $('device-script').value;
      activePresetId = 'custom';
      renderScriptTabs();
    }
  } else {
    customScript = $('device-script')?.value || '';
  }
  scheduleScriptHighlight();
}

async function rpcCall() {
  if (!isAttached()) return setStatus('Attach agent first', 'err');
  const fn = ($('device-rpc-fn')?.value || 'ping').trim();
  let args = [];
  const raw = ($('device-rpc-args')?.value || '[]').trim();
  try {
    args = JSON.parse(raw || '[]');
  } catch (e) {
    return setStatus(`Invalid args JSON: ${e.message}`, 'err');
  }
  try {
    setStatus(`RPC ${fn}…`, 'busy');
    const result = await session.rpcCall(fn, args);
    log(`← ${fn} → ${result}`, 'device-log-ok');
    setStatus('RPC ok', 'attached');
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
    setStatus(`RPC failed: ${e.message || e}`, 'err');
  }
}

async function postMsg() {
  if (!isAttached()) return setStatus('Attach agent first', 'err');
  const raw = ($('device-post-json')?.value || '{"type":"ping"}').trim();
  try {
    const obj = JSON.parse(raw);
    await session.post(obj);
    log(`Post ${raw}`, 'device-log-msg');
  } catch (e) {
    log(String(e.message || e), 'device-log-err');
  }
}

export function initDeviceUi(ctx = {}) {
  getApkBytes = ctx.getApkBytes || getApkBytes;
  getApkName = ctx.getApkName || getApkName;
  getPackageHint = ctx.getPackageHint || getPackageHint;

  const script = $('device-script');
  customScript = DEFAULT_SMOKE_SCRIPT;
  selectPreset('smoke', { force: true });
  script?.addEventListener('input', () => onScriptEdited());
  script?.addEventListener('scroll', () => {
    const pre = $('device-script-highlight');
    if (pre && script) {
      pre.scrollTop = script.scrollTop;
      pre.scrollLeft = script.scrollLeft;
    }
  });
  script?.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      const start = script.selectionStart;
      const end = script.selectionEnd;
      const v = script.value;
      script.value = `${v.slice(0, start)}  ${v.slice(end)}`;
      script.selectionStart = script.selectionEnd = start + 2;
      onScriptEdited();
    }
  });

  getBundledGoauldMeta()
    .then((m) => {
      const hint = $('device-bin-hint');
      if (hint) {
        hint.textContent = `Bundled arm64 goauld (${m.version}) used by default. Optional overrides:`;
      }
    })
    .catch(() => {});

  $('device-connect')?.addEventListener('click', () => connect());
  $('device-disconnect')?.addEventListener('click', () => disconnect());
  $('device-refresh-apps')?.addEventListener('click', () => refreshApps());
  $('device-third-party')?.addEventListener('change', () => {
    if (adbDevice.isAdbConnected()) refreshApps();
  });
  $('device-app-filter')?.addEventListener('input', (e) => {
    filterText = e.target.value || '';
    renderApps();
  });
  $('device-package')?.addEventListener('input', () => syncWorkflowUi());
  $('device-pid')?.addEventListener('input', () => syncWorkflowUi());
  $('device-launch')?.addEventListener('click', () => launchSelected());
  $('device-stop')?.addEventListener('click', () => stopSelected());
  $('device-install-apk')?.addEventListener('click', () => installAnalyzedApk());
  $('device-inject')?.addEventListener('click', () => injectSelected());
  $('device-attach')?.addEventListener('click', () => attachSelected());
  $('device-detach')?.addEventListener('click', () => detachSession());
  $('device-trace-java')?.addEventListener('click', () => traceJavaApi());
  $('device-trace-syscalls')?.addEventListener('click', () => traceSyscallsBtn());
  $('device-script-load')?.addEventListener('click', () => loadScript());
  $('device-script-load-run')?.addEventListener('click', () => loadScriptAndWatch());
  $('device-rpc-call')?.addEventListener('click', () => rpcCall());
  $('device-post')?.addEventListener('click', () => postMsg());
  $('device-console-clear')?.addEventListener('click', () => clearConsole());

  if (!adbDevice.isWebUsbAvailable()) {
    setStatus('WebUSB unavailable', 'err');
    if ($('device-connect')) $('device-connect').disabled = true;
  }
  updateConsoleChrome();
  syncWorkflowUi();
}

export function openDeviceTab(switchTab) {
  switchTab?.('device-tab');
  applyPackageHint({ force: false });
  syncWorkflowUi();
}

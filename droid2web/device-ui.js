/**
 * Dedicated Device tab — WebUSB ADB + goauld attach / protocol console.
 */

import * as adbDevice from './adb-device.js';
import { startMirror, NAV, bindMirrorCapture } from './mirror-ui.js';
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
let apiTraceArmed = false;
let noisyApiNoted = false;
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
let consoleFilter = 'all';

function $(id) {
  return document.getElementById(id);
}

function isPhoneConnected() {
  return phoneLinked;
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
  if (cls.includes('device-log-muted') || cls.includes('device-log-sys')) return 'sys';
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
  applyConsoleFilter();
}

function applyConsoleFilter() {
  const el = $('device-console');
  if (!el) return;
  el.querySelectorAll('.device-log').forEach((row) => {
    const kind = row.dataset.kind || 'info';
    const show =
      consoleFilter === 'all' ||
      kind === consoleFilter ||
      (consoleFilter === 'sys' && (kind === 'sys' || kind === 'syscall'));
    row.hidden = !show;
  });
}

function appendConsoleRow(row) {
  const el = $('device-console');
  if (!el) return;
  el.appendChild(row);
  consoleLineCount += 1;
  updateConsoleChrome();
  const follow = $('device-console-autoscroll')?.checked !== false;
  if (follow) el.scrollTop = el.scrollHeight;
}

function log(msg, cls = '') {
  const kind = logKindFromClass(cls);
  const row = document.createElement('div');
  row.className = `device-log device-log-${kind}${cls ? ` ${cls}` : ''}`;
  row.dataset.kind = kind === 'info' && cls.includes('device-log-sys') ? 'sys' : kind;

  const time = document.createElement('span');
  time.className = 'device-log-time';
  time.textContent = formatLogTime();

  const tag = document.createElement('span');
  tag.className = 'device-log-tag';
  tag.textContent = kind;

  const body = document.createElement('span');
  body.className = 'device-log-body';
  body.textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);

  row.append(time, tag, body);
  appendConsoleRow(row);
}

/**
 * Structured trace / protocol event with full fields visible.
 * @param {{ kind?: string, tag?: string, title: string, subtitle?: string, fields?: Record<string, unknown>, raw?: unknown }} ev
 */
function logEvent(ev) {
  const kind = ev.kind || 'msg';
  const row = document.createElement('div');
  row.className = `device-log device-log-event device-log-${kind}`;
  row.dataset.kind = kind;

  const time = document.createElement('span');
  time.className = 'device-log-time';
  time.textContent = formatLogTime();

  const tag = document.createElement('span');
  tag.className = 'device-log-tag';
  tag.textContent = ev.tag || kind;

  const body = document.createElement('div');
  body.className = 'device-log-body device-evt';

  const head = document.createElement('div');
  head.className = 'device-evt-head';
  const title = document.createElement('div');
  title.className = 'device-evt-title';
  title.textContent = ev.title;
  head.appendChild(title);
  if (ev.subtitle) {
    const sub = document.createElement('div');
    sub.className = 'device-evt-sub';
    sub.textContent = ev.subtitle;
    head.appendChild(sub);
  }
  body.appendChild(head);

  const fields = ev.fields && typeof ev.fields === 'object' ? ev.fields : null;
  const raw = ev.raw;
  const hasDetails = (fields && Object.keys(fields).length) || raw != null;
  if (hasDetails) {
    const details = document.createElement('details');
    details.className = 'device-evt-details';
    details.open = kind === 'api' || kind === 'syscall';
    const summary = document.createElement('summary');
    summary.textContent = 'Full event';
    details.appendChild(summary);

    if (fields) {
      const dl = document.createElement('dl');
      dl.className = 'device-evt-fields';
      for (const [key, value] of Object.entries(fields)) {
        if (value == null || value === '') continue;
        const dt = document.createElement('dt');
        dt.textContent = key;
        const dd = document.createElement('dd');
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          dd.textContent = String(value);
        } else {
          const pre = document.createElement('pre');
          pre.className = 'device-evt-json';
          pre.textContent = JSON.stringify(value, null, 2);
          dd.appendChild(pre);
        }
        dl.append(dt, dd);
      }
      details.appendChild(dl);
    }

    if (raw != null) {
      const pre = document.createElement('pre');
      pre.className = 'device-evt-json';
      pre.textContent = typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2);
      details.appendChild(pre);
    }
    body.appendChild(details);
  }

  row.append(time, tag, body);
  appendConsoleRow(row);
}

function clearConsole() {
  const el = $('device-console');
  if (el) el.replaceChildren();
  consoleLineCount = 0;
  updateConsoleChrome();
}

function prettyJson(value, maxLen = 4000) {
  try {
    const s = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    if (s.length > maxLen) return `${s.slice(0, maxLen)}\n… (${s.length} chars)`;
    return s;
  } catch {
    return String(value);
  }
}

function splitPrettyMethod(method) {
  let head = String(method || '');
  const paren = head.indexOf('(');
  const sig = paren >= 0 ? head.slice(paren) : '';
  head = paren >= 0 ? head.slice(0, paren) : head;
  // ART PrettyMethod sometimes prefixes a return type: "void android.foo.Bar.baz"
  const typed = head.match(/^(?:void|boolean|byte|char|short|int|long|float|double)\s+(.+)$/);
  if (typed) head = typed[1];
  const dot = head.lastIndexOf('.');
  if (dot > 0) {
    return { className: head.slice(0, dot), methodName: head.slice(dot + 1), signature: sig, full: method };
  }
  return { className: '', methodName: head, signature: sig, full: method };
}

function formatApiArg(a) {
  if (a == null) return 'null';
  if (typeof a === 'object' && ('t' in a || 'v' in a)) {
    const v = a.v;
    const shown = typeof v === 'string' && v.length > 64 ? `${v.slice(0, 64)}…` : String(v);
    return a.t != null && a.t !== '' ? `${a.t}=${shown}` : shown;
  }
  if (typeof a === 'string') return JSON.stringify(a.length > 80 ? `${a.slice(0, 80)}…` : a);
  if (typeof a === 'object') return JSON.stringify(a);
  return String(a);
}

function isNoisyAndroidApi(method) {
  const parts = splitPrettyMethod(method || '');
  const cn = parts.className || '';
  const noise = [
    'android.view.DisplayEventReceiver',
    'android.view.Choreographer',
    'android.view.ViewRootImpl',
    'android.view.ThreadedRenderer',
    'android.view.SurfaceControl',
    'android.view.InsetsController',
    'android.view.SyncRtSurfaceTransactionApplier',
    'android.graphics.HardwareRenderer',
    'android.animation.AnimationHandler',
  ];
  return noise.some((p) => cn === p || cn.startsWith(`${p}$`) || cn.startsWith(`${p}.`));
}

function formatAndroidApiEvent(parsed) {
  const parts = splitPrettyMethod(parsed.method || '');
  const n = parsed.n != null ? `#${parsed.n}` : '';
  const title = parts.className
    ? `${parts.className}.${parts.methodName}${parts.signature || ''}`
    : parts.full || 'android-api';
  const argsPreview = parsed.args != null
    ? (Array.isArray(parsed.args)
      ? parsed.args.map(formatApiArg).join(', ')
      : prettyJson(parsed.args, 200))
    : '';
  return {
    kind: 'api',
    tag: 'api',
    title: `${n ? n + ' ' : ''}${title}`,
    subtitle: [
      parsed.static ? 'static' : 'instance',
      parsed.shorty ? `shorty ${parsed.shorty}` : '',
      argsPreview ? `(${argsPreview})` : '',
    ].filter(Boolean).join(' · '),
    fields: {
      n: parsed.n,
      method: parsed.method,
      class: parts.className || undefined,
      name: parts.methodName || undefined,
      signature: parts.signature || undefined,
      shorty: parsed.shorty,
      static: parsed.static,
      args: parsed.args,
    },
    raw: parsed,
  };
}

/** Parse goauld-injector syscall trace stdout into structured rows. */
function logSyscallLine(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return 'blank';
  if (/^OK traced\b/i.test(trimmed) || /^tracing syscalls\b/i.test(trimmed)) {
    log(trimmed, 'device-log-ok');
    return 'status';
  }
  if (/__GOAULD_EXIT:/.test(trimmed)) {
    log(trimmed, 'device-log-muted');
    return 'status';
  }
  // [tid] name(args) = 0xret   OR   [tid] → name(args)
  const re = /^\[(\d+)\]\s+(→\s+)?([a-zA-Z0-9_]+)\((.*)\)(?:\s*=\s*(.+))?$/;
  const m = trimmed.match(re);
  if (m) {
    const tid = m[1];
    const enter = !!m[2];
    const name = m[3];
    const args = m[4];
    const ret = m[5];
    logEvent({
      kind: 'syscall',
      tag: enter ? 'enter' : 'sys',
      title: enter ? `→ ${name}(${args})` : `${name}(${args}) = ${ret}`,
      subtitle: `tid ${tid}${ret != null ? ` · ret ${ret}` : ''}`,
      fields: {
        tid: Number(tid),
        name,
        direction: enter ? 'enter' : 'exit',
        args,
        retval: ret,
        line: trimmed,
      },
    });
    return 'event';
  }
  log(trimmed, /error|denied|fail/i.test(trimmed) ? 'device-log-err' : 'device-log-muted');
  return 'other';
}

function logSyscallTraceOutput(out) {
  const text = String(out || '');
  const lines = text.split(/\r?\n/);
  let events = 0;
  let other = 0;
  for (const line of lines) {
    const kind = logSyscallLine(line);
    if (kind === 'event') events += 1;
    else if (kind === 'other') other += 1;
  }
  if (events) {
    log(`Parsed ${events} syscall event(s)${other ? ` · ${other} other line(s)` : ''}`, 'device-log-ok');
  } else if (!text.trim()) {
    log('(empty syscall trace output)', 'device-log-muted');
  }
}

/** payload_json is often JSON-encoded twice (`send()` stringifies a string). */
function unwrapJson(value) {
  let v = value;
  for (let i = 0; i < 4 && typeof v === 'string'; i++) {
    const t = v.trim();
    if (!t) return v;
    const c = t[0];
    if (c !== '{' && c !== '[' && c !== '"') return v;
    try {
      v = JSON.parse(t);
    } catch {
      return v;
    }
  }
  return v;
}

function usablePackage(name) {
  const s = String(name || '').trim();
  if (!s || /^(unknown|agent|\?)$/i.test(s)) return '';
  return s;
}

/** `0.1.6 (git:59dcb42 built:…) js=quickjs` → `0.1.6 · 59dcb42 · quickjs`. */
function shortGoauldVersion(version) {
  const v = String(version || '').trim();
  if (!v) return '';
  const pkg = (v.match(/(\d+\.\d+\.\d+)/) || [])[1] || v.split(/\s+/)[0];
  const git = (v.match(/git:([0-9a-f]+)/i) || [])[1];
  const js = (v.match(/\bjs=([^\s)]+)/) || [])[1];
  return [pkg, git ? git.slice(0, 7) : '', js].filter(Boolean).join(' · ');
}

function attachedPackage(hello, fallback) {
  return usablePackage(session?.displayPackage) || usablePackage(hello?.package) || usablePackage(fallback);
}

function attachedGoauldVersion(hello) {
  return shortGoauldVersion(hello?.version || session?.goauldVersion || '');
}

function formatMsg(msg) {
  if (msg.type === MsgType.Hello) {
    return {
      mode: 'text',
      text: `Hello pid=${msg.json?.pid} pkg=${msg.json?.package} abi=${msg.json?.abi} sdk=${msg.json?.sdk_int} goauld=${msg.json?.version || '?'}`,
      cls: 'device-log-ok',
    };
  }
  if (msg.type === MsgType.Log) {
    return {
      mode: 'text',
      text: `Log[${msg.json?.level || '?'}] ${msg.json?.message || ''}`,
      cls: 'device-log-muted',
    };
  }
  if (msg.type === MsgType.Send) {
    const payload = msg.payload_json;
    const parsed = unwrapJson(payload);
    if (parsed && typeof parsed === 'object') {
        if (parsed.type === 'api-trace-stopped') {
          return { mode: 'skip' };
        }
        if (parsed.type === 'android-api') {
          if (isNoisyAndroidApi(parsed.method)) {
            if (!noisyApiNoted) {
              noisyApiNoted = true;
              log(
                'Hiding frame-pump calls (vsync, Choreographer, ViewRootImpl). They are not the API your script called.',
                'device-log-muted',
              );
            }
            return { mode: 'skip' };
          }
          return { mode: 'event', event: formatAndroidApiEvent(parsed) };
        }
        if (parsed.type === 'android-api-err' || parsed.type === 'java-api-err') {
          return {
            mode: 'event',
            event: {
              kind: 'err',
              tag: 'err',
              title: parsed.type,
              subtitle: parsed.err || '',
              fields: parsed,
              raw: parsed,
            },
          };
        }
        if (parsed.type === 'trace-java-ready') {
          return {
            mode: 'event',
            event: {
              kind: 'ok',
              tag: 'ok',
              title: 'Java / Android API trace ready',
              subtitle: `hook=${parsed.art_invoke_hook} · filter=${parsed.filter}`,
              fields: parsed,
              raw: parsed,
            },
          };
        }
        return {
          mode: 'event',
          event: {
            kind: 'msg',
            tag: parsed.type || 'send',
            title: parsed.type || 'Send',
            subtitle: Object.keys(parsed)
              .filter((k) => k !== 'type')
              .slice(0, 4)
              .map((k) => `${k}=${typeof parsed[k] === 'object' ? '…' : parsed[k]}`)
              .join(' · '),
            fields: parsed,
            raw: parsed,
          },
        };
    }
    return {
      mode: 'text',
      text: `Send script=${msg.script_id} ${typeof payload === 'string' ? payload : JSON.stringify(payload)}`,
      cls: 'device-log-msg',
    };
  }
  if (msg.type === MsgType.RpcReply) {
    const err = msg.json?.error;
    return {
      mode: 'event',
      event: {
        kind: err ? 'err' : 'ok',
        tag: 'rpc',
        title: err ? `RpcReply error · id=${msg.json?.call_id}` : `RpcReply id=${msg.json?.call_id}`,
        subtitle: err || String(msg.json?.result_json ?? ''),
        fields: msg.json,
        raw: msg.json,
      },
    };
  }
  return {
    mode: 'event',
    event: {
      kind: 'msg',
      tag: msg.name || 'msg',
      title: String(msg.name || 'message'),
      fields: msg.json ?? msg,
      raw: msg.json ?? msg,
    },
  };
}

function logProtocolMsg(msg) {
  const formatted = formatMsg(msg);
  if (!formatted || formatted.mode === 'skip') return;
  if (formatted.mode === 'event') logEvent(formatted.event);
  else log(formatted.text, formatted.cls);
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
      const name = attachedPackage(hello, pkg);
      const ver = attachedGoauldVersion(hello);
      const bits = ['Live', name, `pid ${hello?.pid || pid || '?'}`];
      if (ver) bits.push(`goauld ${ver}`);
      gate.textContent = bits.filter(Boolean).join(' · ');
      gate.title = hello?.version || session?.goauldVersion || '';
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
      const name = attachedPackage(hello, pkg) || 'app';
      const ver = attachedGoauldVersion(hello);
      const bits = ['Attached', name, `pid ${hello?.pid || pid || '?'}`];
      if (ver) bits.push(`goauld ${ver}`);
      chip.textContent = bits.join(' · ');
      chip.title = hello?.version || session?.goauldVersion || 'goauld version not reported by this agent';
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

function renderApps() {
  const ul = $('device-app-list');
  if (!ul) return;
  const count = $('device-app-count');
  const runningN = apps.filter((a) => a.running).length;
  if (count) count.textContent = apps.length ? `${runningN} running` : '';
  ul.innerHTML = '';
  const f = filterText.toLowerCase();
  const list = apps.filter((a) => !f || a.package.toLowerCase().includes(f) || (a.user || '').toLowerCase().includes(f));
  const typedPid = ($('device-pid')?.value || '').trim();
  const selected = currentPackage();
  for (const app of list) {
    const li = document.createElement('li');
    const procs = Array.isArray(app.processes) ? app.processes : [];
    const liveIds = new Set(procs.map((p) => String(p.pid)));
    if (app.pid != null) liveIds.add(String(app.pid));
    const stale = selected === app.package && typedPid && !liveIds.has(typedPid);
    li.className = 'device-app-item'
      + (selected === app.package ? ' active' : '')
      + (app.running ? ' is-running' : '');
    li.dataset.package = app.package;
    const procLabel = procs.length > 1 ? `${procs.length} processes` : (procs.length === 1 ? '1 process' : '');
    const metaBits = [];
    if (app.running) {
      if (app.user) metaBits.push(app.user);
      metaBits.push(`pid ${app.pid}`);
      if (procLabel) metaBits.push(procLabel);
    }
    const showProcs = selected === app.package && procs.length > 0;
    const procHtml = showProcs
      ? `<ul class="device-app-procs">${procs.map((p) => {
          const role = p.name === app.package ? 'main' : p.name.slice(app.package.length);
          const bits = [p.user, p.state && p.state !== '?' ? p.state : '', p.ppid ? `ppid ${p.ppid}` : ''].filter(Boolean);
          return `<li><span class="device-app-pid">${p.pid}</span> ${escapeHtml(role)} <span class="muted">${escapeHtml(bits.join(' · '))}</span></li>`;
        }).join('')}</ul>`
      : '';
    li.innerHTML =
      `<div class="device-app-row">` +
        `<span class="device-app-name">${escapeHtml(app.package)}</span>` +
        `<span class="device-app-badge${app.running ? ' is-on' : ''}">${app.running ? 'running' : 'stopped'}</span>` +
      `</div>` +
      `<span class="device-app-meta">${app.running ? escapeHtml(metaBits.join(' · ')) : 'not running'}</span>` +
      (stale ? `<span class="device-app-stale">pid field ${escapeHtml(typedPid)} is not this app</span>` : '') +
      procHtml;
    li.addEventListener('click', () => {
      selectedPkg = app.package;
      const pkgInput = $('device-package');
      if (pkgInput) pkgInput.value = app.package;
      const pidInput = $('device-pid');
      if (pidInput) pidInput.value = app.pid != null ? String(app.pid) : '';
      renderApps();
      syncWorkflowUi();
      const extra = app.user ? ` · ${app.user}` : '';
      setStatus(
        app.pid != null ? `${app.package} · pid ${app.pid}${extra}` : `${app.package} · stopped`,
        'ok',
      );
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

/** pidof the package and replace a stale PID field. Returns the live pid or null. */
async function refreshLivePid(pkg, { quiet = false } = {}) {
  if (!pkg) return currentPid();
  const liveRaw = await adbDevice.pidOf(pkg).catch(() => null);
  const live = liveRaw ? Number(String(liveRaw).trim()) : null;
  const typed = currentPid();
  const input = $('device-pid');
  if (live && typed && typed !== live) {
    log(`pid ${typed} is not running — ${pkg} is pid ${live}`, 'device-log-muted');
  } else if (!live && typed && !quiet) {
    log(`pid ${typed} is not running — ${pkg} has no process`, 'device-log-muted');
  }
  if (input) input.value = live ? String(live) : '';
  const app = apps.find((a) => a.package === pkg);
  if (app) {
    app.running = !!live;
    app.pid = live;
    if (!live) app.processes = [];
    else if (!Array.isArray(app.processes) || !app.processes.some((p) => p.pid === live)) {
      const rest = (app.processes || []).filter((p) => p.name !== pkg);
      app.processes = [{ pid: live, ppid: null, user: app.user || '', state: '', name: pkg }, ...rest];
    }
  }
  renderApps();
  return live;
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
    if (app && pidInput) {
      const typed = pidInput.value.trim();
      const liveIds = new Set((app.processes || []).map((p) => String(p.pid)));
      if (app.pid != null) liveIds.add(String(app.pid));
      const stale = typed && !liveIds.has(typed);
      if (!typed || stale || force) {
        pidInput.value = app.pid != null ? String(app.pid) : '';
      }
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

function clipInjectLog(out) {
  const text = String(out || '');
  if (text.length <= 8000) return text;
  return `${text.slice(0, 2500)}\n…\n${text.slice(-5000)}`;
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
    const live = await refreshLivePid(pkg);
    if (!live) {
      setStatus(`${pkg} is not running — Launch it, then Live inject`, 'err');
      return;
    }
    const out = String(
      await adbDevice.injectGoauldLive({
        packageName: pkg,
        pid: live,
        stageIntoApp: true,
        via: root.via,
      }) || '',
    );
    const exit = out.match(/__GOAULD_EXIT:(\d+)/);
    const failed =
      (exit && exit[1] !== '0') ||
      /goauld-injector error:|dlopen failed/i.test(out) ||
      !/OK handle=/i.test(out);
    log(clipInjectLog(out), failed ? 'device-log-err' : 'device-log-ok');
    if (failed) {
      setStatus('Live inject failed — the agent was not loaded', 'err');
      log(
        'Attach only works after inject prints OK handle=. A stock app does not listen until that succeeds. If the pid changed, the process restarted without the agent.',
        'device-log-muted',
      );
      return;
    }
    await new Promise((r) => setTimeout(r, 800));
    const injectedPid = out.match(/into pid=(\d+)/);
    const pid = await adbDevice.pidOf(pkg);
    if (pid) {
      if ($('device-pid')) $('device-pid').value = pid;
      if (injectedPid && injectedPid[1] !== String(pid)) {
        log(
          `Injected pid ${injectedPid[1]}, but ${pkg} is pid ${pid}. The agent was loaded into a different process (often the su shell) and is gone.`,
          'device-log-err',
        );
        setStatus('Process restarted after inject — agent is gone', 'err');
        return;
      }
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
  apiTraceArmed = false;
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

    if (pkg) {
      pid = await refreshLivePid(pkg, { quiet: true });
      if (!pid && doLaunch) {
        setStatus(`Launching ${pkg}…`, 'busy');
        log(`Launch ${pkg} (embedded agent needs a live process)`, 'device-log-muted');
        await adbDevice.launchPackage(pkg);
        setStatus(`Waiting for pid of ${pkg}…`, 'busy');
        pid = await adbDevice.waitForPackagePid(pkg, { timeoutMs: 20000 });
        if ($('device-pid') && pid) $('device-pid').value = String(pid);
      } else if (!pid) {
        setStatus('App not running — enable “Launch before attach” or start it manually', 'err');
        return false;
      } else {
        log(`Process already running (pid ${pid})`, 'device-log-muted');
      }
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
        apiTraceArmed = false;
        adbDevice.releaseStreamExclusive?.();
        syncWorkflowUi();
        setStatus('Agent session closed — Attach again', 'ok');
      },
    });
    transport = null; // owned by session now

    const hello = await session.attach();
    if (!session._alive) session._alive = true;
    if (!session.hello && hello) session.hello = hello;

    const named = usablePackage(hello?.package) || usablePackage(pkg);
    session.displayPackage = named;
    session.goauldVersion = String(hello?.version || '').trim();
    if (!session.displayPackage && pid) {
      try {
        const raw = String(await adbDevice.adbShell(`tr '\\0' ' ' < /proc/${pid}/cmdline`) || '');
        session.displayPackage = usablePackage(raw.trim().split(/\s+/)[0]);
      } catch {
        /* package stays blank; chip omits "unknown" */
      }
    }
    if (!session.goauldVersion) {
      const meta = await getBundledGoauldMeta().catch(() => null);
      session.goauldVersion = String(meta?.version || '').trim();
    }
    const pkgInput = $('device-package');
    if (session.displayPackage && pkgInput && !usablePackage(pkgInput.value)) {
      pkgInput.value = session.displayPackage;
    }
    const verShort = shortGoauldVersion(session.goauldVersion);
    const who = session.displayPackage || `pid ${hello?.pid || pid}`;
    setStatus(
      `Agent attached · ${who} · pid ${hello?.pid || pid}${verShort ? ` · goauld ${verShort}` : ''}`,
      'attached',
    );
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
        `${pkg || 'This app'} has no goauld agent listening. Use Live inject (root) on the Target card, or install an APK that already embeds the agent and then Attach.`,
        'device-log-muted',
      );
      document.getElementById('device-live-inject')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    } else {
      log(
        'Embedded-agent apps: install/launch → Attach. Apps without the agent (e.g. Calculator): Live inject on the Target card, then Attach.',
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

    const source = buildJavaApiTraceScript({ filter, maxEvents });
    selectPreset('java-api', { force: true });
    const editor = $('device-script');
    if (editor) {
      editor.value = source;
      scheduleScriptHighlight();
    }

    setStatus('Installing Java/Android API tracer…');
    log(`ScriptLoad java-api trace (collect ${maxEvents} events) — use the app on the phone`, 'device-log-ok');
    await session.loadScript(source);
    apiTraceArmed = true;
    noisyApiNoted = false;
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
            if (p?.type === 'android-api' && !isNoisyAndroidApi(p.method)) apiCount++;
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
    if (pkg) {
      pid = await refreshLivePid(pkg, { quiet: true });
    }
    if (!pid && pkg) {
      log(`Launching ${pkg}…`);
      await adbDevice.launchPackage(pkg);
      pid = await adbDevice.waitForPackagePid(pkg);
      if ($('device-pid') && pid) $('device-pid').value = String(pid);
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

    setStatus(`Tracing syscalls ${secs}s · max ${maxEvents} — events show as they happen`, 'busy');
    log(
      `trace-syscalls --pid ${pid || '(pkg)'} --duration-secs ${secs} --max-events ${maxEvents}` +
        (filter ? ` --filter ${filter}` : '') +
        (enterOnly ? ' --enter-only' : ''),
      'device-log-ok',
    );
    let events = 0;
    const result = await adbDevice.traceSyscalls({
      pid: pid || undefined,
      packageName: pid ? undefined : pkg,
      durationSecs: secs,
      maxEvents,
      filter,
      enterOnly,
      via: root.via,
      onLine(line) {
        const kind = logSyscallLine(line);
        if (kind === 'event') {
          events += 1;
          if (events === 1 || events % 20 === 0) {
            setStatus(`Tracing… ${events} syscall event(s)`, 'busy');
          }
        }
      },
    });
    const out = typeof result === 'string' ? result : result?.out || '';
    const via = typeof result === 'object' ? result.via : '';
    if (via) log(`ran via ${via}`, 'device-log-muted');
    if (events) {
      log(`${events} syscall event(s)`, 'device-log-ok');
    } else if (!String(out).trim()) {
      log('(empty syscall trace output)', 'device-log-muted');
    }

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

async function pauseApiTrace() {
  if (!session || !apiTraceArmed) return;
  apiTraceArmed = false;
  const stop = `try { __goauld.stopAndroidApiTrace(); } catch (e) {}
try { __goauld.traceAndroidApi('__off.', 1); } catch (e) {}
send({ type: 'api-trace-stopped' });
`;
  try {
    await session.loadScript(stop);
    await session.drain({ maxMessages: 8, untilAgentMessage: true });
  } catch {
    /* older agents ignore the stop; the __off. filter still drops further events */
  }
  log('API trace stopped — later scripts are not mixed with framework calls', 'device-log-muted');
}

async function loadScript() {
  if (!isAttached()) {
    setStatus('Attach agent first — then ScriptLoad', 'err');
    log('ScriptLoad blocked: no agent session', 'device-log-err');
    return null;
  }
  const source = $('device-script')?.value || DEFAULT_SMOKE_SCRIPT;
  try {
    if (apiTraceArmed && !source.includes('traceAndroidApi')) await pauseApiTrace();
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
  log('Waiting briefly for agent Send…', 'device-log-muted');
  await new Promise((r) => setTimeout(r, 400));
  try {
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
  $('device-console-filters')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-filter]');
    if (!btn) return;
    consoleFilter = btn.getAttribute('data-filter') || 'all';
    $('device-console-filters')
      ?.querySelectorAll('.device-console-filter')
      .forEach((b) => b.classList.toggle('is-on', b === btn));
    applyConsoleFilter();
  });

  if (!adbDevice.isWebUsbAvailable()) {
    setStatus('WebUSB unavailable', 'err');
    if ($('device-connect')) $('device-connect').disabled = true;
  }
  updateConsoleChrome();
  syncWorkflowUi();
  bindDeviceMirror();
}

export function openDeviceTab(switchTab) {
  switchTab?.('device-tab');
  syncDeviceContents(true);
  applyPackageHint({ force: false });
  syncWorkflowUi();
}

let deviceMirror = null;

export function syncDeviceContents(on) {
  const panel = document.getElementById('left-panel');
  const slot = document.getElementById('device-mirror-slot');
  const title = document.getElementById('left-panel-title');
  if (!panel || !slot) return;
  panel.classList.toggle('is-device-screen', !!on);
  slot.hidden = !on;
  if (!title) return;
  if (on) {
    if (title.dataset.prevTitle == null) title.dataset.prevTitle = title.textContent || 'Contents';
    title.textContent = 'Screen';
    if (panel.getBoundingClientRect().width < 320) panel.style.width = '360px';
  } else if (title.dataset.prevTitle != null) {
    title.textContent = title.dataset.prevTitle;
    delete title.dataset.prevTitle;
  }
}

function bindDeviceMirror() {
  const startBtn = document.getElementById('device-mirror-start');
  const canvas = document.getElementById('device-mirror-canvas');
  if (!startBtn || !canvas || startBtn.dataset.bound) return;
  startBtn.dataset.bound = '1';
  const stopBtn = document.getElementById('device-mirror-stop');
  const statusEl = document.getElementById('device-mirror-status');
  const captureUi = bindMirrorCapture({
    shot: document.getElementById('device-mirror-shot'),
    gif: document.getElementById('device-mirror-gif'),
    mp4: document.getElementById('device-mirror-mp4'),
  }, () => deviceMirror);
  const setStatus = (s) => {
    if (statusEl) statusEl.textContent = s;
    if (s === 'stopped') {
      deviceMirror = null;
      startBtn.hidden = false;
      startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      captureUi.setEnabled(false);
    }
  };
  startBtn.addEventListener('click', async () => {
    startBtn.disabled = true;
    try {
      deviceMirror = await startMirror(canvas, { onStatus: setStatus });
      startBtn.hidden = true;
      if (stopBtn) stopBtn.disabled = false;
      captureUi.setEnabled(true);
      canvas.focus();
    } catch (e) {
      setStatus(e?.message || String(e));
      startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      captureUi.setEnabled(false);
    }
  });
  stopBtn?.addEventListener('click', async () => {
    stopBtn.disabled = true;
    const current = deviceMirror;
    deviceMirror = null;
    captureUi.setEnabled(false);
    try { await current?.stop(); } catch { /* closed */ }
    startBtn.hidden = false;
    startBtn.disabled = false;
    setStatus('Click to mirror');
  });
  document.querySelectorAll('[data-device-mirror-nav]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const code = NAV[btn.getAttribute('data-device-mirror-nav')];
      if (code == null || !deviceMirror?.client) return;
      canvas.focus();
      deviceMirror.transport?.write(deviceMirror.client.nav(code, 0));
      deviceMirror.transport?.write(deviceMirror.client.nav(code, 1));
    });
  });
}

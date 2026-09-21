/**
 * RustPython shell (https://github.com/RustPython/RustPython) over the open analysis.
 * Every entry in DROID_COMMANDS is exported on `droid` and as a top-level name.
 */

/** @type {{ name: string, js: string, kind: 'json'|'text', py: string, jsCall: string, doc: string }[]} */
export const DROID_COMMANDS = [
  { name: 'info', js: 'snapshot', kind: 'json', py: '()', jsCall: '()', doc: 'Open file, counts, selection, finding totals' },
  { name: 'classes', js: 'classes', kind: 'json', py: '(query="", limit=200)', jsCall: '(query, int(limit))', doc: 'Class names; optional substring filter' },
  { name: 'methods', js: 'methods', kind: 'json', py: '(class_name)', jsCall: '(class_name)', doc: 'Methods of one class' },
  { name: 'findings', js: 'findings', kind: 'json', py: '()', jsCall: '()', doc: 'Vuln, Semgrep, and MT findings' },
  { name: 'strings', js: 'strings', kind: 'json', py: '(query="", limit=100)', jsCall: '(query, int(limit))', doc: 'DEX string pool search' },
  { name: 'manifest', js: 'manifest', kind: 'text', py: '()', jsCall: '()', doc: 'AndroidManifest.xml text' },
  { name: 'source', js: 'source', kind: 'text', py: '()', jsCall: '()', doc: 'Current decompiled source' },
];

const PY_KEYWORDS = [
  'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def', 'del',
  'elif', 'else', 'except', 'False', 'finally', 'for', 'from', 'global', 'if', 'import',
  'in', 'is', 'lambda', 'None', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
  'True', 'try', 'while', 'with', 'yield',
];

const PY_BUILTINS = [
  'print', 'len', 'range', 'str', 'int', 'float', 'list', 'dict', 'set', 'tuple',
  'type', 'isinstance', 'dir', 'help', 'json', 'sorted', 'enumerate', 'zip', 'map', 'filter',
];

const KEYWORD_SET = new Set(PY_KEYWORDS);
const COMMAND_SET = new Set(DROID_COMMANDS.map((c) => c.name));
const BUILTIN_SET = new Set([...PY_BUILTINS, 'droid', 'help', 'commands']);

let pyExec = null;
let pyExecSingle = null;
let ready = null;
let history = [];
let historyIdx = -1;
/** @type {{ prefix: string, suffix: string, hits: {label:string, kind:string, insert:string}[], index: number } | null} */
let completeState = null;

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function setStatus(msg) {
  const el = $('python-status');
  if (el) el.textContent = msg || '';
}

function highlightPython(src) {
  const s = String(src ?? '');
  let html = '';
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    if (c === '#') {
      let j = s.indexOf('\n', i);
      if (j < 0) j = n;
      html += `<span class="py-tok-cmt">${escapeHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const triple = s.slice(i, i + 3) === c + c + c;
      const q = triple ? c + c + c : c;
      let j = i + q.length;
      while (j < n) {
        if (s[j] === '\\') {
          j += 2;
          continue;
        }
        if (s.slice(j, j + q.length) === q) {
          j += q.length;
          break;
        }
        j++;
      }
      html += `<span class="py-tok-str">${escapeHtml(s.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (/[0-9]/.test(c) && (i === 0 || !/[A-Za-z_]/.test(s[i - 1]))) {
      const m = s.slice(i).match(/^(0[xX][0-9a-fA-F]+|\d+\.\d*|\d+)/);
      if (m) {
        html += `<span class="py-tok-num">${escapeHtml(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = s.slice(i).match(/^[A-Za-z_][\w]*/);
      const id = m[0];
      let cls = 'py-tok-id';
      if (KEYWORD_SET.has(id)) cls = 'py-tok-kw';
      else if (COMMAND_SET.has(id) || id === 'droid') cls = 'py-tok-cmd';
      else if (BUILTIN_SET.has(id)) cls = 'py-tok-fn';
      html += `<span class="${cls}">${escapeHtml(id)}</span>`;
      i += id.length;
      continue;
    }
    html += escapeHtml(c);
    i++;
  }
  return html;
}

function syncInputHighlight() {
  const input = $('python-input');
  const hl = $('python-input-hl');
  if (!input || !hl) return;
  const text = input.value || '';
  hl.innerHTML = text ? highlightPython(text) : '';
  hl.scrollTop = input.scrollTop;
  hl.scrollLeft = input.scrollLeft;
}

function appendLog(text, kind) {
  const log = $('python-log');
  if (!log) return;
  const span = document.createElement('span');
  if (kind) span.className = kind;
  const body = text.endsWith('\n') ? text : text + '\n';
  if (kind === 'py-in' || kind === 'py-val' || kind === 'py-out') {
    span.innerHTML = highlightPython(body.endsWith('\n') ? body.slice(0, -1) : body) + '\n';
  } else {
    span.textContent = body;
  }
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
}

function errorText(err) {
  if (!err) return 'error';
  if (typeof err === 'string') return err;
  return err.message || err.toString?.() || String(err);
}

function buildPrelude() {
  const methods = DROID_COMMANDS.map((c) => {
    const sig = c.py === '()' ? '' : c.py.slice(1, -1);
    const params = sig ? ', ' + sig : '';
    const ret = c.kind === 'json'
      ? `json.loads(js_vars[${JSON.stringify(c.js)}]${c.jsCall})`
      : `js_vars[${JSON.stringify(c.js)}]${c.jsCall}`;
    return [
      `    def ${c.name}(self${params}):`,
      `        """${c.doc}"""`,
      `        return ${ret}`,
    ].join('\n');
  }).join('\n');

  const aliases = [
    ...DROID_COMMANDS.map((c) => `${c.name} = droid.${c.name}`),
    'snapshot = droid.info',
  ].join('\n');
  const helpRows = DROID_COMMANDS.map((c) => (
    `    (${JSON.stringify(c.name + c.py)}, ${JSON.stringify(c.doc)}),`
  )).join('\n');

  return `
import json

class _Droid:
    """Analysis commands. Each method is also a top-level name."""
${methods}
    def help(self, topic=""):
        rows = [
${helpRows}
        ]
        topic = str(topic or "")
        if topic:
            for sig, doc in rows:
                if sig.startswith(topic):
                    print(sig)
                    print("  " + doc)
                    return None
            print("No command named " + topic)
            return None
        print("Commands (droid.<name> and <name>()):")
        for sig, doc in rows:
            print("  " + sig + "  —  " + doc)
        print("snapshot() is an alias of info().")
        print("help('classes') for one command. Tab completes names.")
        return None

droid = _Droid()
${aliases}
help = droid.help
commands = droid.help

print("RustPython ready. help() lists every command. Tab completes.")
`;
}

function assertCommandsExported(vars) {
  const missing = DROID_COMMANDS.filter((c) => typeof vars?.[c.js] !== 'function').map((c) => c.js);
  if (missing.length) {
    appendLog('Missing JS exports: ' + missing.join(', '), 'py-err');
  }
}

async function ensurePython(getVars) {
  if (ready) return ready;
  ready = (async () => {
    setStatus('Loading RustPython…');
    appendLog('Loading RustPython WASM…', 'py-muted');
    const mod = await import('./pkg-rustpython/rustpython_wasm.js');
    await mod.default();
    pyExec = mod.pyExec;
    pyExecSingle = mod.pyExecSingle;
    const vars = getVars();
    assertCommandsExported(vars);
    pyExec(buildPrelude(), {
      vars,
      stdout(chunk) {
        appendLog(String(chunk ?? ''), 'py-out');
      },
    });
    setStatus('Ready');
  })().catch((err) => {
    ready = null;
    setStatus('Failed');
    appendLog(errorText(err), 'py-err');
    throw err;
  });
  return ready;
}

function runSource(source, getVars) {
  const src = String(source || '').replace(/\s+$/, '');
  if (!src) return;
  const shown = src.split('\n').map((line, i) => (i === 0 ? '>>> ' + line : '... ' + line)).join('\n');
  appendLog(shown, 'py-in');
  const opts = {
    vars: getVars(),
    stdout(chunk) {
      const text = String(chunk ?? '');
      if (text) appendLog(text, 'py-out');
    },
  };
  const single = !src.includes('\n');
  if (single) {
    try {
      pyExecSingle(src, opts);
      return;
    } catch (err) {
      const msg = errorText(err);
      if (!/SyntaxError|IndentationError|unexpected EOF/i.test(msg)) {
        appendLog(msg, 'py-err');
        return;
      }
    }
  }
  try {
    pyExec(src + '\n', opts);
  } catch (err) {
    appendLog(errorText(err), 'py-err');
  }
}

function commandHits() {
  return [
    { label: 'help', kind: 'fn', insert: 'help' },
    { label: 'commands', kind: 'fn', insert: 'commands' },
    { label: 'snapshot', kind: 'cmd', insert: 'snapshot' },
    ...DROID_COMMANDS.map((c) => ({ label: c.name, kind: 'cmd', insert: c.name })),
  ];
}

function completionCandidates(token) {
  const pool = [];
  if (token.includes('.')) {
    pool.push({ label: 'droid.help', kind: 'cmd', insert: 'droid.help' });
    for (const c of DROID_COMMANDS) pool.push({ label: 'droid.' + c.name, kind: 'cmd', insert: 'droid.' + c.name });
  } else if (!token) {
    return commandHits();
  } else {
    pool.push({ label: 'droid', kind: 'cmd', insert: 'droid' });
    pool.push(...commandHits());
    for (const k of PY_KEYWORDS) pool.push({ label: k, kind: 'kw', insert: k });
    for (const k of PY_BUILTINS) pool.push({ label: k, kind: 'fn', insert: k });
  }
  const hits = [];
  const seen = new Set();
  for (const h of pool) {
    if (!h.insert.startsWith(token) || h.insert === token) continue;
    if (seen.has(h.insert)) continue;
    seen.add(h.insert);
    hits.push(h);
  }
  hits.sort((a, b) => {
    const rank = (h) => (h.kind === 'cmd' ? 0 : h.kind === 'fn' ? 1 : 2);
    return rank(a) - rank(b) || a.insert.localeCompare(b.insert);
  });
  return hits;
}

function tokenAt(text, caret) {
  const before = text.slice(0, caret);
  const m = before.match(/[A-Za-z_][\w.]*$/);
  if (!m) return { start: caret, token: '' };
  return { start: caret - m[0].length, token: m[0] };
}

function hideComplete() {
  completeState = null;
  const list = $('python-complete');
  if (!list) return;
  list.hidden = true;
  list.innerHTML = '';
}

function renderComplete() {
  const list = $('python-complete');
  if (!list || !completeState) return;
  const { hits, index } = completeState;
  if (!hits.length) {
    hideComplete();
    return;
  }
  list.hidden = false;
  list.innerHTML = hits.map((h, i) => (
    `<li class="python-complete-item is-${h.kind}${i === index ? ' is-active' : ''}" role="option" data-i="${i}">` +
    `<span class="python-complete-kind">${h.kind}</span>` +
    `<span class="python-complete-label">${escapeHtml(h.label)}</span>` +
    `</li>`
  )).join('');
  list.querySelector('.is-active')?.scrollIntoView({ block: 'nearest' });
}

function writeHit(input) {
  if (!completeState || completeState.index < 0) return;
  const { prefix, suffix, hits, index } = completeState;
  const hit = hits[index];
  if (!hit) return;
  input.value = prefix + hit.insert + suffix;
  const pos = prefix.length + hit.insert.length;
  input.selectionStart = input.selectionEnd = pos;
  syncInputHighlight();
}

function applyComplete(input, hit) {
  if (!completeState || !hit) return;
  const { prefix, suffix } = completeState;
  input.value = prefix + hit.insert + suffix;
  const pos = prefix.length + hit.insert.length;
  input.selectionStart = input.selectionEnd = pos;
  hideComplete();
  syncInputHighlight();
}

function startComplete(input) {
  const caret = input.selectionStart ?? input.value.length;
  const { start, token } = tokenAt(input.value, caret);
  const hits = completionCandidates(token);
  if (!hits.length) {
    hideComplete();
    return;
  }
  completeState = {
    prefix: input.value.slice(0, start),
    suffix: input.value.slice(caret),
    hits,
    index: token ? 0 : -1,
  };
  if (token) writeHit(input);
  if (hits.length === 1) hideComplete();
  else renderComplete();
}

function cycleComplete(input, dir) {
  if (!completeState) return;
  const n = completeState.hits.length;
  if (completeState.index < 0) completeState.index = dir > 0 ? 0 : n - 1;
  else completeState.index = (completeState.index + dir + n) % n;
  writeHit(input);
  renderComplete();
}

export function initPythonConsole({ getVars }) {
  const form = $('python-form');
  const input = $('python-input');
  if (!form || !input || form.dataset.bound === '1') return;
  form.dataset.bound = '1';

  window.droid2webEnsurePython = () => {
    ensurePython(getVars).catch(() => {});
  };

  const submit = async () => {
    const src = input.value;
    if (!src.trim()) return;
    hideComplete();
    history.push(src);
    historyIdx = history.length;
    input.value = '';
    syncInputHighlight();
    try {
      await ensurePython(getVars);
      runSource(src, getVars);
    } catch (_) { /* status already set */ }
  };

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submit();
  });

  input.addEventListener('input', () => {
    hideComplete();
    syncInputHighlight();
  });
  input.addEventListener('scroll', () => syncInputHighlight());

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      if (completeState && completeState.hits.length > 1) {
        cycleComplete(input, e.shiftKey ? -1 : 1);
        return;
      }
      startComplete(input);
      return;
    }
    if (e.key === 'Escape') {
      hideComplete();
      return;
    }
    if (completeState && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      cycleComplete(input, e.key === 'ArrowDown' ? 1 : -1);
      return;
    }
    if (completeState && e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      hideComplete();
      return;
    }
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      form.requestSubmit();
      return;
    }
    if (e.key === 'Enter' && !e.shiftKey && !input.value.includes('\n')) {
      e.preventDefault();
      form.requestSubmit();
      return;
    }
    if (e.key === 'ArrowUp' && (input.selectionStart === 0 || !input.value)) {
      if (!history.length) return;
      e.preventDefault();
      historyIdx = Math.max(0, historyIdx - 1);
      input.value = history[historyIdx] || '';
      syncInputHighlight();
    } else if (e.key === 'ArrowDown' && !completeState && historyIdx >= 0 && historyIdx < history.length) {
      e.preventDefault();
      historyIdx += 1;
      input.value = historyIdx >= history.length ? '' : history[historyIdx];
      syncInputHighlight();
    }
  });

  $('python-complete')?.addEventListener('mousedown', (e) => {
    const item = e.target.closest?.('.python-complete-item');
    if (!item || !completeState) return;
    e.preventDefault();
    const i = Number(item.dataset.i);
    applyComplete(input, completeState.hits[i]);
    input.focus();
  });

  $('python-clear')?.addEventListener('click', () => {
    const log = $('python-log');
    if (log) log.textContent = '';
  });

  document.querySelector('[data-tab="python-tab"]')?.addEventListener('click', () => {
    window.droid2webEnsurePython?.();
    requestAnimationFrame(() => input.focus());
  });

  syncInputHighlight();
}

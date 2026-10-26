/**
 * Find tab — on-demand ASC findrefs (string, type, method, field, extends, impl) and getclass.
 */

/** @type {{ runInParseWorker: Function, switchToCenterTab: Function, normalizeWasmResult?: Function, timeoutMs?: number, getFindBytes?: Function, getDecompileOptions?: Function, navigateToRef?: Function, highlightJava?: Function, escapeHtml?: Function, escapeAttr?: Function, formatHexOffset?: Function, setStatus?: Function } | null} */
let api = null;

const RECENT_KEY = 'droid2web.find.recent';

const KINDS = {
  string: {
    label: 'String',
    placeholder: 'Text used by const-string…',
    hint: 'Every const-string and encoded use of this text. Fast RawDex scan — no full xref index.',
    action: 'Find references',
    example: { value: 'http://', className: '' },
  },
  type: {
    label: 'Type',
    placeholder: 'Class name, e.g. android.app.Activity',
    hint: 'References to a type: check-cast, new-instance, const-class, and method signatures.',
    action: 'Find references',
    example: { value: 'android.app.Activity', className: '' },
  },
  method: {
    label: 'Method',
    placeholder: 'Method name, e.g. startActivity',
    hint: 'Invoke sites. Set the declaring class to limit the search to one type.',
    action: 'Find references',
    example: { value: 'startActivity', className: 'android.app.Activity' },
  },
  field: {
    label: 'Field',
    placeholder: 'Field name, e.g. TAG',
    hint: 'iget, sget, iput, and sput sites. Set the declaring class to limit the owner.',
    action: 'Find references',
    example: { value: 'TAG', className: '' },
  },
  extends: {
    label: 'Extends',
    placeholder: 'Base class, e.g. android.app.Activity',
    hint: 'Classes whose direct superclass is this type (ASC findrefs extends).',
    action: 'Find subclasses',
    hierarchy: true,
    hitLabel: 'subclass',
    example: { value: 'android.app.Activity', className: '' },
  },
  impl: {
    label: 'Implements',
    placeholder: 'Interface, e.g. java.io.Serializable',
    hint: 'Classes that directly implement this interface (ASC findrefs impl).',
    action: 'Find implementors',
    hierarchy: true,
    hitLabel: 'implementor',
    example: { value: 'java.io.Serializable', className: '' },
  },
};

function isHierarchy(k) {
  return !!KINDS[k]?.hierarchy;
}

/** @type {object | null} */
let lastInfo = null;
/** Index into lastInfo.sites, or -1. */
let selected = -1;
/** @type {string} */
let sourceText = '';

function $(id) {
  return document.getElementById(id);
}

function esc(s) {
  if (typeof api?.escapeHtml === 'function') return api.escapeHtml(s);
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(s) {
  if (typeof api?.escapeAttr === 'function') return api.escapeAttr(s);
  return esc(s).replace(/'/g, '&#39;');
}

function formatOff(n) {
  if (typeof api?.formatHexOffset === 'function') return api.formatHexOffset(n);
  const v = Number(n);
  if (!Number.isFinite(v)) return '';
  return `0x${(v >>> 0).toString(16)}`;
}

function setStatus(msg) {
  const el = $('find-status');
  if (el) el.textContent = msg || '';
}

function setBusy(busy) {
  const a = $('find-refs-btn');
  const b = $('find-getclass-btn');
  if (a) a.disabled = !!busy;
  if (b) b.disabled = !!busy;
}

function kind() {
  return $('find-kind')?.value || 'string';
}

function syncKindUi(next) {
  const k = KINDS[next] ? next : 'string';
  const sel = $('find-kind');
  if (sel) sel.value = k;
  const panel = $('find-panel');
  if (panel) panel.dataset.kind = k;
  document.querySelectorAll('input[name="find-kind-ui"]').forEach((el) => {
    el.checked = el.value === k;
  });
  const input = $('find-value');
  const meta = KINDS[k];
  if (input && meta) input.placeholder = meta.placeholder;
  const hint = $('find-hint');
  if (hint && meta) {
    hint.innerHTML = `${esc(meta.hint)} <kbd>Enter</kbd> searches. <kbd>↑</kbd><kbd>↓</kbd> move. <kbd>Enter</kbd> on a hit opens it.`;
  }
  const btn = $('find-refs-btn');
  if (btn && meta) {
    btn.textContent = meta.action || 'Find references';
    btn.title = isHierarchy(k)
      ? 'List matching classes across every DEX in the file'
      : 'Search references across every DEX in the file';
  }
}

function normalize(raw) {
  let result = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (typeof api?.normalizeWasmResult === 'function') {
    result = api.normalizeWasmResult(result) || result;
    if (result?.data) result.data = api.normalizeWasmResult(result.data) || result.data;
  }
  return result;
}

function siteOf(s) {
  return {
    className: s.class_name || s.className || '',
    methodName: s.method_name || s.methodName || '',
    dex: s.dex_file || s.dexFile || '',
    off: s.offset,
    fileOff: s.file_offset ?? s.fileOffset,
    ci: s.class_idx ?? s.classIdx,
    mi: s.method_idx_in_class ?? s.methodIdxInClass,
    pool: s.pool_idx ?? s.poolIdx,
  };
}

function visibleIndexes() {
  const sites = Array.isArray(lastInfo?.sites) ? lastInfo.sites : [];
  const q = ($('find-filter')?.value || '').trim().toLowerCase();
  const out = [];
  sites.forEach((s, i) => {
    if (!q) {
      out.push(i);
      return;
    }
    const hit = siteOf(s);
    const blob = `${hit.className} ${hit.methodName} ${hit.dex}`.toLowerCase();
    if (blob.includes(q)) out.push(i);
  });
  return out;
}

function paintEmpty() {
  const host = $('find-results');
  if (!host) return;
  const cards = Object.entries(KINDS)
    .map(([id, meta]) => {
      const scope = meta.example.className
        ? `<span class="find-ex-scope">${esc(meta.example.className)}</span>`
        : '';
      return `<button type="button" class="find-example" data-kind="${escAttr(id)}" data-value="${escAttr(meta.example.value)}" data-class="${escAttr(meta.example.className)}"><span class="find-ex-kind">${esc(meta.label)}</span><span class="find-ex-value">${esc(meta.example.value)}</span>${scope}</button>`;
    })
    .join('');
  host.innerHTML = `<div class="find-empty">
    <h2>Find where something is used</h2>
    <p>On-demand ASC findrefs over every DEX — strings, types, methods, fields, subclasses, and interface implementors — without building a full xref index. Open a hit in Code or decompile a class here.</p>
    <div class="find-examples">${cards}</div>
  </div>`;
}

function renderSites(info) {
  lastInfo = info;
  selected = Array.isArray(info?.sites) && info.sites.length ? 0 : -1;
  const filter = $('find-filter');
  if (filter) {
    filter.hidden = !info?.sites?.length;
    filter.value = '';
  }
  paintResults();
  if (selected >= 0) showHit(selected);
  else clearInspector();
}

function paintResults() {
  const host = $('find-results');
  if (!host || !lastInfo) return;
  const sites = Array.isArray(lastInfo.sites) ? lastInfo.sites : [];
  const shown = visibleIndexes();
  const hierarchy = isHierarchy(lastInfo.kind);
  const nouns = hierarchy ? 'classes' : 'usages';
  if (!sites.length) {
    host.innerHTML = `<div class="find-empty"><h2>No ${nouns}</h2><p>Nothing matched ${esc(lastInfo.kind || '')} <strong>${esc(lastInfo.value || '')}</strong>.</p></div>`;
    return;
  }
  if (!shown.length) {
    host.innerHTML = `<div class="find-empty"><h2>No matches in this list</h2><p>Clear the filter to see all ${sites.length} ${nouns}.</p></div>`;
    return;
  }
  const trunc = lastInfo.truncated
    ? `<p class="find-trunc">Showing the first ${sites.length} ${nouns}. Narrow the query to see the rest.</p>`
    : '';

  if (hierarchy) {
    /** @type {Map<string, number[]>} */
    const byPkg = new Map();
    for (const i of shown) {
      const name = siteOf(sites[i]).className || '(unknown class)';
      const pkg = name.includes('.') ? name.slice(0, name.lastIndexOf('.')) : '(default)';
      if (!byPkg.has(pkg)) byPkg.set(pkg, []);
      byPkg.get(pkg).push(i);
    }
    const role = KINDS[lastInfo.kind]?.hitLabel || 'class';
    const blocks = [...byPkg.entries()]
      .map(([pkg, idxs]) => {
        const rows = idxs
          .map((i) => {
            const hit = siteOf(sites[i]);
            const simple = hit.className.split('.').pop() || hit.className;
            const dexShort = hit.dex ? String(hit.dex).split('/').pop() : '';
            const on = i === selected ? ' is-on' : '';
            return `<button type="button" class="find-hit find-hit-class${on}" data-index="${i}" data-class="${escAttr(hit.className)}" data-method="" data-dex="${escAttr(hit.dex)}" data-class-idx="${hit.ci ?? ''}" data-method-idx="" data-offset=""><span class="find-hit-method">${esc(simple)}</span><span class="find-hit-meta muted">${esc(role)}${dexShort ? ` · ${esc(dexShort)}` : ''}</span></button>`;
          })
          .join('');
        return `<section class="find-group"><header class="find-group-head"><span class="find-group-name">${esc(pkg)}</span><span class="find-group-count">${idxs.length}</span></header><div class="find-hit-list">${rows}</div></section>`;
      })
      .join('');
    host.innerHTML = `${trunc}${blocks}`;
    host.querySelector('.find-hit.is-on')?.scrollIntoView({ block: 'nearest' });
    return;
  }

  /** @type {Map<string, number[]>} */
  const groups = new Map();
  for (const i of shown) {
    const name = siteOf(sites[i]).className || '(unknown class)';
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(i);
  }
  const blocks = [...groups.entries()]
    .map(([className, idxs]) => {
      const rows = idxs
        .map((i) => {
          const hit = siteOf(sites[i]);
          const dexShort = hit.dex ? String(hit.dex).split('/').pop() : '';
          const on = i === selected ? ' is-on' : '';
          return `<button type="button" class="find-hit${on}" data-index="${i}" data-class="${escAttr(hit.className)}" data-method="${escAttr(hit.methodName)}" data-dex="${escAttr(hit.dex)}" data-class-idx="${hit.ci ?? ''}" data-method-idx="${hit.mi ?? ''}" data-offset="${hit.off ?? ''}"><span class="find-hit-method">${esc(hit.methodName || '(unknown)')}</span><span class="find-hit-meta muted">${esc(formatOff(hit.off))}${dexShort ? ` · ${esc(dexShort)}` : ''}</span></button>`;
        })
        .join('');
      const simple = className.split('.').pop() || className;
      const pkg = className.includes('.') ? className.slice(0, className.lastIndexOf('.')) : '';
      return `<section class="find-group"><header class="find-group-head"><span class="find-group-name">${esc(simple)}</span><span class="find-group-pkg muted">${esc(pkg)}</span><span class="find-group-count">${idxs.length}</span></header><div class="find-hit-list">${rows}</div></section>`;
    })
    .join('');
  host.innerHTML = `${trunc}${blocks}`;
  host.querySelector('.find-hit.is-on')?.scrollIntoView({ block: 'nearest' });
}

function clearInspector() {
  const empty = $('find-inspector-empty');
  const fields = $('find-inspector-fields');
  const code = $('find-source-code');
  const meta = $('find-source-meta');
  const openBtn = $('find-source-open');
  const copyBtn = $('find-source-copy');
  if (empty) empty.hidden = false;
  if (fields) {
    fields.hidden = true;
    fields.innerHTML = '';
  }
  if (code && !sourceText) code.hidden = true;
  if (meta && !sourceText) meta.textContent = 'No selection';
  if (openBtn && !openBtn.dataset.class) openBtn.hidden = true;
  if (openBtn) {
    openBtn.textContent = 'Open';
    openBtn.title = 'Open this method in Code';
  }
  if (copyBtn && !sourceText) copyBtn.hidden = true;
}

function showHit(index) {
  const sites = lastInfo?.sites || [];
  const raw = sites[index];
  if (!raw) return;
  selected = index;
  const hit = siteOf(raw);
  const hierarchy = isHierarchy(lastInfo?.kind);
  const empty = $('find-inspector-empty');
  const fields = $('find-inspector-fields');
  const meta = $('find-source-meta');
  const openBtn = $('find-source-open');
  const copyBtn = $('find-source-copy');
  if (empty) empty.hidden = true;
  if (meta) {
    meta.textContent = hierarchy
      ? hit.className
      : `${hit.className}.${hit.methodName || '?'}`;
  }
  if (fields) {
    const rows = hierarchy
      ? [
          ['Class', hit.className],
          ['Relation', KINDS[lastInfo.kind]?.hitLabel || lastInfo.kind],
          ['Base / interface', lastInfo.value || '—'],
          ['DEX', hit.dex || '—'],
        ]
      : [
          ['Class', hit.className],
          ['Method', hit.methodName || '—'],
          ['DEX', hit.dex || '—'],
          ['Offset', formatOff(hit.off) || '—'],
          ['File offset', formatOff(hit.fileOff) || '—'],
          ['Pool', hit.pool != null ? String(hit.pool) : '—'],
        ];
    fields.hidden = false;
    fields.innerHTML = rows
      .map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`)
      .join('');
  }
  if (openBtn) {
    openBtn.hidden = !hit.className;
    openBtn.textContent = hierarchy ? 'Open class' : 'Open';
    openBtn.title = hierarchy ? 'Open this class in Code' : 'Open this method in Code';
    openBtn.dataset.class = hit.className;
    openBtn.dataset.method = hierarchy ? '' : hit.methodName;
    openBtn.dataset.dex = hit.dex;
    openBtn.dataset.classIdx = hit.ci ?? '';
    openBtn.dataset.methodIdx = hierarchy ? '' : (hit.mi ?? '');
    openBtn.dataset.offset = hierarchy ? '' : (hit.off ?? '');
  }
  if (copyBtn) {
    copyBtn.hidden = false;
    copyBtn.dataset.mode = 'hit';
    copyBtn.dataset.source = hierarchy
      ? `${hit.className}${hit.dex ? ` (${hit.dex})` : ''}`
      : `${hit.className}.${hit.methodName} @ ${formatOff(hit.off)}${hit.dex ? ` (${hit.dex})` : ''}`;
  }
  paintResults();
}

function openHit(index) {
  const sites = lastInfo?.sites || [];
  const raw = sites[index];
  if (!raw || !api?.navigateToRef) return;
  showHit(index);
  const hit = siteOf(raw);
  const fake = document.createElement('button');
  fake.setAttribute('data-class', hit.className);
  fake.setAttribute('data-method', hit.methodName);
  fake.setAttribute('data-dex', hit.dex);
  fake.setAttribute('data-offset', hit.off ?? '');
  api.navigateToRef(fake);
}

function moveSelection(delta) {
  const shown = visibleIndexes();
  if (!shown.length) return;
  const pos = Math.max(0, shown.indexOf(selected));
  const next = shown[Math.min(shown.length - 1, Math.max(0, pos + delta))];
  showHit(next);
  $('find-results')?.focus();
}

function showSource(info) {
  const meta = $('find-source-meta');
  const code = $('find-source-code');
  const openBtn = $('find-source-open');
  const copyBtn = $('find-source-copy');
  const empty = $('find-inspector-empty');
  if (!code) return;
  if (empty) empty.hidden = true;
  const name = info?.name || '';
  const path = info?.relative_path || info?.relativePath || '';
  if (meta) meta.textContent = path || name || 'class';
  sourceText = typeof info?.source === 'string' ? info.source : '';
  code.hidden = false;
  if (typeof api?.highlightJava === 'function' && sourceText) {
    code.innerHTML = api.highlightJava(sourceText);
  } else {
    code.textContent = sourceText || '(empty)';
  }
  if (openBtn && name) {
    openBtn.hidden = false;
    openBtn.dataset.class = name;
    openBtn.dataset.method = '';
    openBtn.dataset.offset = '';
    openBtn.dataset.classIdx = '';
    openBtn.dataset.methodIdx = '';
  }
  if (copyBtn) {
    copyBtn.hidden = !sourceText;
    copyBtn.dataset.mode = 'source';
    copyBtn.dataset.source = sourceText;
  }
}

function loadRecent() {
  try {
    const raw = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]');
    return Array.isArray(raw) ? raw.slice(0, 8) : [];
  } catch {
    return [];
  }
}

function rememberQuery(entry) {
  const recent = loadRecent().filter(
    (r) => !(r.kind === entry.kind && r.value === entry.value && r.className === entry.className),
  );
  recent.unshift(entry);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, 8)));
  } catch {
    /* private mode */
  }
  paintRecent();
}

function paintRecent() {
  const host = $('find-recent');
  if (!host) return;
  const recent = loadRecent();
  if (!recent.length) {
    host.hidden = true;
    host.innerHTML = '';
    return;
  }
  host.hidden = false;
  host.innerHTML = `<span class="muted">Recent</span>${recent
    .map(
      (r, i) =>
        `<button type="button" class="find-recent-chip" data-recent="${i}">${esc(KINDS[r.kind]?.label || r.kind)} ${esc(r.value)}</button>`,
    )
    .join('')}`;
}

function applyQuery({ kind: k, value, className, exact }) {
  syncKindUi(k || 'string');
  if ($('find-value')) $('find-value').value = value || '';
  if ($('find-class')) $('find-class').value = className || '';
  if ($('find-exact-class') && exact != null) $('find-exact-class').checked = !!exact;
}

async function runFindRefs() {
  if (!api) return;
  const bytes = typeof api.getFindBytes === 'function' ? api.getFindBytes() : null;
  if (!bytes?.length) {
    setStatus('Load a DEX or APK first');
    return;
  }
  const k = kind();
  const value = ($('find-value')?.value || '').trim();
  const classFilter = ($('find-class')?.value || '').trim();
  const exactClass = $('find-exact-class')?.checked !== false;
  if (!value) {
    setStatus('Enter a name to search');
    $('find-value')?.focus();
    return;
  }
  setBusy(true);
  setStatus(`Searching ${KINDS[k]?.label || k}…`);
  try {
    const copy = bytes.slice();
    const raw = await api.runInParseWorker(
      'find_refs',
      {
        bytes: copy.buffer,
        kind: k,
        value,
        classFilter: k === 'method' || k === 'field' ? classFilter || undefined : undefined,
        exactClass,
      },
      { timeoutMs: api.timeoutMs || 120000, transfer: [copy.buffer] },
    );
    const result = normalize(raw);
    if (!result?.ok) throw new Error(result?.error || 'find_refs failed');
    const info = result.data || result;
    renderSites(info);
    const n = info.sites?.length || 0;
    const hierarchy = isHierarchy(info.kind || k);
    if (!n) {
      setStatus(hierarchy ? 'No classes' : 'No usages');
    } else if (hierarchy) {
      setStatus(`${n} class${n === 1 ? '' : 'es'} · ${info.dex_count || 1} DEX`);
    } else {
      const classes = new Set((info.sites || []).map((s) => siteOf(s).className)).size;
      setStatus(
        `${n} usage${n === 1 ? '' : 's'} in ${classes} class${classes === 1 ? '' : 'es'} · ${info.dex_count || 1} DEX`,
      );
    }
    rememberQuery({ kind: k, value, className: classFilter, exact: exactClass });
    if (n) $('find-results')?.focus();
  } catch (e) {
    setStatus(e?.message || String(e));
    const host = $('find-results');
    if (host) {
      host.innerHTML = `<div class="find-empty"><h2>Search failed</h2><p>${esc(e?.message || String(e))}</p></div>`;
    }
  } finally {
    setBusy(false);
  }
}

async function runGetClass() {
  if (!api) return;
  const bytes = typeof api.getFindBytes === 'function' ? api.getFindBytes() : null;
  if (!bytes?.length) {
    setStatus('Load a DEX or APK first');
    return;
  }
  const className = ($('find-class')?.value || $('find-value')?.value || '').trim();
  if (!className) {
    setStatus('Enter a class name');
    ($('find-class') || $('find-value'))?.focus();
    return;
  }
  setBusy(true);
  setStatus(`Decompiling ${className}…`);
  try {
    const copy = bytes.slice();
    const options = typeof api.getDecompileOptions === 'function' ? api.getDecompileOptions() : undefined;
    const raw = await api.runInParseWorker(
      'getclass_java',
      { bytes: copy.buffer, className, options },
      { timeoutMs: api.timeoutMs || 180000, transfer: [copy.buffer] },
    );
    const result = normalize(raw);
    if (!result?.ok) throw new Error(result?.error || 'getclass failed');
    const info = result.data || result;
    showSource(info);
    setStatus(`Decompiled ${info.name || className}`);
    if (typeof api.switchToCenterTab === 'function') api.switchToCenterTab('find-tab');
  } catch (e) {
    setStatus(e?.message || String(e));
  } finally {
    setBusy(false);
  }
}

function bindUi() {
  document.querySelectorAll('input[name="find-kind-ui"]').forEach((el) => {
    el.addEventListener('change', () => {
      if (el.checked) syncKindUi(el.value);
    });
  });
  $('find-refs-btn')?.addEventListener('click', () => runFindRefs());
  $('find-getclass-btn')?.addEventListener('click', () => runGetClass());
  $('find-value')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      runFindRefs();
    }
  });
  $('find-class')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) runGetClass();
      else runFindRefs();
    }
  });
  $('find-filter')?.addEventListener('input', () => {
    const shown = visibleIndexes();
    if (selected >= 0 && !shown.includes(selected)) selected = shown[0] ?? -1;
    paintResults();
    const n = lastInfo?.sites?.length || 0;
    setStatus(shown.length === n ? `${n} usages` : `${shown.length} of ${n} usages`);
  });
  $('find-results')?.addEventListener('click', (e) => {
    const example = e.target.closest?.('.find-example');
    if (example) {
      applyQuery({
        kind: example.dataset.kind,
        value: example.dataset.value,
        className: example.dataset.class,
        exact: true,
      });
      $('find-value')?.focus();
      return;
    }
    const hit = e.target.closest?.('.find-hit');
    if (!hit) return;
    const index = Number(hit.dataset.index);
    if (!Number.isFinite(index)) return;
    showHit(index);
  });
  $('find-results')?.addEventListener('dblclick', (e) => {
    const hit = e.target.closest?.('.find-hit');
    if (!hit) return;
    const index = Number(hit.dataset.index);
    if (Number.isFinite(index)) openHit(index);
  });
  $('find-results')?.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveSelection(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveSelection(-1);
    } else if (e.key === 'Enter' && selected >= 0) {
      e.preventDefault();
      openHit(selected);
    }
  });
  $('find-recent')?.addEventListener('click', (e) => {
    const chip = e.target.closest?.('.find-recent-chip');
    if (!chip) return;
    const entry = loadRecent()[Number(chip.dataset.recent)];
    if (!entry) return;
    applyQuery(entry);
    runFindRefs();
  });
  $('find-source-open')?.addEventListener('click', () => {
    const btn = $('find-source-open');
    if (!btn || !api?.navigateToRef) return;
    // Prefer the inspector selection when it matches the Open button, otherwise
    // open the decompiled class (or whatever class the button is bound to).
    const btnClass = btn.dataset.class || '';
    const btnMethod = btn.dataset.method || '';
    if (selected >= 0 && lastInfo?.sites?.[selected]) {
      const hit = siteOf(lastInfo.sites[selected]);
      if (hit.className === btnClass && (btnMethod === '' || hit.methodName === btnMethod)) {
        openHit(selected);
        return;
      }
    }
    api.navigateToRef(btn);
  });
  $('find-source-copy')?.addEventListener('click', async () => {
    const src = $('find-source-copy')?.dataset?.source || '';
    if (!src) return;
    try {
      await navigator.clipboard.writeText(src);
      setStatus($('find-source-copy')?.dataset?.mode === 'source' ? 'Source copied' : 'Location copied');
    } catch {
      setStatus('Copy failed');
    }
  });
  syncKindUi(kind());
  paintRecent();
  paintEmpty();
}

/**
 * @param {typeof api} hooks
 */
export function initFindRefsUi(hooks) {
  api = hooks || null;
  bindUi();
}

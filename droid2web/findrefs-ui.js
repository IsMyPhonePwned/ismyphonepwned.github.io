/**
 * ASC findrefs / getclass UI (Find tab).
 */

/** @type {{ runInParseWorker: Function, switchToCenterTab: Function, normalizeWasmResult?: Function, timeoutMs?: number, getFindBytes?: Function, getDecompileOptions?: Function, navigateToRef?: Function, highlightJava?: Function, escapeHtml?: Function, escapeAttr?: Function, formatHexOffset?: Function, setStatus?: Function } | null} */
let api = null;

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

function normalize(raw) {
  let result = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (typeof api?.normalizeWasmResult === 'function') {
    result = api.normalizeWasmResult(result) || result;
    if (result?.data) result.data = api.normalizeWasmResult(result.data) || result.data;
  }
  return result;
}

function renderSites(info) {
  const host = $('find-results');
  if (!host) return;
  const sites = Array.isArray(info?.sites) ? info.sites : [];
  if (!sites.length) {
    host.innerHTML = `<div class="muted center-text">No sites for ${esc(info?.kind || '')} ${esc(JSON.stringify(info?.value || ''))}</div>`;
    return;
  }
  const trunc = info.truncated ? ' <span class="muted">(truncated)</span>' : '';
  const rows = sites
    .map((s) => {
      const className = s.class_name || s.className || '';
      const methodName = s.method_name || s.methodName || '';
      const dex = s.dex_file || s.dexFile || '';
      const off = s.offset;
      const fileOff = s.file_offset ?? s.fileOffset;
      const ci = s.class_idx ?? s.classIdx;
      const mi = s.method_idx_in_class ?? s.methodIdxInClass;
      const simple = className.split('.').pop() || className || '?';
      const dexShort = dex ? String(dex).split('/').pop() : '';
      return `<button type="button" class="find-hit" data-class="${escAttr(className)}" data-method="${escAttr(methodName)}" data-dex="${escAttr(dex)}" data-class-idx="${ci ?? ''}" data-method-idx="${mi ?? ''}" data-offset="${off ?? ''}" title="${escAttr(`${className}.${methodName} @ ${formatOff(off)} · file ${formatOff(fileOff)}${dex ? ' · ' + dex : ''}`)}"><span class="find-hit-loc">${esc(simple)}.${esc(methodName || '?')}</span><span class="find-hit-meta muted">${esc(formatOff(off))}${dexShort ? ` · ${esc(dexShort)}` : ''}</span></button>`;
    })
    .join('');
  host.innerHTML = `<div class="find-results-meta muted">${sites.length} site(s) · ${info.dex_count || 1} DEX${trunc}</div><div class="find-hit-list">${rows}</div>`;
}

function showSource(info) {
  const aside = $('find-source');
  const meta = $('find-source-meta');
  const code = $('find-source-code');
  const openBtn = $('find-source-open');
  const copyBtn = $('find-source-copy');
  if (!aside || !code) return;
  aside.hidden = false;
  const name = info?.name || '';
  const path = info?.relative_path || info?.relativePath || '';
  if (meta) meta.textContent = path || name || 'class';
  const src = typeof info?.source === 'string' ? info.source : '';
  if (typeof api?.highlightJava === 'function' && src) {
    code.innerHTML = api.highlightJava(src);
  } else {
    code.textContent = src || '(empty)';
  }
  if (openBtn) {
    openBtn.hidden = !name;
    openBtn.dataset.class = name;
  }
  if (copyBtn) {
    copyBtn.hidden = !src;
    copyBtn.dataset.source = src;
  }
}

async function runFindRefs() {
  if (!api) return;
  const bytes = typeof api.getFindBytes === 'function' ? api.getFindBytes() : null;
  if (!bytes?.length) {
    setStatus('Load a DEX or APK first');
    return;
  }
  const kind = $('find-kind')?.value || 'string';
  const value = ($('find-value')?.value || '').trim();
  const classFilter = ($('find-class')?.value || '').trim();
  const exactClass = $('find-exact-class')?.checked !== false;
  if (!value) {
    setStatus('Enter a needle');
    $('find-value')?.focus();
    return;
  }
  setBusy(true);
  setStatus(`Searching ${kind}…`);
  try {
    const copy = bytes.slice();
    const raw = await api.runInParseWorker(
      'find_refs',
      {
        bytes: copy.buffer,
        kind,
        value,
        classFilter: classFilter || undefined,
        exactClass,
      },
      { timeoutMs: api.timeoutMs || 120000, transfer: [copy.buffer] }
    );
    const result = normalize(raw);
    if (!result?.ok) throw new Error(result?.error || 'find_refs failed');
    const info = result.data || result;
    renderSites(info);
    setStatus(`${info.sites?.length || 0} site(s)`);
  } catch (e) {
    setStatus(e?.message || String(e));
    const host = $('find-results');
    if (host) host.innerHTML = `<div class="muted center-text">${esc(e?.message || String(e))}</div>`;
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
  setStatus(`getclass ${className}…`);
  try {
    const copy = bytes.slice();
    const options =
      typeof api.getDecompileOptions === 'function' ? api.getDecompileOptions() : undefined;
    const raw = await api.runInParseWorker(
      'getclass_java',
      { bytes: copy.buffer, className, options },
      { timeoutMs: api.timeoutMs || 180000, transfer: [copy.buffer] }
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
  $('find-results')?.addEventListener('click', (e) => {
    const hit = e.target.closest?.('.find-hit');
    if (!hit || !api?.navigateToRef) return;
    api.navigateToRef(hit);
  });
  $('find-source-open')?.addEventListener('click', () => {
    const className = $('find-source-open')?.dataset?.class || '';
    if (!className || !api?.navigateToRef) return;
    const fake = document.createElement('button');
    fake.setAttribute('data-class', className);
    fake.setAttribute('data-method', '');
    fake.setAttribute('data-offset', '');
    api.navigateToRef(fake);
  });
  $('find-source-copy')?.addEventListener('click', async () => {
    const src = $('find-source-copy')?.dataset?.source || $('find-source-code')?.textContent || '';
    if (!src) return;
    try {
      await navigator.clipboard.writeText(src);
      setStatus('Copied');
    } catch (_) {
      setStatus('Copy failed');
    }
  });
}

/**
 * @param {typeof api} hooks
 */
export function initFindRefsUi(hooks) {
  api = hooks || null;
  bindUi();
}

/**
 * DEX-only APK/DEX compare UI.
 *
 * Structural matching runs in WASM (SimHash + LSH). Decompiled source is
 * fetched on demand for the selected method, then shown as a collapsed
 * GitHub-style hunk diff with intra-line highlights.
 */

const CLASS_RENDER_CAP = 400;
const LINE_DIFF_CELL_CAP = 1_500_000;
const HUNK_CONTEXT = 3;
const DECOMP_CACHE_MAX = 80;
const ANDROID_RE = /^(android\.|androidx\.|android$|androidx$)/;
const TOKEN_RE = /(\s+|\/\/|\/\*|\*\/|[{}()[\];,.]|==|!=|<=|>=|&&|\|\||\+\+|--)/;

export function isAndroidFrameworkClass(name) {
  const n = String(name || '').trim();
  return ANDROID_RE.test(n);
}

function splitLines(text) {
  if (text == null || text === '') return [];
  return String(text).split('\n');
}

/** LCS (or hashed-anchor fallback) line alignment. Exported for unit tests. */
export function diffLines(aText, bText) {
  const a = splitLines(aText);
  const b = splitLines(bText);
  let start = 0;
  const min = Math.min(a.length, b.length);
  while (start < min && a[start] === b[start]) start++;
  let aEnd = a.length;
  let bEnd = b.length;
  while (aEnd > start && bEnd > start && a[aEnd - 1] === b[bEnd - 1]) {
    aEnd--;
    bEnd--;
  }
  const aMid = a.slice(start, aEnd);
  const bMid = b.slice(start, bEnd);
  const cells = aMid.length * bMid.length;
  const mid = cells === 0
    ? [
        ...aMid.map((line) => ({ t: 'del', a: line, b: '' })),
        ...bMid.map((line) => ({ t: 'add', a: '', b: line })),
      ]
    : cells > LINE_DIFF_CELL_CAP
      ? anchoredDiff(aMid, bMid)
      : lcsDiff(aMid, bMid);
  const head = a.slice(0, start).map((line) => ({ t: 'eq', a: line, b: line }));
  const tail = a.slice(aEnd).map((line) => ({ t: 'eq', a: line, b: line }));
  return head.concat(mid, tail);
}

function lcsDiff(a, b) {
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    const ai = a[i];
    const row = dp[i];
    const next = dp[i + 1];
    for (let j = m - 1; j >= 0; j--) {
      row[j] = ai === b[j] ? next[j + 1] + 1 : next[j] >= row[j + 1] ? next[j] : row[j + 1];
    }
  }
  const rows = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      rows.push({ t: 'eq', a: a[i], b: b[j] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ t: 'del', a: a[i], b: '' });
      i++;
    } else {
      rows.push({ t: 'add', a: '', b: b[j] });
      j++;
    }
  }
  while (i < n) rows.push({ t: 'del', a: a[i++], b: '' });
  while (j < m) rows.push({ t: 'add', a: '', b: b[j++] });
  return rows;
}

/** Linear unique-line anchors when LCS would allocate too much. */
function anchoredDiff(a, b) {
  const pos = new Map();
  for (let j = 0; j < b.length; j++) {
    const line = b[j];
    const list = pos.get(line);
    if (list) list.push(j);
    else pos.set(line, [j]);
  }
  const matches = [];
  let lastJ = -1;
  for (let i = 0; i < a.length; i++) {
    const js = pos.get(a[i]);
    if (!js) continue;
    let found = -1;
    for (let k = 0; k < js.length; k++) {
      if (js[k] > lastJ) {
        found = js[k];
        break;
      }
    }
    if (found < 0) continue;
    matches.push([i, found]);
    lastJ = found;
  }
  const rows = [];
  let i = 0;
  let j = 0;
  for (const [mi, mj] of matches) {
    while (i < mi) rows.push({ t: 'del', a: a[i++], b: '' });
    while (j < mj) rows.push({ t: 'add', a: '', b: b[j++] });
    rows.push({ t: 'eq', a: a[i], b: b[j] });
    i++;
    j++;
  }
  while (i < a.length) rows.push({ t: 'del', a: a[i++], b: '' });
  while (j < b.length) rows.push({ t: 'add', a: '', b: b[j++] });
  return rows;
}

export function diffStats(rows) {
  let add = 0;
  let del = 0;
  for (const row of rows) {
    if (row.t === 'add') add++;
    else if (row.t === 'del') del++;
  }
  return { add, del };
}

/**
 * Collapse unchanged runs, keeping `context` equal lines around each change.
 * Returns `{ type: 'hunk'|'gap', start, end }` parts covering the full row list.
 */
export function collateHunks(rows, context = HUNK_CONTEXT) {
  const n = rows.length;
  if (!n) return [];
  const ranges = [];
  let i = 0;
  while (i < n) {
    if (rows[i].t === 'eq') {
      i++;
      continue;
    }
    let end = i + 1;
    while (end < n && rows[end].t !== 'eq') end++;
    ranges.push([Math.max(0, i - context), Math.min(n, end + context)]);
    i = end;
  }
  if (!ranges.length) return [{ type: 'gap', start: 0, end: n }];
  const merged = [];
  for (const [start, end] of ranges) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  const parts = [];
  let cursor = 0;
  for (const [start, end] of merged) {
    if (start > cursor) parts.push({ type: 'gap', start: cursor, end: start });
    parts.push({ type: 'hunk', start, end });
    cursor = end;
  }
  if (cursor < n) parts.push({ type: 'gap', start: cursor, end: n });
  return parts;
}

function tokenize(s) {
  return String(s).split(TOKEN_RE).filter((t) => t !== '');
}

/** Token-level LCS for a replacement pair. Empty arrays mean “highlight the whole line”. */
export function inlineTokenDiff(a, b) {
  const ta = tokenize(a);
  const tb = tokenize(b);
  if (!ta.length || !tb.length) return { a: [], b: [] };
  if (ta.length * tb.length > 6400) return { a: [], b: [] };
  const rows = lcsDiff(ta, tb);
  let eq = 0;
  for (const row of rows) if (row.t === 'eq') eq++;
  if (eq / Math.max(ta.length, tb.length) < 0.18) return { a: [], b: [] };
  return {
    a: rows.filter((r) => r.t !== 'add').map((r) => ({ t: r.t === 'eq' ? 'eq' : 'del', s: r.a })),
    b: rows.filter((r) => r.t !== 'del').map((r) => ({ t: r.t === 'eq' ? 'eq' : 'add', s: r.b })),
  };
}

function basename(path) {
  const s = String(path || '').replace(/\\/g, '/');
  const i = s.lastIndexOf('/');
  return i >= 0 ? s.slice(i + 1) : s;
}

function looksLikeDex(bytes) {
  if (!bytes || bytes.length < 8) return false;
  return bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a;
}

function looksLikeApk(bytes) {
  return bytes && bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;
}

function classTitle(cls) {
  const left = cls.left?.name;
  const right = cls.right?.name;
  if (left && right && left !== right) return `${left} → ${right}`;
  return right || left || '(unnamed class)';
}

function methodTitle(m) {
  const loc = m.left || m.right || {};
  const name = loc.name || '(method)';
  const proto = loc.proto || '';
  if (!proto) return name;
  const close = proto.lastIndexOf(')');
  if (close >= 0) {
    const params = proto.slice(0, close + 1);
    const ret = proto.slice(close + 1);
    return ret ? `${name}${params}: ${ret}` : `${name}${params}`;
  }
  return `${name}${proto}`;
}

function methodText(info) {
  if (!info) return '';
  const src = info.decompilation || info.source || '';
  if (src && String(src).trim()) return String(src);
  const rows = info.bytecode;
  if (Array.isArray(rows) && rows.length) {
    return rows
      .map((r) => {
        const off = r.offset != null ? String(r.offset).padStart(4, '0') : '';
        return `${off}  ${r.mnemonic || ''} ${r.operands || ''}`.trimEnd();
      })
      .join('\n');
  }
  return '';
}

function dexKeyVariants(name) {
  const n = String(name || '');
  const out = [n];
  const base = basename(n);
  if (base && base !== n) out.push(base);
  return out;
}

function numberRows(rows) {
  let lno = 0;
  let rno = 0;
  return rows.map((row) => {
    const leftNo = row.t === 'add' ? 0 : ++lno;
    const rightNo = row.t === 'del' ? 0 : ++rno;
    return { t: row.t, a: row.a, b: row.b, leftNo, rightNo };
  });
}

function marksHtml(parts, escapeHtml) {
  if (!parts.length) return '';
  let html = '';
  for (const p of parts) {
    const s = escapeHtml(p.s);
    if (p.t === 'eq') html += s;
    else html += `<mark class="dex-diff-ih dex-diff-ih-${p.t}">${s}</mark>`;
  }
  return html;
}

export function initDexDiff(deps) {
  const {
    runInParseWorker,
    getDexMethodInWorker,
    getApkFileContent,
    ensureWasm,
    escapeHtml,
    getLoadedFile,
    normalizeWasmResult,
    timeoutMs = 180000,
  } = deps;

  const statusEl = document.getElementById('dex-diff-status');
  const summaryEl = document.getElementById('dex-diff-summary');
  const filtersEl = document.getElementById('dex-diff-filters');
  const bodyEl = document.getElementById('dex-diff-body');
  const classesEl = document.getElementById('dex-diff-classes');
  const methodsEl = document.getElementById('dex-diff-methods');
  const sourceEl = document.getElementById('dex-diff-source');
  const runBtn = document.getElementById('dex-diff-run');
  const exportBtn = document.getElementById('dex-diff-export');
  const searchEl = document.getElementById('dex-diff-search');
  const androidCb = document.getElementById('dex-diff-show-android');
  const fileLeft = document.getElementById('dex-diff-file-left');
  const fileRight = document.getElementById('dex-diff-file-right');
  const nameLeft = document.getElementById('dex-diff-name-left');
  const nameRight = document.getElementById('dex-diff-name-right');
  const dropLeft = document.getElementById('dex-diff-drop-left');
  const dropRight = document.getElementById('dex-diff-drop-right');
  const useLeft = document.getElementById('dex-diff-use-left');
  const useRight = document.getElementById('dex-diff-use-right');

  if (!runBtn || !classesEl) return;

  const state = {
    left: null,
    right: null,
    report: null,
    leftDex: new Map(),
    rightDex: new Map(),
    filter: 'all',
    selectedClass: -1,
    selectedMethod: -1,
    busy: false,
    unified: true,
    collapse: true,
    loadGen: 0,
    decompCache: new Map(),
    view: null,
    expandedGaps: new Set(),
    searchTimer: 0,
    hunkCursor: 0,
  };

  function setStatus(text, isError) {
    if (!statusEl) return;
    statusEl.textContent = text || '';
    statusEl.classList.toggle('is-error', !!isError);
  }

  function unwrap(raw) {
    let result = raw;
    if (typeof normalizeWasmResult === 'function') result = normalizeWasmResult(raw) || raw;
    if (!result?.ok) throw new Error(result?.error || 'Worker returned an error');
    let data = result.data ?? result;
    if (typeof normalizeWasmResult === 'function') data = normalizeWasmResult(data) || data;
    return data;
  }

  async function readPickedFile(file) {
    const buf = await file.arrayBuffer();
    return { name: file.name || 'file', bytes: new Uint8Array(buf) };
  }

  function setSide(side, file) {
    state[side] = file;
    const el = side === 'left' ? nameLeft : nameRight;
    const drop = side === 'left' ? dropLeft : dropRight;
    if (el) {
      el.textContent = file ? file.name : 'Drop APK or DEX';
      el.classList.toggle('muted', !file);
    }
    drop?.classList.toggle('has-file', !!file);
    runBtn.disabled = !(state.left && state.right) || state.busy;
  }

  function bindDrop(el, fileInput, side) {
    if (!el) return;
    const onFile = async (file) => {
      if (!file) return;
      try {
        setSide(side, await readPickedFile(file));
      } catch (err) {
        setStatus(String(err.message || err), true);
      }
    };
    el.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      fileInput?.click();
    });
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput?.click();
      }
    });
    fileInput?.addEventListener('change', () => {
      const f = fileInput.files?.[0];
      fileInput.value = '';
      onFile(f);
    });
    el.addEventListener('dragover', (e) => {
      e.preventDefault();
      el.classList.add('drag-over');
    });
    el.addEventListener('dragleave', () => el.classList.remove('drag-over'));
    el.addEventListener('drop', (e) => {
      e.preventDefault();
      el.classList.remove('drag-over');
      onFile(e.dataTransfer?.files?.[0]);
    });
  }

  bindDrop(dropLeft, fileLeft, 'left');
  bindDrop(dropRight, fileRight, 'right');

  function refreshUseLoaded() {
    const loaded = typeof getLoadedFile === 'function' ? getLoadedFile() : null;
    const show = !!(loaded?.bytes?.length);
    if (useLeft) useLeft.hidden = !show;
    if (useRight) useRight.hidden = !show;
    const quick = document.getElementById('dex-diff-quick');
    const quickName = document.getElementById('dex-diff-quick-name');
    const hdr = document.getElementById('btn-compare-with');
    if (quick) quick.hidden = !show;
    if (quickName) quickName.textContent = show ? (loaded.name || 'loaded') : '—';
    if (hdr) {
      hdr.hidden = !show;
      hdr.title = show
        ? `Keep ${loaded.name} and pick another APK or DEX to compare`
        : 'Upload an APK or DEX first';
    }
    if (show && !state.left) {
      setSide('left', { name: loaded.name || 'loaded', bytes: loaded.bytes });
    }
  }

  function useLoaded(side) {
    const loaded = typeof getLoadedFile === 'function' ? getLoadedFile() : null;
    if (!loaded?.bytes?.length) {
      setStatus('Load an APK or DEX first, or drop a file here.', true);
      return;
    }
    setSide(side, { name: loaded.name || 'loaded', bytes: loaded.bytes });
  }

  async function compareAgainstFile(file) {
    const loaded = typeof getLoadedFile === 'function' ? getLoadedFile() : null;
    if (!loaded?.bytes?.length) {
      setStatus('Upload an APK or DEX first, then choose another to compare.', true);
      return;
    }
    if (!file) return;
    const other = file instanceof File ? await readPickedFile(file) : file;
    if (!other?.bytes?.length) {
      setStatus('Could not read the other APK or DEX.', true);
      return;
    }
    setSide('left', { name: loaded.name || 'loaded', bytes: loaded.bytes });
    setSide('right', other);
    if (typeof deps.switchToTab === 'function') deps.switchToTab('diff-tab');
    refreshUseLoaded();
    await runCompare();
  }

  useLeft?.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    useLoaded('left');
  });
  useRight?.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    useLoaded('right');
  });

  document.getElementById('diff-tab-btn')?.addEventListener('click', refreshUseLoaded);
  refreshUseLoaded();

  const quickEl = document.getElementById('dex-diff-quick');
  const quickPick = document.getElementById('dex-diff-quick-pick');
  const quickFile = document.getElementById('dex-diff-quick-file');
  quickPick?.addEventListener('click', () => quickFile?.click());
  quickFile?.addEventListener('change', () => {
    const f = quickFile.files?.[0];
    quickFile.value = '';
    if (f) compareAgainstFile(f);
  });
  quickEl?.addEventListener('dragover', (e) => {
    e.preventDefault();
    quickEl.classList.add('drag-over');
  });
  quickEl?.addEventListener('dragleave', () => quickEl.classList.remove('drag-over'));
  quickEl?.addEventListener('drop', (e) => {
    e.preventDefault();
    quickEl.classList.remove('drag-over');
    const f = e.dataTransfer?.files?.[0];
    if (f) compareAgainstFile(f);
  });

  async function cacheDexBlobs(file, meta) {
    const map = new Map();
    const bytes = file.bytes;
    const names = Array.isArray(meta?.dex_files) ? meta.dex_files : [];
    if (meta?.kind === 'dex' || looksLikeDex(bytes)) {
      const keys = names.length ? names : [file.name || 'classes.dex'];
      for (const k of keys) map.set(k, bytes);
      map.set(file.name, bytes);
      return map;
    }
    if (!looksLikeApk(bytes) && names.length === 0) {
      map.set(file.name, bytes);
      return map;
    }
    if (typeof ensureWasm === 'function') await ensureWasm();
    for (const name of names) {
      const extracted = getApkFileContent(bytes, name);
      if (!extracted || !extracted.length) continue;
      const u8 = extracted instanceof Uint8Array ? extracted.slice() : new Uint8Array(extracted);
      map.set(name, u8);
      map.set(basename(name), u8);
    }
    return map;
  }

  function dexBytes(map, loc) {
    if (!map || !loc) return null;
    for (const k of dexKeyVariants(loc.dex)) {
      if (map.has(k)) return map.get(k);
    }
    if (map.size === 1) return map.values().next().value;
    return null;
  }

  function cacheGet(key) {
    const hit = state.decompCache.get(key);
    if (!hit) return null;
    state.decompCache.delete(key);
    state.decompCache.set(key, hit);
    return hit;
  }

  function cacheSet(key, value) {
    if (state.decompCache.has(key)) state.decompCache.delete(key);
    state.decompCache.set(key, value);
    while (state.decompCache.size > DECOMP_CACHE_MAX) {
      const oldest = state.decompCache.keys().next().value;
      state.decompCache.delete(oldest);
    }
  }

  function locCacheKey(side, loc) {
    if (!loc || loc.method_idx == null) return '';
    return `${side}:${loc.dex}:${loc.class_idx}:${loc.method_idx}`;
  }

  async function runCompare() {
    if (!state.left || !state.right || state.busy) return;
    state.busy = true;
    runBtn.disabled = true;
    setStatus('Matching DEX classes (SimHash + LSH)…');
    summaryEl.hidden = true;
    filtersEl.hidden = true;
    bodyEl.hidden = true;
    exportBtn.hidden = true;
    try {
      const leftCopy = state.left.bytes.slice();
      const rightCopy = state.right.bytes.slice();
      const raw = await runInParseWorker(
        'diff_dex',
        {
          left: leftCopy.buffer,
          leftName: state.left.name,
          right: rightCopy.buffer,
          rightName: state.right.name,
        },
        { timeoutMs, transfer: [leftCopy.buffer, rightCopy.buffer] },
      );
      const report = unwrap(raw);
      state.report = report;
      state.selectedClass = -1;
      state.selectedMethod = -1;
      state.decompCache.clear();
      state.view = null;
      setStatus('Extracting DEX blobs for on-demand decompile…');
      const [leftDex, rightDex] = await Promise.all([
        cacheDexBlobs(state.left, report.left),
        cacheDexBlobs(state.right, report.right),
      ]);
      state.leftDex = leftDex;
      state.rightDex = rightDex;
      renderSummary(report);
      renderClassList();
      summaryEl.hidden = false;
      filtersEl.hidden = false;
      bodyEl.hidden = false;
      exportBtn.hidden = false;
      const s = report.summary || {};
      const ms = report.elapsed_ms != null ? `${report.elapsed_ms} ms` : '';
      setStatus(
        `Compared ${report.left?.dex_files?.length || 0} + ${report.right?.dex_files?.length || 0} DEX files` +
          (ms ? ` in ${ms}` : '') +
          `. Identical classes omitted (${s.classes_identical || 0}).`,
      );
      const first = filteredClasses()[0];
      if (first != null) selectClass(first, true);
      else {
        methodsEl.innerHTML = '<p class="muted dex-diff-placeholder">Select a class to see method changes.</p>';
        sourceEl.innerHTML = '<p class="muted dex-diff-placeholder">Select a changed method to see the source diff.</p>';
      }
    } catch (err) {
      state.report = null;
      setStatus(String(err.message || err), true);
    } finally {
      state.busy = false;
      runBtn.disabled = !(state.left && state.right);
    }
  }

  runBtn.addEventListener('click', () => runCompare());

  exportBtn?.addEventListener('click', () => {
    if (!state.report) return;
    const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    const left = (state.left?.name || 'left').replace(/\.[^.]+$/, '');
    const right = (state.right?.name || 'right').replace(/\.[^.]+$/, '');
    a.href = URL.createObjectURL(blob);
    a.download = `dex-diff-${left}-vs-${right}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });

  function chip(label, count, key, title) {
    const active = state.filter === key ? ' is-active' : '';
    return `<button type="button" class="dex-diff-chip${active}" data-filter="${escapeHtml(key)}" title="${escapeHtml(title || label)}"><span>${escapeHtml(label)}</span><strong>${count}</strong></button>`;
  }

  function renderSummary(report) {
    const s = report.summary || {};
    const left = report.left || {};
    const right = report.right || {};
    summaryEl.innerHTML =
      `<div class="dex-diff-meta">` +
      `<span><strong>A</strong> ${escapeHtml(left.name || '')} · ${escapeHtml(left.kind || '')} · ${left.class_count || 0} classes · ${(left.dex_files || []).length} DEX</span>` +
      `<span><strong>B</strong> ${escapeHtml(right.name || '')} · ${escapeHtml(right.kind || '')} · ${right.class_count || 0} classes · ${(right.dex_files || []).length} DEX</span>` +
      `</div>` +
      `<div class="dex-diff-chips" role="toolbar" aria-label="Class verdict filters">` +
      chip('All changes', (s.classes_added || 0) + (s.classes_removed || 0) + (s.classes_modified || 0) + (s.classes_renamed || 0), 'all', 'Every non-identical class') +
      chip('Modified', s.classes_modified || 0, 'modified', 'Same name, different bytecode') +
      chip('Renamed', s.classes_renamed || 0, 'renamed', 'Fuzzy-matched after ProGuard/R8 rename') +
      chip('Added', s.classes_added || 0, 'added', 'Only in B') +
      chip('Removed', s.classes_removed || 0, 'removed', 'Only in A') +
      `<span class="dex-diff-chip dex-diff-chip-static" title="Omitted from the list"><span>Identical</span><strong>${s.classes_identical || 0}</strong></span>` +
      `</div>` +
      `<div class="dex-diff-method-counts muted">Methods: +${s.methods_added || 0} / −${s.methods_removed || 0} / ~${s.methods_modified || 0} / renamed ${s.methods_renamed || 0} / identical ${s.methods_identical || 0}</div>`;
  }

  summaryEl?.addEventListener('click', (e) => {
    const chipBtn = e.target.closest('[data-filter]');
    if (!chipBtn) return;
    state.filter = chipBtn.getAttribute('data-filter') || 'all';
    if (state.report) renderSummary(state.report);
    renderClassList();
    const first = filteredClasses()[0];
    if (first != null) selectClass(first, true);
    else {
      state.selectedClass = -1;
      state.selectedMethod = -1;
      methodsEl.innerHTML = '<p class="muted dex-diff-placeholder">Select a class to see method changes.</p>';
      sourceEl.innerHTML = '<p class="muted dex-diff-placeholder">Select a changed method to see the source diff.</p>';
    }
  });

  function filteredClasses() {
    const classes = state.report?.classes || [];
    const q = (searchEl?.value || '').trim().toLowerCase();
    const showAndroid = !!androidCb?.checked;
    const out = [];
    for (let i = 0; i < classes.length; i++) {
      const c = classes[i];
      if (state.filter !== 'all' && c.verdict !== state.filter) continue;
      const left = c.left?.name || '';
      const right = c.right?.name || '';
      if (!showAndroid && isAndroidFrameworkClass(left || right)) continue;
      if (q && !classTitle(c).toLowerCase().includes(q) && !left.toLowerCase().includes(q) && !right.toLowerCase().includes(q)) {
        continue;
      }
      out.push(i);
    }
    return out;
  }

  function renderClassList() {
    const idxs = filteredClasses();
    const classes = state.report?.classes || [];
    const shown = idxs.slice(0, CLASS_RENDER_CAP);
    if (!idxs.length) {
      classesEl.innerHTML = '<p class="muted dex-diff-placeholder">No matching class differences.</p>';
      return;
    }
    let html = `<div class="dex-diff-list-meta muted">${idxs.length} class${idxs.length === 1 ? '' : 'es'}${idxs.length > CLASS_RENDER_CAP ? ` (showing ${CLASS_RENDER_CAP})` : ''}</div>`;
    html += '<ul class="dex-diff-list">';
    for (const i of shown) {
      const c = classes[i];
      const score = c.score != null ? Math.round(c.score * 100) : null;
      const mcounts = [];
      if (c.methods_modified) mcounts.push(`~${c.methods_modified}`);
      if (c.methods_renamed) mcounts.push(`r${c.methods_renamed}`);
      if (c.methods_added) mcounts.push(`+${c.methods_added}`);
      if (c.methods_removed) mcounts.push(`−${c.methods_removed}`);
      const active = i === state.selectedClass ? ' is-active' : '';
      html +=
        `<li><button type="button" class="dex-diff-item dex-diff-item-${escapeHtml(c.verdict)}${active}" data-class-idx="${i}">` +
        `<span class="dex-diff-verdict">${escapeHtml(c.verdict)}</span>` +
        `<span class="dex-diff-item-name" title="${escapeHtml(classTitle(c))}">${escapeHtml(classTitle(c))}</span>` +
        `<span class="dex-diff-item-meta">${mcounts.length ? escapeHtml(mcounts.join(' ')) : '—'}${score != null && c.verdict === 'renamed' ? ` · ${score}%` : ''}</span>` +
        `</button></li>`;
    }
    html += '</ul>';
    classesEl.innerHTML = html;
  }

  function markActive(root, attr, idx) {
    root.querySelectorAll('.dex-diff-item.is-active').forEach((el) => el.classList.remove('is-active'));
    root.querySelector(`[${attr}="${idx}"]`)?.classList.add('is-active');
  }

  searchEl?.addEventListener('input', () => {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(() => {
      renderClassList();
      const first = filteredClasses()[0];
      if (first != null) selectClass(first, true);
    }, 80);
  });
  androidCb?.addEventListener('change', () => {
    renderClassList();
    const first = filteredClasses()[0];
    if (first != null) selectClass(first, true);
  });

  function selectClass(idx, autoMethod) {
    state.selectedClass = idx;
    state.selectedMethod = -1;
    markActive(classesEl, 'data-class-idx', idx);
    renderMethodList();
    const methods = state.report?.classes?.[idx]?.methods || [];
    if (autoMethod && methods.length) {
      selectMethod(0);
    } else if (!methods.length) {
      sourceEl.innerHTML = `<p class="muted dex-diff-placeholder">${
        state.report?.classes?.[idx]?.verdict === 'renamed'
          ? 'Matched after rename; method bodies are identical.'
          : 'No method-level differences reported.'
      }</p>`;
    }
  }

  classesEl.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-class-idx]');
    if (!btn) return;
    const idx = Number(btn.getAttribute('data-class-idx'));
    if (!Number.isFinite(idx)) return;
    selectClass(idx, true);
  });

  function renderMethodList() {
    const cls = state.report?.classes?.[state.selectedClass];
    if (!cls) {
      methodsEl.innerHTML = '<p class="muted dex-diff-placeholder">Select a class to see method changes.</p>';
      return;
    }
    const methods = cls.methods || [];
    const trunc = cls.methods_truncated
      ? `<p class="muted dex-diff-placeholder">Showing the first ${methods.length} changed methods.</p>`
      : '';
    if (!methods.length) {
      methodsEl.innerHTML =
        `<div class="dex-diff-list-meta"><strong>${escapeHtml(classTitle(cls))}</strong></div>` +
        `<p class="muted dex-diff-placeholder">${cls.verdict === 'renamed' ? 'Matched after rename; method bodies are identical.' : 'No method-level differences reported.'}</p>` +
        trunc;
      return;
    }
    let html =
      `<div class="dex-diff-list-meta"><strong>${escapeHtml(classTitle(cls))}</strong>` +
      ` <span class="muted">${methods.length} changed method${methods.length === 1 ? '' : 's'} · ${cls.methods_identical || 0} identical omitted</span></div>` +
      trunc +
      '<ul class="dex-diff-list">';
    methods.forEach((m, i) => {
      const active = i === state.selectedMethod ? ' is-active' : '';
      const left = m.left?.name;
      const right = m.right?.name;
      const rename = left && right && left !== right ? ` <span class="muted">${escapeHtml(left)} → ${escapeHtml(right)}</span>` : '';
      const ins = m.left?.insn_count != null || m.right?.insn_count != null
        ? ` · ${m.left?.insn_count ?? '—'}→${m.right?.insn_count ?? '—'} insn`
        : '';
      html +=
        `<li><button type="button" class="dex-diff-item dex-diff-item-${escapeHtml(m.verdict)}${active}" data-method-idx="${i}">` +
        `<span class="dex-diff-verdict">${escapeHtml(m.verdict)}</span>` +
        `<span class="dex-diff-item-name" title="${escapeHtml(methodTitle(m))}">${escapeHtml(methodTitle(m))}${rename}</span>` +
        `<span class="dex-diff-item-meta">${ins.trim()}</span>` +
        `</button></li>`;
    });
    html += '</ul>';
    methodsEl.innerHTML = html;
  }

  function selectMethod(idx) {
    state.selectedMethod = idx;
    markActive(methodsEl, 'data-method-idx', idx);
    loadMethodDiff(idx);
  }

  methodsEl.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-method-idx]');
    if (!btn) return;
    const idx = Number(btn.getAttribute('data-method-idx'));
    if (!Number.isFinite(idx)) return;
    selectMethod(idx);
  });

  async function decompileSide(map, loc, side) {
    if (!loc || loc.method_idx == null) return { text: '', label: loc?.name || '' };
    const key = locCacheKey(side, loc);
    const cached = key && cacheGet(key);
    if (cached) return cached;
    const bytes = dexBytes(map, loc);
    if (!bytes?.length) return { text: `/* DEX ${loc.dex || ''} not extracted */`, label: loc.name };
    const raw = await getDexMethodInWorker(bytes, loc.class_idx, loc.method_idx);
    const info = unwrap(raw);
    const out = { text: methodText(info) || '/* empty decompilation */', label: info.name || loc.name };
    if (key) cacheSet(key, out);
    return out;
  }

  function prefetchMethod(idx) {
    const m = state.report?.classes?.[state.selectedClass]?.methods?.[idx];
    if (!m) return;
    if (m.left && locCacheKey('L', m.left) && !state.decompCache.has(locCacheKey('L', m.left))) {
      decompileSide(state.leftDex, m.left, 'L').catch(() => {});
    }
    if (m.right && locCacheKey('R', m.right) && !state.decompCache.has(locCacheKey('R', m.right))) {
      decompileSide(state.rightDex, m.right, 'R').catch(() => {});
    }
  }

  function renderMarksOrLine(text, parts) {
    if (parts && parts.length) return marksHtml(parts, escapeHtml);
    return escapeHtml(text || '');
  }

  function unifiedRowHtml(kind, leftNo, rightNo, sign, codeHtml, hunkIdx) {
    const lnL = leftNo ? String(leftNo) : '';
    const lnR = rightNo ? String(rightNo) : '';
    return (
      `<div class="dex-diff-urow dex-diff-src-${kind}" data-hunk="${hunkIdx}">` +
      `<span class="dex-diff-ln">${escapeHtml(lnL)}</span>` +
      `<span class="dex-diff-ln">${escapeHtml(lnR)}</span>` +
      `<span class="dex-diff-sign" aria-hidden="true">${sign}</span>` +
      `<code class="dex-diff-code">${codeHtml}</code>` +
      `</div>`
    );
  }

  function splitRowHtml(kind, leftNo, rightNo, leftHtml, rightHtml, hunkIdx) {
    const lnL = leftNo ? String(leftNo) : '';
    const lnR = rightNo ? String(rightNo) : '';
    return (
      `<div class="dex-diff-srow dex-diff-src-${kind}" data-hunk="${hunkIdx}">` +
      `<span class="dex-diff-ln">${escapeHtml(lnL)}</span>` +
      `<code class="dex-diff-code">${leftHtml}</code>` +
      `<span class="dex-diff-ln">${escapeHtml(lnR)}</span>` +
      `<code class="dex-diff-code">${rightHtml}</code>` +
      `</div>`
    );
  }

  function rowsHtml(rows, hunkIdx) {
    let html = '';
    let i = 0;
    while (i < rows.length) {
      const row = rows[i];
      const next = rows[i + 1];
      if (row.t === 'del' && next?.t === 'add') {
        const inline = inlineTokenDiff(row.a, next.b);
        const leftHtml = renderMarksOrLine(row.a, inline.a);
        const rightHtml = renderMarksOrLine(next.b, inline.b);
        if (state.unified) {
          html += unifiedRowHtml('del', row.leftNo, 0, '−', leftHtml, hunkIdx);
          html += unifiedRowHtml('add', 0, next.rightNo, '+', rightHtml, hunkIdx);
        } else {
          html += splitRowHtml('rep', row.leftNo, next.rightNo, leftHtml, rightHtml, hunkIdx);
        }
        i += 2;
        continue;
      }
      if (state.unified) {
        if (row.t === 'add') html += unifiedRowHtml('add', 0, row.rightNo, '+', escapeHtml(row.b), hunkIdx);
        else if (row.t === 'del') html += unifiedRowHtml('del', row.leftNo, 0, '−', escapeHtml(row.a), hunkIdx);
        else html += unifiedRowHtml('eq', row.leftNo, row.rightNo, ' ', escapeHtml(row.a), hunkIdx);
      } else if (row.t === 'add') {
        html += splitRowHtml('add', 0, row.rightNo, '', escapeHtml(row.b), hunkIdx);
      } else if (row.t === 'del') {
        html += splitRowHtml('del', row.leftNo, 0, escapeHtml(row.a), '', hunkIdx);
      } else {
        html += splitRowHtml('eq', row.leftNo, row.rightNo, escapeHtml(row.a), escapeHtml(row.b), hunkIdx);
      }
      i++;
    }
    return html;
  }

  function gapHtml(part, idx) {
    const n = part.end - part.start;
    const expanded = state.expandedGaps.has(idx);
    if (!state.collapse || expanded) {
      return (
        `<div class="dex-diff-gap-open" data-gap="${idx}">` +
        (state.collapse
          ? `<button type="button" class="dex-diff-gap" data-collapse-gap="${idx}">Collapse ${n} unchanged line${n === 1 ? '' : 's'}</button>`
          : '') +
        rowsHtml(state.view.rows.slice(part.start, part.end), -1) +
        `</div>`
      );
    }
    return `<button type="button" class="dex-diff-gap" data-expand-gap="${idx}">↕ ${n} unchanged line${n === 1 ? '' : 's'}</button>`;
  }

  function paintDiffBody() {
    const view = state.view;
    if (!view || !sourceEl) return;
    const parts = view.parts;
    let hunks = 0;
    let html = '';
    parts.forEach((part, idx) => {
      if (part.type === 'gap') {
        html += gapHtml(part, idx);
        return;
      }
      const changed = slice.filter((x) => x.t !== 'eq').length;
      if (!changed) {
        html += `<div class="dex-diff-hunk">${rowsHtml(slice, -1)}</div>`;
        return;
      }
      const first = slice.find((r) => r.t !== 'eq') || slice[0];
      const l = first?.leftNo || 1;
      const r = first?.rightNo || 1;
      html +=
        `<div class="dex-diff-hunk" data-hunk-wrap="${hunks}" style="content-visibility:auto;contain-intrinsic-size:auto 8rem">` +
        `<div class="dex-diff-hunk-head">@@ −${l} +${r} · ${changed} changed</div>` +
        rowsHtml(slice, hunks) +
        `</div>`;
      hunks++;
    });
    view.hunkCount = hunks;
    const body = sourceEl.querySelector('.dex-diff-src-body');
    if (body) body.innerHTML = html;
  }

  function paintSource(method) {
    const view = state.view;
    if (!view) return;
    const stats = view.stats;
    const leftTitle = method.left ? methodTitle({ left: method.left, right: null }) : '(absent in A)';
    const rightTitle = method.right ? methodTitle({ left: null, right: method.right }) : '(absent in B)';
    sourceEl.innerHTML =
      `<div class="dex-diff-src">` +
      `<div class="dex-diff-src-toolbar">` +
      `<span class="dex-diff-src-stats"><span class="dex-diff-stat-add">+${stats.add}</span><span class="dex-diff-stat-del">−${stats.del}</span></span>` +
      (stats.add + stats.del === 0
        ? `<span class="muted">Decompiled source matches</span>`
        : '') +
      `<button type="button" class="btn btn-small" data-diff-nav="-1" title="Previous change hunk">Prev</button>` +
      `<button type="button" class="btn btn-small" data-diff-nav="1" title="Next change hunk">Next</button>` +
      `<label class="list-filter-opt pane-toggle"><input type="checkbox" data-diff-unified ${state.unified ? 'checked' : ''}><span>Unified</span></label>` +
      `<label class="list-filter-opt pane-toggle"><input type="checkbox" data-diff-collapse ${state.collapse ? 'checked' : ''}><span>Collapse</span></label>` +
      `</div>` +
      `<div class="dex-diff-src-head ${state.unified ? 'is-unified' : ''}">` +
      `<span title="${escapeHtml(leftTitle)}"><strong>A</strong> ${escapeHtml(leftTitle)}</span>` +
      `<span title="${escapeHtml(rightTitle)}"><strong>B</strong> ${escapeHtml(rightTitle)}</span>` +
      `</div>` +
      `<div class="dex-diff-src-body ${state.unified ? 'is-unified' : 'is-split'}" role="table" aria-label="Decompiled source diff"></div>` +
      `</div>`;
    paintDiffBody();
    state.hunkCursor = 0;
    scrollHunk(0, false);
  }

  function scrollHunk(delta, relative) {
    const wraps = sourceEl.querySelectorAll('[data-hunk-wrap]');
    if (!wraps.length) return;
    if (relative) state.hunkCursor = (state.hunkCursor + delta + wraps.length) % wraps.length;
    else state.hunkCursor = Math.max(0, Math.min(wraps.length - 1, delta));
    wraps[state.hunkCursor]?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  sourceEl.addEventListener('click', (e) => {
    const nav = e.target.closest('[data-diff-nav]');
    if (nav) {
      scrollHunk(Number(nav.getAttribute('data-diff-nav')) || 1, true);
      return;
    }
    const expand = e.target.closest('[data-expand-gap]');
    if (expand) {
      state.expandedGaps.add(Number(expand.getAttribute('data-expand-gap')));
      paintDiffBody();
      return;
    }
    const collapse = e.target.closest('[data-collapse-gap]');
    if (collapse) {
      state.expandedGaps.delete(Number(collapse.getAttribute('data-collapse-gap')));
      paintDiffBody();
      return;
    }
  });

  sourceEl.addEventListener('change', (e) => {
    const unified = e.target.closest('[data-diff-unified]');
    if (unified) {
      state.unified = !!unified.checked;
      if (state.view) paintSource(state.view.method);
      return;
    }
    const collapse = e.target.closest('[data-diff-collapse]');
    if (collapse) {
      state.collapse = !!collapse.checked;
      state.expandedGaps.clear();
      if (state.view) paintSource(state.view.method);
    }
  });

  async function loadMethodDiff(methodIdx) {
    const cls = state.report?.classes?.[state.selectedClass];
    const m = cls?.methods?.[methodIdx];
    if (!m) return;
    const gen = ++state.loadGen;
    sourceEl.innerHTML = '<p class="muted dex-diff-placeholder">Decompiling…</p>';
    try {
      const [left, right] = await Promise.all([
        decompileSide(state.leftDex, m.left, 'L'),
        decompileSide(state.rightDex, m.right, 'R'),
      ]);
      if (gen !== state.loadGen) return;
      const leftText = m.left ? left.text : '';
      const rightText = m.right ? right.text : '';
      const rows = numberRows(diffLines(leftText, rightText));
      state.expandedGaps = new Set();
      state.view = {
        method: m,
        rows,
        parts: collateHunks(rows, HUNK_CONTEXT),
        stats: diffStats(rows),
        hunkCount: 0,
      };
      paintSource(m);
      const next = methodIdx + 1;
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(() => { if (gen === state.loadGen) prefetchMethod(next); }, { timeout: 400 });
      } else {
        setTimeout(() => { if (gen === state.loadGen) prefetchMethod(next); }, 40);
      }
    } catch (err) {
      if (gen !== state.loadGen) return;
      sourceEl.innerHTML = `<p class="dex-diff-error">${escapeHtml(String(err.message || err))}</p>`;
    }
  }

  return { compareAgainstFile, syncLoadedUi: refreshUseLoaded };
}

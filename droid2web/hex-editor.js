/**
 * Hex / raw viewer (elfbrowser-style), tuned for droid2web themes.
 * Address | grouped hex | ASCII | entropy, with a selection inspector.
 */

const HEX_TABLE = new Array(256);
for (let i = 0; i < 256; i++) HEX_TABLE[i] = i.toString(16).padStart(2, '0');

const BYTES_PER_LINE = 16;
const MIN_LINES = 16;
const PREFS_KEY = 'droid2web-hex-prefs';

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function computeEntropy(bytes, offset, length) {
  const off = offset || 0;
  const len = length || (bytes.length - off);
  if (len <= 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < len; i++) freq[bytes[off + i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

function entropyToColor(e) {
  const t = Math.min(Math.max(e / 8, 0), 1);
  const stops = [
    [0.00, 10, 10, 40],
    [0.10, 20, 40, 120],
    [0.25, 30, 140, 200],
    [0.40, 40, 200, 100],
    [0.55, 200, 220, 40],
    [0.70, 240, 160, 20],
    [0.85, 230, 50, 30],
    [1.00, 200, 40, 180],
  ];
  let lo = stops[0];
  let hi = stops[stops.length - 1];
  for (let i = 0; i < stops.length - 1; i++) {
    if (t >= stops[i][0] && t <= stops[i + 1][0]) {
      lo = stops[i];
      hi = stops[i + 1];
      break;
    }
  }
  const f = lo[0] === hi[0] ? 0 : (t - lo[0]) / (hi[0] - lo[0]);
  const r = Math.round(lo[1] + f * (hi[1] - lo[1]));
  const g = Math.round(lo[2] + f * (hi[2] - lo[2]));
  const b = Math.round(lo[3] + f * (hi[3] - lo[3]));
  return `rgb(${r},${g},${b})`;
}

function parseOffset(text) {
  if (text == null) return NaN;
  const s = String(text).trim();
  if (!s) return NaN;
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  if (/^[0-9a-f]+h$/i.test(s)) return parseInt(s.slice(0, -1), 16);
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  if (/^[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  return NaN;
}

function parseHexQuery(q) {
  const cleaned = String(q || '').trim();
  if (!cleaned) return null;
  const tokens = cleaned.split(/[\s,]+/).filter(Boolean);
  const out = [];
  for (const t of tokens) {
    let hex = t;
    if (hex.toLowerCase().startsWith('0x')) hex = hex.slice(2);
    if (hex.length === 2 && /^[0-9a-fA-F]{2}$/.test(hex)) {
      out.push(parseInt(hex, 16));
    } else if (/^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0) {
      for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
    } else {
      return null;
    }
  }
  return out.length ? out : null;
}

function detectSearchMode(q) {
  const s = String(q || '').trim();
  if (!s) return 'string';
  if (s.startsWith('/') && s.length > 2) return 'regex';
  if (/\?\?/.test(s) || /0[xX][0-9a-fA-F]+/.test(s)) return 'hex';
  const tokens = s.split(/[\s,]+/).filter(Boolean);
  if (tokens.length >= 2 && tokens.every((t) => /^(0x)?[0-9a-fA-F]{1,2}$/i.test(t))) return 'hex';
  if (/^[0-9a-fA-F]+$/.test(s) && s.length >= 4 && s.length % 2 === 0) return 'hex';
  return 'string';
}

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return {};
    const p = JSON.parse(raw);
    return p && typeof p === 'object' ? p : {};
  } catch (_) {
    return {};
  }
}

function savePrefs(partial) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({ ...loadPrefs(), ...partial }));
  } catch (_) {}
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function readU16LE(bytes, off) {
  if (off + 1 >= bytes.length) return null;
  return bytes[off] | (bytes[off + 1] << 8);
}
function readU16BE(bytes, off) {
  if (off + 1 >= bytes.length) return null;
  return (bytes[off] << 8) | bytes[off + 1];
}
function readU32LE(bytes, off) {
  if (off + 3 >= bytes.length) return null;
  return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0;
}
function readU32BE(bytes, off) {
  if (off + 3 >= bytes.length) return null;
  return ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
}

/**
 * @param {HTMLElement} root
 * @param {{ onStatus?: (msg: string) => void }} [opts]
 */
export function createHexEditor(root, prefsOrOpts = {}) {
  if (!root) throw new Error('hex editor root required');
  const opts = prefsOrOpts || {};
  const prefs = { ...loadPrefs(), ...(opts.prefs || {}) };

  const EMPTY_HTML =
    '<div class="hex-empty">'
    + '<div class="hex-empty-title">Raw bytes</div>'
    + '<div class="hex-empty-body">Open an APK, DEX, AXML, or ARSC — or extract a file from an APK — to inspect it here.</div>'
    + '<div class="hex-empty-hint muted">Jump here from Strings → Raw, or click file offsets in Info / Security.</div>'
    + '</div>';

  const fontSizeRem = (() => {
    const n = Number(prefs.fontSize);
    if (!Number.isFinite(n)) return 0.92;
    return Math.min(1.28, Math.max(0.72, n));
  })();

  root.innerHTML = `
    <div class="hex-editor" data-hex-palette="${escHtml(prefs.palette || 'default')}" style="--hex-font-size:${fontSizeRem}rem">
      <div class="hex-toolbar">
        <div class="hex-toolbar-row hex-toolbar-primary">
          <div class="hex-toolbar-brand">
            <span class="hex-toolbar-title">Raw</span>
            <span class="hex-info muted"></span>
          </div>
          <div class="hex-toolbar-group">
            <label class="hex-goto-wrap">
              <span class="hex-toolbar-label">Offset</span>
              <input type="text" class="hex-goto-input" placeholder="0x0" spellcheck="false" aria-label="Go to offset">
            </label>
            <button type="button" class="btn btn-small hex-goto-btn">Go</button>
            <button type="button" class="btn btn-small hex-page-prev" title="Previous page (PageUp)">▲</button>
            <button type="button" class="btn btn-small hex-page-next" title="Next page (PageDown)">▼</button>
          </div>
          <div class="hex-toolbar-group hex-toolbar-grow">
            <input type="search" class="hex-search-input" placeholder="Search string, hex, or /regex/" aria-label="Search bytes" autocomplete="off">
            <select class="hex-search-mode" aria-label="Search mode" title="Search mode">
              <option value="auto">Auto</option>
              <option value="string">String</option>
              <option value="hex">Hex</option>
              <option value="regex">Regex</option>
            </select>
            <button type="button" class="btn btn-small hex-search-btn">Find</button>
            <button type="button" class="btn btn-small hex-search-prev" title="Previous match">↑</button>
            <button type="button" class="btn btn-small hex-search-next" title="Next match">↓</button>
            <span class="hex-search-status muted"></span>
          </div>
        </div>
        <div class="hex-toolbar-row hex-toolbar-secondary">
          <div class="hex-toolbar-group">
            <span class="hex-toolbar-label">View</span>
            <select class="hex-palette-select" aria-label="Color palette" title="Byte color palette">
              <option value="default">Palette</option>
              <option value="grayscale">Grayscale</option>
              <option value="pastel">Pastel</option>
              <option value="vivid">Vivid</option>
              <option value="off">No color</option>
            </select>
            <label class="hex-toggle" title="Show per-line entropy bars">
              <input type="checkbox" class="hex-entropy-toggle"${prefs.entropy === false ? '' : ' checked'}>
              <span>Entropy</span>
            </label>
            <div class="hex-font-wrap" title="Hex dump font size">
              <button type="button" class="btn btn-small hex-font-dec" aria-label="Decrease font size">A−</button>
              <button type="button" class="btn btn-small hex-font-inc" aria-label="Increase font size">A+</button>
            </div>
          </div>
          <div class="hex-toolbar-group hex-toolbar-actions">
            <div class="hex-copy-wrap">
              <button type="button" class="btn btn-small hex-copy-btn" title="Copy selection">Copy</button>
              <select class="hex-copy-format" aria-label="Copy format" title="Copy format">
                <option value="hex">Hex</option>
                <option value="hexc">C array</option>
                <option value="ascii">ASCII</option>
                <option value="offset">Offsets</option>
              </select>
            </div>
          </div>
        </div>
      </div>
      <div class="hex-col-header" aria-hidden="true">
        <span class="hex-hdr-addr">Offset</span>
        <span class="hex-hdr-hex"></span>
        <span class="hex-hdr-ascii">ASCII</span>
        <span class="hex-hdr-ent">H</span>
      </div>
      <div class="hex-dump-wrap">
        <pre class="hex-dump" tabindex="0">${EMPTY_HTML}</pre>
      </div>
      <div class="hex-inspector" hidden>
        <div class="hex-inspector-label">Selection</div>
        <div class="hex-inspector-main"></div>
        <div class="hex-inspector-ints"></div>
      </div>
      <div class="hex-status-bar">
        <span class="hex-status-left muted"></span>
        <span class="hex-status-mid muted"></span>
        <span class="hex-status-right muted"></span>
      </div>
    </div>`;

  const shell = root.querySelector('.hex-editor');
  const dumpEl = root.querySelector('.hex-dump');
  const dumpWrap = root.querySelector('.hex-dump-wrap');
  const colHeader = root.querySelector('.hex-col-header');
  const inspector = root.querySelector('.hex-inspector');
  const inspectorMain = root.querySelector('.hex-inspector-main');
  const inspectorInts = root.querySelector('.hex-inspector-ints');
  const gotoInput = root.querySelector('.hex-goto-input');
  const gotoBtn = root.querySelector('.hex-goto-btn');
  const pagePrev = root.querySelector('.hex-page-prev');
  const pageNext = root.querySelector('.hex-page-next');
  const searchInput = root.querySelector('.hex-search-input');
  const searchMode = root.querySelector('.hex-search-mode');
  const searchBtn = root.querySelector('.hex-search-btn');
  const searchPrev = root.querySelector('.hex-search-prev');
  const searchNext = root.querySelector('.hex-search-next');
  const searchStatus = root.querySelector('.hex-search-status');
  const paletteSelect = root.querySelector('.hex-palette-select');
  const entropyToggle = root.querySelector('.hex-entropy-toggle');
  const copyBtn = root.querySelector('.hex-copy-btn');
  const copyFormat = root.querySelector('.hex-copy-format');
  const fontDecBtn = root.querySelector('.hex-font-dec');
  const fontIncBtn = root.querySelector('.hex-font-inc');
  const infoEl = root.querySelector('.hex-info');
  const statusLeft = root.querySelector('.hex-status-left');
  const statusMid = root.querySelector('.hex-status-mid');
  const statusRight = root.querySelector('.hex-status-right');
  let currentFontRem = fontSizeRem;

  function applyFontSize(rem, { persist = true } = {}) {
    currentFontRem = Math.min(1.28, Math.max(0.72, rem));
    shell.style.setProperty('--hex-font-size', `${currentFontRem}rem`);
    if (persist) savePrefs({ fontSize: currentFontRem });
    measureLines();
    render();
  }

  if (paletteSelect) paletteSelect.value = prefs.palette || 'default';
  if (copyFormat) copyFormat.value = prefs.copyFormat || 'hex';

  /** @type {Uint8Array | null} */
  let bytes = null;
  let label = '';
  let viewOffset = 0;
  let selectionStart = -1;
  let selectionEnd = -1;
  let hoverOff = -1;
  /** @type {{ offset: number, length: number }[]} */
  let searchMatches = [];
  let searchIndex = -1;
  let showEntropy = prefs.entropy !== false;
  let linesPerPage = LINES_PER_PAGE_DEFAULT();

  function LINES_PER_PAGE_DEFAULT() {
    return 32;
  }

  function pageSize() {
    return BYTES_PER_LINE * linesPerPage;
  }

  function measureLines() {
    if (!dumpWrap) return;
    const style = getComputedStyle(dumpEl);
    const fs = parseFloat(style.fontSize) || 12.5;
    const lh = parseFloat(style.lineHeight) || fs * 1.55;
    const pad = 16;
    const h = dumpWrap.clientHeight || 400;
    const n = Math.max(MIN_LINES, Math.floor((h - pad) / lh));
    if (n !== linesPerPage) {
      linesPerPage = n;
      return true;
    }
    return false;
  }

  function clampView() {
    if (!bytes || !bytes.length) {
      viewOffset = 0;
      return;
    }
    const max = Math.max(0, bytes.length - 1);
    viewOffset = Math.max(0, Math.min(viewOffset, max));
    viewOffset -= viewOffset % BYTES_PER_LINE;
  }

  function setStatus(msg) {
    if (typeof opts.onStatus === 'function') opts.onStatus(msg);
  }

  function updateChrome() {
    const len = bytes?.length || 0;
    const end = Math.min(len, viewOffset + pageSize());
    if (infoEl) {
      infoEl.textContent = len
        ? `${label ? label + ' · ' : ''}${formatSize(len)}`
        : (label || 'No file');
    }
    if (statusLeft) {
      if (selectionStart >= 0 && selectionEnd >= 0) {
        const lo = Math.min(selectionStart, selectionEnd);
        const hi = Math.max(selectionStart, selectionEnd);
        const n = hi - lo + 1;
        statusLeft.textContent = `Sel 0x${lo.toString(16)}–0x${hi.toString(16)} · ${n} byte${n === 1 ? '' : 's'}`;
      } else {
        statusLeft.textContent = len ? `${len.toLocaleString()} bytes` : 'No bytes loaded';
      }
    }
    if (statusMid) {
      statusMid.textContent = len
        ? `View 0x${viewOffset.toString(16)}–0x${Math.max(0, end - 1).toString(16)}`
        : '';
    }
    if (statusRight) {
      statusRight.textContent = len
        ? `Page ${Math.floor(viewOffset / pageSize()) + 1}/${Math.max(1, Math.ceil(len / pageSize()))}`
        : '';
    }
    if (gotoInput && document.activeElement !== gotoInput) {
      gotoInput.value = '0x' + viewOffset.toString(16);
    }
    if (colHeader) colHeader.hidden = !len;
    const entHdr = colHeader?.querySelector('.hex-hdr-ent');
    if (entHdr) entHdr.style.visibility = showEntropy ? 'visible' : 'hidden';
  }

  function updateSearchStatus() {
    if (!searchStatus) return;
    if (!searchMatches.length) {
      searchStatus.textContent = searchInput?.value?.trim() ? 'No matches' : '';
      return;
    }
    searchStatus.textContent = `${searchIndex + 1}/${searchMatches.length}`;
  }

  function updateInspector() {
    if (!inspector || !inspectorMain || !inspectorInts) return;
    if (!bytes?.length || selectionStart < 0) {
      inspector.hidden = true;
      return;
    }
    const lo = Math.min(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart);
    const hi = Math.max(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart);
    const n = hi - lo + 1;
    const b0 = bytes[lo];
    const ch = b0 >= 32 && b0 < 127 ? String.fromCharCode(b0) : '·';
    const bits = [
      `<span class="hex-insp-chip"><em>off</em> 0x${lo.toString(16)}</span>`,
      `<span class="hex-insp-chip"><em>len</em> ${n}</span>`,
      `<span class="hex-insp-chip"><em>hex</em> ${HEX_TABLE[b0]}</span>`,
      `<span class="hex-insp-chip"><em>dec</em> ${b0}</span>`,
      `<span class="hex-insp-chip"><em>bin</em> ${b0.toString(2).padStart(8, '0')}</span>`,
      `<span class="hex-insp-chip"><em>chr</em> ${escHtml(ch)}</span>`,
    ];
    inspectorMain.innerHTML = bits.join('');

    const u16le = readU16LE(bytes, lo);
    const u16be = readU16BE(bytes, lo);
    const u32le = readU32LE(bytes, lo);
    const u32be = readU32BE(bytes, lo);
    const ints = [];
    if (u16le != null) ints.push(`<span class="hex-insp-chip"><em>u16le</em> ${u16le} <span class="muted">0x${u16le.toString(16)}</span></span>`);
    if (u16be != null) ints.push(`<span class="hex-insp-chip"><em>u16be</em> ${u16be} <span class="muted">0x${u16be.toString(16)}</span></span>`);
    if (u32le != null) ints.push(`<span class="hex-insp-chip"><em>u32le</em> ${u32le} <span class="muted">0x${u32le.toString(16)}</span></span>`);
    if (u32be != null) ints.push(`<span class="hex-insp-chip"><em>u32be</em> ${u32be} <span class="muted">0x${u32be.toString(16)}</span></span>`);
    if (n > 1 && n <= 64) {
      const slice = Array.from(bytes.subarray(lo, hi + 1)).map((b) => HEX_TABLE[b]).join(' ');
      ints.push(`<span class="hex-insp-chip hex-insp-wide"><em>bytes</em> ${slice}</span>`);
    }
    inspectorInts.innerHTML = ints.join('');
    inspector.hidden = false;
  }

  function renderHeaderHex() {
    if (!colHeader) return;
    const hexHdr = colHeader.querySelector('.hex-hdr-hex');
    if (!hexHdr) return;
    let s = '';
    for (let i = 0; i < BYTES_PER_LINE; i++) {
      if (i === 8) s += '<span class="hex-mid-gap" aria-hidden="true"></span>';
      s += `<span class="hex-hdr-byte">${HEX_TABLE[i].toUpperCase()}</span>`;
    }
    hexHdr.innerHTML = s;
  }

  function render() {
    clampView();
    if (!bytes || !bytes.length) {
      dumpEl.innerHTML = EMPTY_HTML;
      updateChrome();
      updateSearchStatus();
      updateInspector();
      return;
    }

    const cur = searchIndex >= 0 ? searchMatches[searchIndex] : null;
    const hitSet = new Set();
    const curSet = new Set();
    const viewEnd = Math.min(bytes.length, viewOffset + pageSize());
    for (const m of searchMatches) {
      const mEnd = m.offset + m.length;
      if (mEnd <= viewOffset || m.offset >= viewEnd) continue;
      const lo = Math.max(m.offset, viewOffset);
      const hi = Math.min(mEnd, viewEnd);
      const isCur = cur && m.offset === cur.offset && m.length === cur.length;
      for (let a = lo; a < hi; a++) {
        hitSet.add(a);
        if (isCur) curSet.add(a);
      }
    }

    const selLo = selectionStart >= 0 ? Math.min(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart) : -1;
    const selHi = selectionStart >= 0 ? Math.max(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart) : -1;
    const paletteOff = shell.dataset.hexPalette === 'off';
    const parts = [];
    const lines = Math.ceil((viewEnd - viewOffset) / BYTES_PER_LINE) || 1;

    for (let line = 0; line < lines; line++) {
      const lineAddr = viewOffset + line * BYTES_PER_LINE;
      if (lineAddr >= bytes.length) break;
      const addrStr = '0x' + lineAddr.toString(16).padStart(8, '0');
      let hexHtml = '';
      let asciiHtml = '';
      for (let bi = 0; bi < BYTES_PER_LINE; bi++) {
        if (bi === 8) {
          hexHtml += '<span class="hex-mid-gap" aria-hidden="true"></span>';
          asciiHtml += '<span class="hex-mid-gap" aria-hidden="true"></span>';
        }
        const off = lineAddr + bi;
        if (off >= bytes.length) {
          hexHtml += '<span class="hex-byte-hex hex-byte hex-byte-empty">  </span>';
          asciiHtml += '<span class="hex-byte-ascii hex-byte hex-byte-empty"> </span>';
          continue;
        }
        const val = bytes[off];
        const hexStr = HEX_TABLE[val];
        const nullCls = val === 0 ? ' hex-byte-null' : '';
        const printCls = val >= 32 && val < 127 ? ' hex-byte-print' : '';
        const valCls = paletteOff ? '' : ` hex-byte-v${val % 16}`;
        const searchCls = hitSet.has(off)
          ? (curSet.has(off) ? ' hex-search-current' : ' hex-search-hit')
          : '';
        const selCls = selLo >= 0 && off >= selLo && off <= selHi ? ' hex-byte-selected' : '';
        const hoverCls = hoverOff === off ? ' hex-byte-hover' : '';
        const cls = `hex-byte clickable${valCls}${nullCls}${printCls}${searchCls}${selCls}${hoverCls}`;
        const tip = `0x${off.toString(16)} (${off}) · ${hexStr} · ${val}`;
        hexHtml += `<span class="hex-byte-hex ${cls}" data-off="${off}" title="${tip}">${hexStr}</span>`;
        const ch = val >= 32 && val < 127 ? String.fromCharCode(val) : '.';
        const chEsc = ch === '<' ? '&lt;' : ch === '>' ? '&gt;' : ch === '&' ? '&amp;' : ch;
        asciiHtml += `<span class="hex-byte-ascii ${cls}" data-off="${off}" title="${tip}">${chEsc}</span>`;
      }

      let entropyBar = '';
      if (showEntropy) {
        const remain = Math.min(BYTES_PER_LINE, bytes.length - lineAddr);
        if (remain > 0) {
          const ent = computeEntropy(bytes, lineAddr, remain);
          entropyBar = `<span class="hex-entropy-bar" style="background:${entropyToColor(ent)}" title="entropy ${ent.toFixed(2)} / 8 bits"></span>`;
        }
      }
      parts.push(
        `<span class="hex-line">` +
        `<span class="hex-addr-col" data-off="${lineAddr}" title="Go to 0x${lineAddr.toString(16)}">${addrStr}</span>` +
        `<span class="hex-bytes-col">${hexHtml}</span>` +
        `<span class="hex-ascii-col">|${asciiHtml}|</span>` +
        `${entropyBar}` +
        `</span>`
      );
    }

    dumpEl.innerHTML = parts.join('');
    updateChrome();
    updateSearchStatus();
    updateInspector();

    if (curSet.size > 0) {
      requestAnimationFrame(() => {
        const el = dumpEl.querySelector('.hex-search-current');
        if (el) el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      });
    }
  }

  function goTo(offset, { selectLen = 0 } = {}) {
    if (!bytes) return;
    const off = Math.max(0, Math.min(bytes.length - 1, offset | 0));
    viewOffset = off - (off % BYTES_PER_LINE);
    if (selectLen > 0) {
      selectionStart = off;
      selectionEnd = Math.min(bytes.length - 1, off + selectLen - 1);
    }
    render();
  }

  function runSearch(query, mode) {
    searchMatches = [];
    searchIndex = -1;
    if (!bytes || !bytes.length) {
      updateSearchStatus();
      render();
      return 0;
    }
    const q = String(query || '').trim();
    if (!q) {
      updateSearchStatus();
      render();
      return 0;
    }
    let effective = mode || 'auto';
    if (effective === 'auto') effective = detectSearchMode(q);

    try {
      if (effective === 'hex') {
        const needle = parseHexQuery(q);
        if (!needle || !needle.length) throw new Error('Invalid hex');
        for (let i = 0; i <= bytes.length - needle.length; i++) {
          let ok = true;
          for (let j = 0; j < needle.length; j++) {
            if (bytes[i + j] !== needle[j]) { ok = false; break; }
          }
          if (ok) {
            searchMatches.push({ offset: i, length: needle.length });
            if (searchMatches.length >= 10000) break;
          }
        }
      } else if (effective === 'regex') {
        let body = q;
        let flags = 'g';
        if (body.startsWith('/') && body.lastIndexOf('/') > 0) {
          const last = body.lastIndexOf('/');
          flags = body.slice(last + 1) || 'g';
          body = body.slice(1, last);
          if (!flags.includes('g')) flags += 'g';
        }
        const re = new RegExp(body, flags);
        let latin = '';
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
          const slice = bytes.subarray(i, Math.min(bytes.length, i + chunk));
          latin += String.fromCharCode.apply(null, slice);
        }
        let m;
        re.lastIndex = 0;
        while ((m = re.exec(latin)) !== null) {
          searchMatches.push({ offset: m.index, length: Math.max(1, m[0].length) });
          if (m[0].length === 0) re.lastIndex++;
          if (searchMatches.length >= 10000) break;
        }
      } else {
        const enc = new TextEncoder().encode(q);
        if (!enc.length) return 0;
        for (let i = 0; i <= bytes.length - enc.length; i++) {
          let ok = true;
          for (let j = 0; j < enc.length; j++) {
            if (bytes[i + j] !== enc[j]) { ok = false; break; }
          }
          if (ok) {
            searchMatches.push({ offset: i, length: enc.length });
            if (searchMatches.length >= 10000) break;
          }
        }
      }
    } catch (e) {
      searchStatus.textContent = e?.message || 'Search error';
      setStatus(searchStatus.textContent);
      render();
      return 0;
    }

    if (searchMatches.length) {
      searchIndex = 0;
      jumpToMatch(0);
    } else {
      render();
    }
    updateSearchStatus();
    setStatus(searchMatches.length ? `${searchMatches.length} match(es)` : 'No matches');
    return searchMatches.length;
  }

  function jumpToMatch(idx) {
    if (!searchMatches.length) return;
    searchIndex = ((idx % searchMatches.length) + searchMatches.length) % searchMatches.length;
    const m = searchMatches[searchIndex];
    goTo(m.offset, { selectLen: m.length });
  }

  function findString(str) {
    if (!bytes || !str) return -1;
    const enc = new TextEncoder().encode(str);
    if (!enc.length) return -1;
    outer: for (let i = 0; i <= bytes.length - enc.length; i++) {
      for (let j = 0; j < enc.length; j++) {
        if (bytes[i + j] !== enc[j]) continue outer;
      }
      searchMatches = [{ offset: i, length: enc.length }];
      searchIndex = 0;
      if (searchInput) searchInput.value = str;
      goTo(i, { selectLen: enc.length });
      updateSearchStatus();
      return i;
    }
    searchMatches = [];
    searchIndex = -1;
    updateSearchStatus();
    return -1;
  }

  function selectionRange() {
    if (!bytes) return null;
    let start = selectionStart >= 0 ? Math.min(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart) : viewOffset;
    let end = selectionStart >= 0 ? Math.max(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart) : Math.min(bytes.length, viewOffset + pageSize()) - 1;
    start = Math.max(0, start);
    end = Math.min(bytes.length - 1, end);
    return { start, end };
  }

  function copySelection() {
    if (!bytes) return;
    const range = selectionRange();
    if (!range) return;
    const { start, end } = range;
    const fmt = copyFormat?.value || 'hex';
    let text = '';
    if (fmt === 'ascii') {
      const parts = [];
      for (let i = start; i <= end; i++) {
        const b = bytes[i];
        parts.push(b >= 32 && b < 127 ? String.fromCharCode(b) : '.');
      }
      text = parts.join('');
    } else if (fmt === 'hexc') {
      const parts = [];
      for (let i = start; i <= end; i++) parts.push('0x' + HEX_TABLE[bytes[i]]);
      text = '{ ' + parts.join(', ') + ' }';
    } else if (fmt === 'offset') {
      text = `0x${start.toString(16)}-0x${end.toString(16)} (${end - start + 1} bytes)`;
    } else {
      const parts = [];
      for (let i = start; i <= end; i++) parts.push(HEX_TABLE[bytes[i]]);
      text = parts.join(' ');
    }
    navigator.clipboard?.writeText(text).then(() => {
      setStatus(`Copied ${end - start + 1} byte(s) as ${fmt}`);
      if (copyBtn) {
        const prev = copyBtn.textContent;
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = prev; }, 900);
      }
    }).catch(() => setStatus('Copy failed'));
  }

  // Events
  gotoBtn?.addEventListener('click', () => {
    const off = parseOffset(gotoInput?.value);
    if (Number.isNaN(off)) return;
    goTo(off, { selectLen: 1 });
  });
  gotoInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      gotoBtn?.click();
    }
  });
  pagePrev?.addEventListener('click', () => {
    viewOffset = Math.max(0, viewOffset - pageSize());
    render();
  });
  pageNext?.addEventListener('click', () => {
    if (!bytes) return;
    viewOffset = Math.min(Math.max(0, bytes.length - 1), viewOffset + pageSize());
    render();
  });
  searchBtn?.addEventListener('click', () => runSearch(searchInput?.value, searchMode?.value));
  searchInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) jumpToMatch(searchIndex - 1);
      else if (searchMatches.length && searchInput.value.trim()) jumpToMatch(searchIndex + 1);
      else runSearch(searchInput.value, searchMode?.value);
    }
  });
  searchPrev?.addEventListener('click', () => jumpToMatch(searchIndex - 1));
  searchNext?.addEventListener('click', () => jumpToMatch(searchIndex + 1));
  paletteSelect?.addEventListener('change', () => {
    shell.dataset.hexPalette = paletteSelect.value || 'default';
    savePrefs({ palette: shell.dataset.hexPalette });
    render();
  });
  entropyToggle?.addEventListener('change', () => {
    showEntropy = !!entropyToggle.checked;
    savePrefs({ entropy: showEntropy });
    render();
  });
  fontDecBtn?.addEventListener('click', () => applyFontSize(currentFontRem - 0.06));
  fontIncBtn?.addEventListener('click', () => applyFontSize(currentFontRem + 0.06));
  copyFormat?.addEventListener('change', () => {
    savePrefs({ copyFormat: copyFormat.value || 'hex' });
  });
  copyBtn?.addEventListener('click', () => copySelection());

  dumpEl.addEventListener('click', (e) => {
    const addr = e.target.closest('.hex-addr-col[data-off]');
    if (addr) {
      const off = parseInt(addr.dataset.off, 10);
      if (!Number.isNaN(off)) goTo(off, { selectLen: 1 });
      return;
    }
    const span = e.target.closest('.hex-byte[data-off]');
    if (!span) return;
    const off = parseInt(span.dataset.off, 10);
    if (Number.isNaN(off)) return;
    if (e.shiftKey && selectionStart >= 0) {
      selectionEnd = off;
    } else {
      selectionStart = off;
      selectionEnd = off;
    }
    render();
  });

  dumpEl.addEventListener('mousemove', (e) => {
    const span = e.target.closest('.hex-byte[data-off]');
    const off = span ? parseInt(span.dataset.off, 10) : -1;
    if (off === hoverOff) return;
    hoverOff = Number.isNaN(off) ? -1 : off;
    dumpEl.querySelectorAll('.hex-byte-hover').forEach((el) => el.classList.remove('hex-byte-hover'));
    if (hoverOff >= 0) {
      dumpEl.querySelectorAll(`.hex-byte[data-off="${hoverOff}"]`).forEach((el) => el.classList.add('hex-byte-hover'));
    }
  });
  dumpEl.addEventListener('mouseleave', () => {
    hoverOff = -1;
    dumpEl.querySelectorAll('.hex-byte-hover').forEach((el) => el.classList.remove('hex-byte-hover'));
  });

  dumpWrap?.addEventListener('wheel', (e) => {
    if (!bytes?.length) return;
    if (Math.abs(e.deltaY) < 2) return;
    e.preventDefault();
    const lines = e.deltaY > 0 ? 4 : -4;
    viewOffset = Math.max(0, Math.min(bytes.length - 1, viewOffset + lines * BYTES_PER_LINE));
    viewOffset -= viewOffset % BYTES_PER_LINE;
    render();
  }, { passive: false });

  dumpEl.addEventListener('keydown', (e) => {
    if (!bytes?.length) return;
    if (e.key === 'ArrowDown' || e.key === 'PageDown') {
      e.preventDefault();
      viewOffset = Math.min(bytes.length - 1, viewOffset + (e.key === 'PageDown' ? pageSize() : BYTES_PER_LINE));
      render();
    } else if (e.key === 'ArrowUp' || e.key === 'PageUp') {
      e.preventDefault();
      viewOffset = Math.max(0, viewOffset - (e.key === 'PageUp' ? pageSize() : BYTES_PER_LINE));
      render();
    } else if (e.key === 'Home') {
      e.preventDefault();
      goTo(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      goTo(Math.max(0, bytes.length - 1));
    } else if ((e.key === 'c' || e.key === 'C') && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      copySelection();
    }
  });

  if (typeof ResizeObserver !== 'undefined' && dumpWrap) {
    const ro = new ResizeObserver(() => {
      if (measureLines()) render();
    });
    ro.observe(dumpWrap);
  }

  renderHeaderHex();
  measureLines();

  return {
    setBytes(u8, meta = {}) {
      bytes = u8 instanceof Uint8Array ? u8 : (u8 ? new Uint8Array(u8) : null);
      label = meta.label || meta.name || '';
      viewOffset = 0;
      selectionStart = -1;
      selectionEnd = -1;
      hoverOff = -1;
      searchMatches = [];
      searchIndex = -1;
      if (searchInput) searchInput.value = '';
      measureLines();
      render();
    },
    clear() {
      this.setBytes(null, {});
      dumpEl.innerHTML = EMPTY_HTML;
    },
    goTo,
    search: runSearch,
    findString,
    highlightRange(start, len) {
      if (!bytes || start < 0) return;
      selectionStart = start;
      selectionEnd = Math.min(bytes.length - 1, start + Math.max(1, len) - 1);
      goTo(start);
    },
    getBytes: () => bytes,
    getSelection: () => (selectionStart < 0 ? null : {
      start: Math.min(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart),
      end: Math.max(selectionStart, selectionEnd >= 0 ? selectionEnd : selectionStart),
    }),
    refresh() {
      measureLines();
      render();
    },
  };
}

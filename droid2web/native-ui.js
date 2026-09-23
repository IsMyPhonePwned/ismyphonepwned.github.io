/**
 * Native tab — ARM64 ELF (.so) assembly / CFG / decompilation.
 */

const ARM_DECOMPILE_OPTIONS_KEY = 'droid2web-arm-decompile-options';

/** @type {{ engine: 'legacy' | 'micro' }} */
let armDecompileOptions = { engine: 'micro' };

function loadArmDecompileOptionsFromStorage() {
  try {
    const raw = localStorage.getItem(ARM_DECOMPILE_OPTIONS_KEY);
    if (!raw) return;
    const o = JSON.parse(raw);
    if (o && (o.engine === 'legacy' || o.engine === 'micro')) {
      armDecompileOptions.engine = o.engine;
    }
  } catch (_) { /* ignore */ }
}

function saveArmDecompileOptionsToStorage() {
  try {
    localStorage.setItem(ARM_DECOMPILE_OPTIONS_KEY, JSON.stringify(armDecompileOptions));
  } catch (_) { /* ignore */ }
}

function syncArmDecompileOptionsUi() {
  const engine = armDecompileOptions.engine === 'legacy' ? 'legacy' : 'micro';
  const nativeEl = $('native-decompile-engine');
  const settingsEl = $('settings-arm-engine');
  if (nativeEl) nativeEl.value = engine;
  if (settingsEl) settingsEl.value = engine;
}

function setArmDecompileEngine(engine, { reload = true } = {}) {
  const next = engine === 'legacy' ? 'legacy' : 'micro';
  const changed = armDecompileOptions.engine !== next;
  armDecompileOptions.engine = next;
  saveArmDecompileOptionsToStorage();
  syncArmDecompileOptionsUi();
  if (changed && reload) reloadCurrentNativeDecompilation();
}

function getArmDecompileEngine() {
  return armDecompileOptions.engine === 'legacy' ? 'legacy' : 'micro';
}

function nativeDecompileOptionsPayload() {
  return {
    mode: $('native-decompile-mode')?.value || 'restructure',
    engine: getArmDecompileEngine(),
  };
}

function reloadCurrentNativeDecompilation() {
  if (selectedFuncIdx >= 0) {
    loadFunction(selectedFuncIdx);
    return;
  }
  if (currentFn?.vaddr != null) {
    loadFunctionAtVaddr(Number(currentFn.vaddr));
  }
}

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatOff(off) {
  return '0x' + (Number(off) >>> 0).toString(16).padStart(4, '0');
}

function formatVaddr(addr) {
  return '0x' + Number(addr || 0).toString(16);
}

/** Lowest FUNC vaddr — used for image-relative (+0x…) labels. */
function nativeFuncBaseVaddr() {
  const funcs = Array.isArray(browseInfo?.functions) ? browseInfo.functions : [];
  let min = null;
  for (const f of funcs) {
    const v = Number(f?.vaddr);
    if (!Number.isFinite(v)) continue;
    if (min == null || v < min) min = v;
  }
  return min == null ? 0 : min;
}

function formatFuncRel(vaddr) {
  const base = nativeFuncBaseVaddr();
  const rel = Number(vaddr || 0) - base;
  if (!Number.isFinite(rel) || rel < 0) return formatVaddr(vaddr);
  return '+' + formatOff(rel);
}

/** Resolve symbol / sub_XXXX / 0xADDR to a function index in browseInfo. */
function resolveNativeCalleeIndex(token) {
  const funcs = Array.isArray(browseInfo?.functions) ? browseInfo.functions : [];
  if (!funcs.length || token == null) return -1;
  const raw = String(token).trim();
  if (!raw) return -1;

  let idx = funcs.findIndex((f) => f.name === raw);
  if (idx >= 0) return idx;
  idx = funcs.findIndex(
    (f) => f.name === raw || String(f.name || '').startsWith(raw + '__')
  );
  if (idx >= 0) return idx;

  const addr = parseNativeAddrToken(raw);
  if (addr != null) {
    idx = funcs.findIndex((f) => Number(f.vaddr) === addr);
    if (idx >= 0) return idx;
    const base = nativeFuncBaseVaddr();
    idx = funcs.findIndex((f) => Number(f.vaddr) - base === addr);
    if (idx >= 0) return idx;
    if (currentFn?.vaddr != null) {
      const abs = Number(currentFn.vaddr) + addr;
      idx = funcs.findIndex((f) => Number(f.vaddr) === abs);
      if (idx >= 0) return idx;
    }
  }
  return -1;
}

/** Parse sub_1120 / #0x1120 / 0x1120 → number, else null. */
function parseNativeAddrToken(token) {
  const raw = String(token || '').trim();
  const sub = raw.match(/^sub_([0-9a-fA-F]+)$/i);
  if (sub) {
    const n = parseInt(sub[1], 16);
    return Number.isFinite(n) ? n : null;
  }
  const hex = raw.match(/^(?:#)?(?:0x)?([0-9a-fA-F]+)$/i);
  if (hex && hex[1].length >= 3) {
    const n = parseInt(hex[1], 16);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

/** Prefer absolute vaddr for a sub_/imm token. */
function resolveNativeCalleeVaddr(token) {
  const idx = resolveNativeCalleeIndex(token);
  if (idx >= 0) return Number(browseInfo.functions[idx].vaddr);
  return parseNativeAddrToken(token);
}

function escapeAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/** Syntax + usage token: always carries data-ident for hover/pin find-usages. */
function paintIdentToken(id, extraClass = '') {
  const cls = ['src-ident', extraClass].filter(Boolean).join(' ');
  return `<span class="${cls}" data-ident="${escapeAttr(id)}">${escapeHtml(id)}</span>`;
}

function nativeCalleeLinkHtml(label, token) {
  const idx = resolveNativeCalleeIndex(token);
  const vaddr = resolveNativeCalleeVaddr(token);
  if (idx < 0 && (vaddr == null || !Number.isFinite(vaddr))) {
    return escapeHtml(label);
  }
  const tipName =
    (idx >= 0 ? browseInfo.functions[idx]?.name : null) ||
    (vaddr != null ? `sub_${Number(vaddr).toString(16)}` : label);
  const tip =
    vaddr != null
      ? `${tipName} · ${formatFuncRel(vaddr)} (${formatVaddr(vaddr)})`
      : tipName;
  const attrs = [
    'href="#"',
    'class="native-fn-link bc-addr-link src-ident src-call"',
    `data-ident="${escapeAttr(label)}"`,
    idx >= 0 ? `data-func-idx="${idx}"` : 'data-func-idx=""',
    vaddr != null ? `data-vaddr="${Number(vaddr) >>> 0}"` : '',
    `title="${escapeHtml(tip)}"`,
  ]
    .filter(Boolean)
    .join(' ');
  return `<a ${attrs}>${escapeHtml(label)}</a>`;
}

const C_KEYWORDS = new Set([
  'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double',
  'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'inline', 'int', 'long',
  'register', 'restrict', 'return', 'short', 'signed', 'sizeof', 'static', 'struct',
  'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while',
  '_Bool', '_Complex', '_Imaginary', 'true', 'false', 'NULL', 'nullptr',
]);

const C_TYPES = new Set([
  'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t',
  'int64_t', 'size_t', 'ssize_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t', 'bool',
  'u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'usize',
  'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8',
  'byte', 'word', 'dword', 'qword', 'uchar', 'ushort', 'uint', 'ulong',
  'JNIEnv', 'jobject', 'jclass', 'jmethodID', 'jfieldID', 'jstring', 'jarray',
  'jint', 'jlong', 'jboolean', 'jbyte', 'jchar', 'jshort', 'jfloat', 'jdouble',
  'jsize', 'jvalue', 'jthrowable', 'JavaVM',
]);

/** Micro/Legacy IR intrinsics that should read as ops, not plain idents. */
const C_INTRINSICS = new Set([
  'LOAD', 'STORE', 'INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_DIV', 'INT_REM',
  'INT_AND', 'INT_OR', 'INT_XOR', 'INT_LEFT', 'INT_RIGHT', 'INT_SRIGHT',
  'INT_NEGATE', 'INT_NOTEQUAL', 'INT_EQUAL', 'INT_LESS', 'INT_LESSEQUAL',
  'INT_SLESS', 'INT_SLESSEQUAL', 'INT_ZEXT', 'INT_SEXT', 'INT_CARRY',
  'BOOL_NEGATE', 'BOOL_AND', 'BOOL_OR', 'BOOL_XOR',
  'FLOAT_ADD', 'FLOAT_SUB', 'FLOAT_MULT', 'FLOAT_DIV', 'FLOAT_NEG',
  'COPY', 'PIECE', 'SUBPIECE', 'MULTIEQUAL', 'INDIRECT', 'PTRADD', 'PTRSUB',
  'CAST', 'CALL', 'CALLIND', 'RETURN', 'BRANCH', 'CBRANCH', 'BRANCHIND',
]);

const ARM_REG_RE = /^(?:[xwvsdqbp]\d+|sp|lr|fp|xzr|wzr|nzcv|wsp|pc)$/i;

/** ARM mnemonic → DEX-style opcode class for listing tint. */
function armOpcodeClass(mnemonic) {
  const m = String(mnemonic || '').toLowerCase();
  if (!m) return '';
  if (
    m === 'ret' || m === 'retaa' || m === 'retab' || m === 'eret' ||
    m === 'br' || m === 'braa' || m === 'brab'
  ) {
    return 'bc-op-return';
  }
  if (m === 'bl' || m === 'blr' || m === 'blraa' || m === 'blrab' || m === 'svc') {
    return 'bc-op-invoke';
  }
  if (
    m === 'b' || m.startsWith('b.') || m === 'bcond' ||
    m === 'cbz' || m === 'cbnz' || m === 'tbz' || m === 'tbnz' ||
    m === 'csel' || m === 'cset' || m === 'csetm' || m === 'cinc' ||
    m === 'csinc' || m === 'csinv' || m === 'csneg'
  ) {
    return 'bc-op-branch';
  }
  if (
    m === 'mov' || m === 'movz' || m === 'movk' || m === 'movn' ||
    m === 'fmov' || m === 'mvn'
  ) {
    return 'bc-op-move';
  }
  if (
    m.startsWith('ldr') || m.startsWith('str') || m.startsWith('ldp') ||
    m.startsWith('stp') || m === 'adr' || m === 'adrp'
  ) {
    return 'bc-op-const';
  }
  return '';
}

function armInsnLineKind(mnemonic) {
  const cls = armOpcodeClass(mnemonic);
  if (cls === 'bc-op-branch') return 'branch';
  if (cls === 'bc-op-return') return 'return';
  if (cls === 'bc-op-invoke') return 'invoke';
  return '';
}

function classifyArmCfgBlock(nodeId, insns, loopHeaders) {
  if (nodeId === 0) return 'entry';
  if (loopHeaders.has(nodeId)) return 'loop';
  if (!insns.length) return 'empty';
  const lastMn = String(insns[insns.length - 1].mnemonic || '').toLowerCase();
  const kind = armInsnLineKind(lastMn);
  if (kind === 'return') return 'exit';
  if (kind === 'branch') return 'branch';
  if (kind === 'invoke') return 'invoke';
  if (insns.some((r) => armInsnLineKind(r.mnemonic) === 'invoke')) return 'invoke';
  return 'normal';
}

function computeLoopHeaders(edges, levelMap) {
  const headers = new Set();
  for (const e of edges) {
    const from = e.from_id ?? e.fromId;
    const to = e.to_id ?? e.toId;
    if ((levelMap[to] ?? 0) <= (levelMap[from] ?? 0)) {
      headers.add(to);
    }
  }
  headers.delete(0);
  return headers;
}

function computeCfgLevels(nodes, edges, entryId = 0) {
  const levelMap = {};
  const outEdges = {};
  for (const e of edges) {
    const from = e.from_id ?? e.fromId;
    const to = e.to_id ?? e.toId;
    if (!outEdges[from]) outEdges[from] = [];
    outEdges[from].push(to);
  }
  let queue = [entryId];
  levelMap[entryId] = 0;
  const seen = new Set([entryId]);
  while (queue.length) {
    const id = queue.shift();
    const level = levelMap[id];
    for (const toId of outEdges[id] || []) {
      if (!seen.has(toId)) {
        seen.add(toId);
        levelMap[toId] = level + 1;
        queue.push(toId);
      }
    }
  }
  const maxLevel = nodes.length;
  for (const n of nodes) {
    const id = n.id;
    if (levelMap[id] === undefined) levelMap[id] = maxLevel;
  }
  return levelMap;
}

/** Match DEX CFG edge coloring / labels (True / False / fall-through / back). */
function buildArmCfgEdgeStyle(fromId, toId, edgeIdx, outCount, levelMap, fromBlockKind, theme, lastMnemonic) {
  const back = (levelMap[toId] ?? 0) <= (levelMap[fromId] ?? 0);
  const labelFont = (color) => ({
    size: 11,
    color,
    face: theme.mono,
    align: 'horizontal',
    strokeWidth: 3,
    strokeColor: theme.bg,
    background: 'transparent',
  });
  void lastMnemonic;

  if (back) {
    return {
      color: theme.edgeBack,
      highlight: theme.text,
      hover: theme.edgeBack,
      opacity: 1,
      dashes: false,
      width: 2.4,
      label: '↺',
      font: labelFont(theme.edgeBack),
      edgeKind: 'back',
    };
  }

  if (fromBlockKind === 'branch' && outCount === 2) {
    const isTaken = edgeIdx === 0;
    const color = isTaken ? theme.edgeYes : theme.edgeNo;
    return {
      color,
      highlight: theme.text,
      hover: color,
      opacity: 1,
      dashes: false,
      width: 2.6,
      label: '',
      font: labelFont(color),
      edgeKind: isTaken ? 'taken' : 'fall',
    };
  }

  if (fromBlockKind === 'branch' && outCount > 1) {
    const isSecondary = edgeIdx > 0;
    const color = isSecondary ? theme.yellow : theme.edgeFlow;
    return {
      color,
      highlight: theme.text,
      hover: color,
      opacity: 1,
      dashes: false,
      width: isSecondary ? 2.1 : 2.4,
      label: outCount <= 4 ? String(edgeIdx) : '',
      font: labelFont(color),
      edgeKind: isSecondary ? 'alt' : 'flow',
    };
  }

  return {
    color: theme.edgeFlow,
    highlight: theme.accent,
    hover: theme.accent,
    opacity: 0.95,
    dashes: false,
    width: 2.1,
    label: '',
    font: labelFont(theme.muted),
    edgeKind: 'flow',
  };
}

function buildCfgOrthogonalPoints(fromPos, toPos, fromSize, toSize, opts = {}) {
  const fw = (fromSize?.width || 220) / 2;
  const fh = (fromSize?.height || 64) / 2;
  const tw = (toSize?.width || 220) / 2;
  const th = (toSize?.height || 64) / 2;
  const fx = fromPos.x;
  const fy = fromPos.y;
  const tx = toPos.x;
  const ty = toPos.y;
  const lane = opts.lane || 0;
  const sideSign = opts.sideSign >= 0 ? 1 : -1;
  const isBack = ty + th < fy - fh + 2;

  if (isBack) {
    const pad = 28 + lane * 16;
    const channelX = sideSign > 0
      ? Math.max(fx + fw, tx + tw) + pad
      : Math.min(fx - fw, tx - tw) - pad;
    const start = { x: fx, y: fy + fh };
    const end = { x: tx, y: ty - th };
    const y1 = start.y + 12 + (lane % 3) * 6;
    const y2 = end.y - 12 - (lane % 3) * 6;
    return [
      start,
      { x: fx, y: y1 },
      { x: channelX, y: y1 },
      { x: channelX, y: y2 },
      { x: tx, y: y2 },
      end,
    ];
  }

  const start = { x: fx, y: fy + fh };
  const end = { x: tx, y: ty - th };
  if (Math.abs(fx - tx) < 1.5) {
    return [start, end];
  }
  const gap = end.y - start.y;
  const frac = Math.min(0.72, Math.max(0.28, 0.5 + lane * 0.08));
  const midY = start.y + gap * frac;
  return [
    start,
    { x: fx, y: midY },
    { x: tx, y: midY },
    end,
  ];
}

function drawCfgArrowHead(ctx, fromPt, toPt, color, size = 9) {
  const dx = toPt.x - fromPt.x;
  const dy = toPt.y - fromPt.y;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  const tip = toPt;
  const left = {
    x: tip.x - ux * size - uy * size * 0.55,
    y: tip.y - uy * size + ux * size * 0.55,
  };
  const right = {
    x: tip.x - ux * size + uy * size * 0.55,
    y: tip.y - uy * size - ux * size * 0.55,
  };
  ctx.beginPath();
  ctx.moveTo(tip.x, tip.y);
  ctx.lineTo(left.x, left.y);
  ctx.lineTo(right.x, right.y);
  ctx.closePath();
  ctx.fillStyle = color;
  ctx.fill();
}

function drawCfgOrthogonalEdges(ctx) {
  const state = cfgOrthoEdgeState;
  if (!state || !cfgNetwork || !ctx) return;
  const positions = cfgNetwork.getPositions();
  const selected = new Set((cfgNetwork.getSelectedEdges?.() || []).map(String));
  const scale = cfgNetwork.getScale() || 1;
  const px = (n) => Math.max(1, n / scale);

  ctx.save();
  ctx.lineCap = 'butt';
  ctx.lineJoin = 'miter';
  ctx.miterLimit = 2;
  if (typeof ctx.imageSmoothingEnabled === 'boolean') ctx.imageSmoothingEnabled = false;

  for (const edge of state.edges) {
    const fromPos = positions[edge.from];
    const toPos = positions[edge.to];
    if (!fromPos || !toPos) continue;
    const fromSize = state.sizes[edge.from] || { width: 220, height: 64 };
    const toSize = state.sizes[edge.to] || { width: 220, height: 64 };
    const points = buildCfgOrthogonalPoints(fromPos, toPos, fromSize, toSize, {
      lane: edge.lane,
      sideSign: edge.sideSign,
    });
    if (points.length < 2) continue;

    const isSel = selected.has(String(edge.id));
    const color = isSel ? (edge.highlight || edge.color) : edge.color;
    const width = px(isSel ? (edge.width || 2) + 1.2 : (edge.width || 2));

    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
    ctx.strokeStyle = color;
    ctx.globalAlpha = edge.opacity == null ? 1 : edge.opacity;
    ctx.lineWidth = width;
    if (edge.dashes) ctx.setLineDash([px(6), px(4)]);
    else ctx.setLineDash([]);
    ctx.stroke();
    ctx.globalAlpha = 1;

    const a = points[points.length - 2];
    const b = points[points.length - 1];
    drawCfgArrowHead(ctx, a, b, color, px(edge.edgeKind === 'back' ? 8 : 9));

    if (edge.label) {
      let best = null;
      let bestLen = -1;
      for (let i = 0; i < points.length - 1; i++) {
        const p0 = points[i];
        const p1 = points[i + 1];
        const horiz = Math.abs(p0.y - p1.y) < 0.5;
        const len = Math.hypot(p1.x - p0.x, p1.y - p0.y);
        if (horiz && len > bestLen) {
          bestLen = len;
          best = { x: (p0.x + p1.x) / 2, y: p0.y };
        }
      }
      if (!best) {
        const mid = points[Math.floor(points.length / 2)];
        best = { x: mid.x, y: mid.y };
      }
      const fontPx = Math.max(9, 11 / scale);
      ctx.font = `${fontPx}px ${state.mono || 'monospace'}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      const tw = ctx.measureText(edge.label).width;
      const padX = px(3);
      const padY = px(2);
      const boxH = fontPx + padY * 2;
      ctx.fillStyle = state.bg || 'rgba(23,25,35,0.92)';
      ctx.fillRect(best.x - tw / 2 - padX, best.y - boxH - padY, tw + padX * 2, boxH);
      ctx.fillStyle = color;
      ctx.fillText(edge.label, best.x, best.y - padY);
    }
  }
  ctx.restore();
}

function estimateCfgNodeSize(label) {
  const lines = String(label || '').split('\n');
  let maxChars = 8;
  for (const line of lines) maxChars = Math.max(maxChars, line.length);
  return {
    width: Math.min(480, Math.max(160, maxChars * 7.2 + 28)),
    height: Math.min(320, Math.max(48, lines.length * 14 + 24)),
  };
}

function cfgThemeColors() {
  const root = document.documentElement;
  const cs = getComputedStyle(root);
  const pick = (v, fallback) => (cs.getPropertyValue(v).trim() || fallback);
  return {
    bg: pick('--surface', '#2d2d30'),
    border: pick('--border', '#3f3f46'),
    text: pick('--text', '#f1f1f1'),
    muted: pick('--text-muted', '#9d9d9d'),
    accent: pick('--accent', '#007acc'),
    green: pick('--green', '#57a64a'),
    orange: pick('--orange', '#dda95b'),
    red: pick('--red', '#d85050'),
    yellow: pick('--yellow', '#dcdcaa'),
    purple: pick('--purple', '#c563bd'),
    edgeYes: pick('--cfg-edge-yes', '#b8d7a3'),
    edgeNo: pick('--cfg-edge-no', '#d85050'),
    edgeFlow: pick('--cfg-edge-flow', '#9cdcfe'),
    edgeBack: pick('--cfg-edge-back', '#007acc'),
    mono: pick('--mono', 'Consolas, monospace'),
  };
}

function mixHex(baseHex, surfaceHex, amount) {
  const parse = (h) => {
    const s = String(h || '').replace('#', '').trim();
    if (s.length === 3) {
      return [parseInt(s[0] + s[0], 16), parseInt(s[1] + s[1], 16), parseInt(s[2] + s[2], 16)];
    }
    if (s.length >= 6) {
      return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
    }
    return [45, 45, 48];
  };
  const [br, bg, bb] = parse(baseHex);
  const [sr, sg, sb] = parse(surfaceHex);
  const t = Math.max(0, Math.min(1, amount));
  const r = Math.round(br * t + sr * (1 - t));
  const g = Math.round(bg * t + sg * (1 - t));
  const b = Math.round(bb * t + sb * (1 - t));
  return `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`;
}

function blockKindColors(kind, theme) {
  switch (kind) {
    case 'entry':
      return {
        background: mixHex(theme.green, theme.bg, 0.28),
        border: theme.green,
        highlight: { background: mixHex(theme.green, theme.bg, 0.4), border: theme.green },
        hover: { background: mixHex(theme.green, theme.bg, 0.34), border: theme.green },
      };
    case 'exit':
      return {
        background: mixHex(theme.orange, theme.bg, 0.26),
        border: theme.orange,
        highlight: { background: mixHex(theme.orange, theme.bg, 0.38), border: theme.orange },
        hover: { background: mixHex(theme.orange, theme.bg, 0.32), border: theme.orange },
      };
    case 'branch':
      return {
        background: mixHex(theme.yellow, theme.bg, 0.22),
        border: theme.yellow,
        highlight: { background: mixHex(theme.yellow, theme.bg, 0.34), border: theme.yellow },
        hover: { background: mixHex(theme.yellow, theme.bg, 0.28), border: theme.yellow },
      };
    case 'invoke':
      return {
        background: mixHex(theme.accent, theme.bg, 0.24),
        border: theme.accent,
        highlight: { background: mixHex(theme.accent, theme.bg, 0.36), border: theme.accent },
        hover: { background: mixHex(theme.accent, theme.bg, 0.3), border: theme.accent },
      };
    case 'loop':
      return {
        background: mixHex(theme.purple, theme.bg, 0.24),
        border: theme.purple,
        highlight: { background: mixHex(theme.purple, theme.bg, 0.36), border: theme.purple },
        hover: { background: mixHex(theme.purple, theme.bg, 0.3), border: theme.purple },
      };
    case 'empty':
      return {
        background: theme.bg,
        border: theme.muted,
        highlight: { background: theme.bg, border: theme.muted },
        hover: { background: theme.bg, border: theme.muted },
      };
    default:
      return {
        background: theme.bg,
        border: theme.border,
        highlight: {
          background: mixHex(theme.accent, theme.bg, 0.14),
          border: theme.accent,
        },
        hover: {
          background: mixHex(theme.accent, theme.bg, 0.08),
          border: theme.border,
        },
      };
  }
}

function highlightArmOperands(operands) {
  const s = String(operands || '');
  if (!s) return '';
  let html = escapeHtml(s);
  html = html.replace(/(?:#)?0x([0-9a-fA-F]+)\b/gi, (full) => {
    const linked = nativeCalleeLinkHtml(full, full.replace(/^#/, ''));
    return linked.includes('<a ') ? linked : `<span class="bc-imm">${full}</span>`;
  });
  html = html.replace(/\b(sub_[0-9a-fA-F]+|[A-Za-z_][\w$.@]*)\b/g, (id) => {
    if (/^[xwvsdq]\d+$/i.test(id) || /^(sp|lr|fp|xzr|wzr|nzcv|wsp)$/i.test(id)) return id;
    if (id.includes('<')) return id;
    if (/^sub_/i.test(id) || resolveNativeCalleeIndex(id) >= 0) {
      return nativeCalleeLinkHtml(id, id);
    }
    return id;
  });
  return html.replace(/\b([xw]\d+|v\d+|s\d+|d\d+|q\d+|sp|lr|fp|xzr|wzr|nzcv|wsp)\b/gi, (m) => {
    if (m.includes('<')) return m;
    const num = (m.match(/\d+/) || ['0'])[0];
    const hue = Number(num) % 12;
    return `<span class="bc-reg bc-reg-h${hue}">${m}</span>`;
  });
}

/** C-like highlighter for arm_decompiler output (Legacy + Micro IR soup). */
function highlightCLike(source) {
  if (!source || typeof source !== 'string') return '';
  let html = '';
  let i = 0;
  const n = source.length;

  const paintReg = (id) => {
    const num = (id.match(/\d+/) || ['0'])[0];
    const hue = Number(num) % 12;
    return paintIdentToken(id, `src-reg bc-reg bc-reg-h${hue}`);
  };

  while (i < n) {
    if (source.slice(i, i + 2) === '/*') {
      let end = source.indexOf('*/', i + 2);
      if (end === -1) end = n - 2;
      html += `<span class="src-comment">${escapeHtml(source.slice(i, end + 2))}</span>`;
      i = end + 2;
      continue;
    }
    if (source.slice(i, i + 2) === '//') {
      let end = source.indexOf('\n', i + 2);
      if (end === -1) end = n;
      html += `<span class="src-comment">${escapeHtml(source.slice(i, end))}</span>`;
      i = end;
      continue;
    }
    if (source[i] === '"' || source[i] === "'") {
      const q = source[i];
      let j = i + 1;
      while (j < n) {
        if (source[j] === '\\') {
          j += 2;
          continue;
        }
        if (source[j] === q) {
          j++;
          break;
        }
        j++;
      }
      html += `<span class="src-string">${escapeHtml(source.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    // Labels like L_9e820:
    if (/^[A-Za-z_][\w]*:/.test(source.slice(i))) {
      const m = source.slice(i).match(/^([A-Za-z_][\w]*):/);
      html += `${paintIdentToken(m[1], 'src-label')}:`;
      i += m[0].length;
      continue;
    }
    // #imm / #0x… / bare hex / decimals
    if (source[i] === '#' || /[0-9]/.test(source[i])) {
      const m = source.slice(i).match(/^#?(0[xX][0-9a-fA-F]+|\d+\.\d*(?:[eE][+-]?\d+)?|\d+)/);
      if (m) {
        html += `<span class="src-number">${escapeHtml(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
    }
    if (/^[A-Za-z_]/.test(source[i])) {
      const m = source.slice(i).match(/^[A-Za-z_][\w$]*/);
      const id = m[0];
      if (C_KEYWORDS.has(id)) {
        html += `<span class="src-keyword">${escapeHtml(id)}</span>`;
      } else if (C_TYPES.has(id)) {
        html += paintIdentToken(id, 'src-type');
      } else if (C_INTRINSICS.has(id)) {
        html += paintIdentToken(id, 'src-intrinsic');
      } else if (ARM_REG_RE.test(id)) {
        html += paintReg(id);
      } else if (/^local_\w+$/i.test(id) || /^param_\w+$/i.test(id) || /^uVar\d+$/i.test(id) || /^iVar\d+$/i.test(id) || /^stack$/i.test(id)) {
        html += paintIdentToken(id, 'src-local');
      } else {
        let k = i + id.length;
        while (k < n && /\s/.test(source[k])) k++;
        const isCall = source[k] === '(';
        const isSub = /^sub_/i.test(id);
        if ((isCall || isSub || id.startsWith('Java_')) && (isSub || resolveNativeCalleeIndex(id) >= 0 || resolveNativeCalleeVaddr(id) != null)) {
          const linked = nativeCalleeLinkHtml(id, id);
          html += linked.includes('<a ')
            ? linked
            : paintIdentToken(id, isCall ? 'src-call' : '');
        } else if (isCall) {
          html += paintIdentToken(id, 'src-call');
        } else {
          html += paintIdentToken(id);
        }
      }
      i += id.length;
      continue;
    }
    html += escapeHtml(source[i]);
    i++;
  }
  return html;
}

function cfgBlockKindLabel(kind) {
  switch (kind) {
    case 'entry': return 'entry';
    case 'exit': return 'exit';
    case 'branch': return 'branch';
    case 'invoke': return 'call';
    case 'loop': return 'loop';
    case 'empty': return 'empty';
    default: return '';
  }
}

function buildArmCfgInsnHtml(row, { isTerm = false } = {}) {
  const opCls = armOpcodeClass(row.mnemonic);
  const lineKind = armInsnLineKind(row.mnemonic);
  const opRaw = String(row.operands || '').trim();
  const operands = opRaw
    ? `<span class="bc-operands">${highlightArmOperands(opRaw)}</span>`
    : '';
  const termCls = isTerm ? ' cfg-insn-term' : '';
  return `<div class="bytecode-line cfg-insn-line${lineKind ? ' cfg-insn-' + lineKind : ''}${termCls}" data-off="${Number(row.offset) >>> 0}" data-vaddr="">` +
    `<span class="bc-offset">${formatOff(row.offset)}</span>` +
    `<span class="bc-mnemonic${opCls ? ' ' + opCls : ''}">${escapeHtml(row.mnemonic || '')}</span>` +
    operands +
    `</div>`;
}

function buildArmCfgSuccessorTags(fromId, toIds, nodeById, blockKind) {
  if (!toIds?.length) return [];
  return toIds.map((toId, idx) => {
    const n = nodeById.get(toId);
    const loc = n?.label || formatOff(n?.start_offset ?? n?.startOffset ?? toId);
    if (blockKind === 'branch' && toIds.length === 2) {
      return { text: `→ ${loc}`, cls: idx === 0 ? 'cfg-succ-t' : 'cfg-succ-f', toId };
    }
    if (toIds.length === 1) return { text: `→ ${loc}`, cls: 'cfg-succ-flow', toId };
    return { text: `→ ${loc}`, cls: 'cfg-succ-multi', toId };
  });
}

function buildArmCfgBlockHtml(node, insns, blockKind, succTags, compact) {
  const start = node.start_offset ?? node.startOffset ?? 0;
  const end = node.end_offset ?? node.endOffset ?? start;
  const endStr = end === 0 || end === 0xffffffff ? '…' : formatOff(end);
  const kindLabel = cfgBlockKindLabel(blockKind);
  let body = '';
  if (!insns.length) {
    body = `<div class="cfg-insn-empty"><span class="bc-offset">${formatOff(start)}</span> (empty)</div>`;
  } else if (compact) {
    body = buildArmCfgInsnHtml(insns[insns.length - 1], { isTerm: true });
  } else {
    const maxShow = 24;
    const shown = insns.slice(0, maxShow);
    body = shown.map((r, i) => buildArmCfgInsnHtml(r, { isTerm: i === shown.length - 1 })).join('');
    if (insns.length > maxShow) {
      body += `<div class="cfg-insn-empty">… +${insns.length - maxShow} more</div>`;
    }
  }
  const rangeComment = kindLabel
    ? `<span class="cfg-block-comment">; ${kindLabel}${compact ? '' : ` · ${formatOff(start)}–${endStr}`}</span>`
    : (compact ? '' : `<span class="cfg-block-comment">; ${formatOff(start)}–${endStr}</span>`);
  const foot = succTags?.length
    ? `<div class="cfg-block-foot">${succTags.map((s) =>
        `<button type="button" class="cfg-succ ${s.cls}" data-cfg-to="${s.toId}" title="Go to ${escapeHtml(s.text)}">${escapeHtml(s.text)}</button>`
      ).join('')}</div>`
    : '';
  const cls = [
    'cfg-block',
    `cfg-block-${blockKind}`,
    'cfg-no-hex',
    compact ? 'cfg-compact' : '',
  ].filter(Boolean).join(' ');
  const loc = node.label || formatOff(start);
  return `<div class="${cls}" data-node-id="${node.id}" data-start-offset="${start}">` +
    `<div class="cfg-block-head" title="Drag header to reposition">` +
    `<span class="cfg-block-drag" title="Drag to reposition" aria-hidden="true">⋮⋮</span>` +
    `<span class="cfg-block-loc">${escapeHtml(loc)}</span>${rangeComment}` +
    `</div>` +
    `<div class="cfg-block-body">${body}</div>` +
    foot +
    `</div>`;
}

/** @type {{ runInParseWorker: Function, switchToCenterTab: Function, setStatus?: Function, timeoutMs?: number, onSelectLib?: Function } | null} */
let api = null;

/** @type {Uint8Array | null} */
let currentBytes = null;
/** @type {string} */
let currentPath = '';
/** @type {object | null} */
let browseInfo = null;
/** @type {number} */
let selectedFuncIdx = -1;
/** @type {object | null} */
let currentFn = null;
/** @type {any} */
let cfgNetwork = null;
/** @type {{ bg: string, mono: string, sizes: Record<number|string, {width:number,height:number}>, edges: any[] } | null} */
let cfgOrthoEdgeState = null;
/** @type {((ctx: CanvasRenderingContext2D) => void) | null} */
let cfgNetworkDrawHandler = null;
/** @type {boolean} */
let nativeCfgCompact = false;
/** Manual block positions for the current function: nodeId → {x,y} */
let nativeCfgBlockPositions = new Map();
/** @type {{ id: string, el: Element, originX: number, originY: number, startClientX: number, startClientY: number, scale: number, moved: boolean, pointerId: number } | null} */
let nativeCfgBlockDragSession = null;
/** @type {string[]} */
let apkLibPaths = [];

const NATIVE_CFG_MIN_W = 168;
const NATIVE_CFG_MAX_W = 520;
const NATIVE_CFG_MAX_H = 420;
const NATIVE_CFG_COMPACT_KEY = 'droid2web-native-cfg-compact';

function loadNativeCfgCompactPref() {
  try {
    nativeCfgCompact = localStorage.getItem(NATIVE_CFG_COMPACT_KEY) === '1';
  } catch (_) {
    nativeCfgCompact = false;
  }
  const el = $('native-cfg-compact');
  if (el) el.checked = nativeCfgCompact;
}

function saveNativeCfgCompactPref() {
  try {
    localStorage.setItem(NATIVE_CFG_COMPACT_KEY, nativeCfgCompact ? '1' : '0');
  } catch (_) { /* ignore */ }
}

function clearNativeCfgHtmlLayer() {
  const layer = $('native-cfg-html-layer');
  if (!layer) return;
  layer.innerHTML = '';
  layer.hidden = true;
  layer.setAttribute('aria-hidden', 'true');
  layer.style.removeProperty('--cfg-z');
}

function endNativeCfgBlockDragSession() {
  if (!nativeCfgBlockDragSession) return;
  const { el, id, moved } = nativeCfgBlockDragSession;
  el?.classList.remove('cfg-block-dragging');
  $('native-cfg-graph-wrap')?.classList.remove('cfg-block-dragging-view');
  if (moved && cfgNetwork && id != null) {
    try {
      const pos = cfgNetwork.getPositions([id])[id];
      if (pos) nativeCfgBlockPositions.set(String(id), { x: pos.x, y: pos.y });
    } catch (_) {}
  }
  nativeCfgBlockDragSession = null;
}

function applyNativeCfgBlockPositions() {
  if (!cfgNetwork || !nativeCfgBlockPositions.size) return;
  try {
    for (const [id, pos] of nativeCfgBlockPositions) {
      if (pos && Number.isFinite(pos.x) && Number.isFinite(pos.y)) {
        cfgNetwork.moveNode(id, Math.round(pos.x), Math.round(pos.y));
      }
    }
  } catch (_) {}
  syncNativeCfgHtmlOverlay();
}

/**
 * Push apart any AABB overlaps left after hierarchical + repulsion layout.
 * vis nodeSpacing is center-to-center and often undershoots wide HTML blocks.
 */
function resolveNativeCfgOverlaps(blockSizes, { gap = 28, iterations = 48 } = {}) {
  if (!cfgNetwork || !blockSizes) return;
  const ids = Object.keys(blockSizes);
  if (ids.length < 2) return;
  let pos;
  try {
    pos = cfgNetwork.getPositions(ids);
  } catch (_) {
    return;
  }
  for (let iter = 0; iter < iterations; iter++) {
    let moved = false;
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i];
        const b = ids[j];
        const pa = pos[a];
        const pb = pos[b];
        const sa = blockSizes[a];
        const sb = blockSizes[b];
        if (!pa || !pb || !sa || !sb) continue;
        const dx = pb.x - pa.x;
        const dy = pb.y - pa.y;
        const needX = (sa.width + sb.width) / 2 + gap;
        const needY = (sa.height + sb.height) / 2 + gap;
        const ox = needX - Math.abs(dx);
        const oy = needY - Math.abs(dy);
        if (ox <= 0 || oy <= 0) continue;
        if (ox < oy) {
          const dir = dx === 0 ? (Number(a) <= Number(b) ? -1 : 1) : Math.sign(dx);
          const push = (ox / 2) * (dir || 1);
          pa.x -= push;
          pb.x += push;
        } else {
          const dir = dy === 0 ? 1 : Math.sign(dy);
          const push = (oy / 2) * (dir || 1);
          pa.y -= push;
          pb.y += push;
        }
        moved = true;
      }
    }
    if (!moved) break;
  }
  try {
    for (const id of ids) {
      const p = pos[id];
      if (p) cfgNetwork.moveNode(id, Math.round(p.x), Math.round(p.y));
    }
  } catch (_) {}
}

function resetNativeCfgLayout() {
  nativeCfgBlockPositions.clear();
  endNativeCfgBlockDragSession();
  if (currentFn) renderCfg(currentFn);
}

function destroyCfg() {
  endNativeCfgBlockDragSession();
  if (cfgNetwork) {
    try {
      if (cfgNetworkDrawHandler) {
        try { cfgNetwork.off('afterDrawing', cfgNetworkDrawHandler); } catch (_) {}
      }
      cfgNetwork.destroy();
    } catch (_) {}
    cfgNetwork = null;
  }
  cfgNetworkDrawHandler = null;
  cfgOrthoEdgeState = null;
  clearNativeCfgHtmlLayer();
  const g = $('native-cfg-graph');
  if (g) g.innerHTML = '';
}

function showCfgEmpty(show) {
  const empty = $('native-cfg-empty');
  const graph = $('native-cfg-graph');
  const layer = $('native-cfg-html-layer');
  if (empty) empty.hidden = !show;
  if (graph) graph.style.display = show ? 'none' : '';
  if (layer && show) {
    layer.hidden = true;
    layer.setAttribute('aria-hidden', 'true');
  }
}

function measureNativeCfgBlockSizes() {
  const sizes = {};
  const layer = $('native-cfg-html-layer');
  if (!layer) return sizes;
  const maxW = nativeCfgCompact ? 360 : NATIVE_CFG_MAX_W;
  layer.style.setProperty('--cfg-z', '1');
  for (const el of layer.querySelectorAll('.cfg-block')) {
    const id = el.getAttribute('data-node-id');
    if (id == null) continue;
    el.style.height = '';
    el.style.minWidth = '';
    el.style.transform = '';
    el.style.maxWidth = `${maxW}px`;
    el.style.width = '';
    const rawW = Math.max(NATIVE_CFG_MIN_W, Math.ceil(el.offsetWidth));
    const width = Math.min(maxW, rawW);
    el.style.width = `${width}px`;
    const rawH = Math.max(40, Math.ceil(el.offsetHeight));
    const height = Math.min(NATIVE_CFG_MAX_H, rawH);
    el.style.height = `${height}px`;
    sizes[id] = { width, height };
    el.dataset.layoutW = String(width);
    el.dataset.layoutH = String(height);
  }
  return sizes;
}

function syncNativeCfgHtmlOverlay() {
  if (!cfgNetwork) return;
  const layer = $('native-cfg-html-layer');
  const graph = $('native-cfg-graph');
  if (!layer || layer.hidden) return;
  const positions = cfgNetwork.getPositions();
  const scale = cfgNetwork.getScale();
  if (!Number.isFinite(scale) || scale <= 0) return;
  const dpr = (typeof window !== 'undefined' && window.devicePixelRatio) || 1;
  layer.style.setProperty('--cfg-z', String(scale));
  if (graph) {
    const grid = Math.max(10, Math.round(20 * scale));
    graph.style.backgroundSize = `${grid}px ${grid}px`;
  }
  for (const el of layer.querySelectorAll('.cfg-block')) {
    const id = el.getAttribute('data-node-id');
    const pos = positions[id];
    if (!pos) continue;
    const dom = cfgNetwork.canvasToDOM({ x: pos.x, y: pos.y });
    const baseW = Number(el.dataset.layoutW) || Math.max(168, el.offsetWidth) || 200;
    const baseH = Number(el.dataset.layoutH) || Math.max(32, el.offsetHeight) || 64;
    const w = baseW * scale;
    const h = baseH * scale;
    const left = Math.round((dom.x - w / 2) * dpr) / dpr;
    const top = Math.round((dom.y - h / 2) * dpr) / dpr;
    el.style.width = `${w}px`;
    el.style.height = `${h}px`;
    el.style.maxWidth = 'none';
    el.style.minWidth = '0';
    el.style.transformOrigin = '0 0';
    el.style.transform = `translate3d(${left}px, ${top}px, 0)`;
  }
}

function setNativeCfgBlockSelected(nodeId) {
  const layer = $('native-cfg-html-layer');
  if (!layer) return;
  layer.querySelectorAll('.cfg-block.is-selected').forEach((el) => el.classList.remove('is-selected'));
  if (nodeId == null) return;
  const el = layer.querySelector(`.cfg-block[data-node-id="${CSS.escape(String(nodeId))}"]`);
  if (el) el.classList.add('is-selected');
}

function scrollAsmToOffset(offset) {
  const listing = $('native-asm-listing');
  if (!listing) return;
  const off = Number(offset) >>> 0;
  const line = listing.querySelector(`.bytecode-line[data-offset="${off}"]`);
  if (!line) return;
  listing.querySelectorAll('.bytecode-line.is-cfg-focus').forEach((el) => el.classList.remove('is-cfg-focus'));
  line.classList.add('is-cfg-focus');
  line.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

function focusNativeCfgNode(nodeId) {
  if (!cfgNetwork || nodeId == null) return;
  try {
    cfgNetwork.selectNodes([nodeId]);
    cfgNetwork.focus(nodeId, { scale: Math.max(cfgNetwork.getScale(), 0.85), animation: true });
  } catch (_) {}
  setNativeCfgBlockSelected(nodeId);
  const layer = $('native-cfg-html-layer');
  const el = layer?.querySelector(`.cfg-block[data-node-id="${CSS.escape(String(nodeId))}"]`);
  const start = el?.getAttribute('data-start-offset');
  if (start != null) scrollAsmToOffset(start);
}

function bindNativeCfgHtmlInteractions() {
  const layer = $('native-cfg-html-layer');
  if (!layer || layer.dataset.cfgInteractBound === '1') return;
  layer.dataset.cfgInteractBound = '1';
  const wrap = () => $('native-cfg-graph-wrap');

  layer.addEventListener('pointerdown', (e) => {
    if (e.button !== 0 || !cfgNetwork) return;
    if (e.target.closest?.('.cfg-block-body') || e.target.closest?.('.cfg-succ') || e.target.closest?.('.cfg-insn-line')) {
      return;
    }
    const head = e.target.closest?.('.cfg-block-head, .cfg-block-drag');
    if (!head) return;
    const block = e.target.closest?.('.cfg-block');
    if (!block || !layer.contains(block)) return;
    const id = block.getAttribute('data-node-id');
    let pos;
    let scale;
    try {
      pos = cfgNetwork.getPositions([id])[id];
      scale = cfgNetwork.getScale();
    } catch (_) {
      return;
    }
    if (!pos || !Number.isFinite(scale) || scale <= 0) return;
    endNativeCfgBlockDragSession();
    nativeCfgBlockDragSession = {
      id,
      el: block,
      originX: pos.x,
      originY: pos.y,
      startClientX: e.clientX,
      startClientY: e.clientY,
      scale,
      moved: false,
      pointerId: e.pointerId,
    };
    block.classList.add('cfg-block-dragging');
    wrap()?.classList.add('cfg-block-dragging-view');
    try { block.setPointerCapture(e.pointerId); } catch (_) {}
    e.preventDefault();
    e.stopPropagation();
    setNativeCfgBlockSelected(id);
  });

  layer.addEventListener('pointermove', (e) => {
    if (!nativeCfgBlockDragSession || !cfgNetwork) return;
    if (nativeCfgBlockDragSession.pointerId != null && e.pointerId !== nativeCfgBlockDragSession.pointerId) return;
    const dx = (e.clientX - nativeCfgBlockDragSession.startClientX) / nativeCfgBlockDragSession.scale;
    const dy = (e.clientY - nativeCfgBlockDragSession.startClientY) / nativeCfgBlockDragSession.scale;
    if (!nativeCfgBlockDragSession.moved && Math.hypot(dx, dy) < 2) return;
    nativeCfgBlockDragSession.moved = true;
    const x = Math.round(nativeCfgBlockDragSession.originX + dx);
    const y = Math.round(nativeCfgBlockDragSession.originY + dy);
    try {
      cfgNetwork.moveNode(nativeCfgBlockDragSession.id, x, y);
      syncNativeCfgHtmlOverlay();
    } catch (_) {}
    e.preventDefault();
  });

  const endDrag = (e) => {
    if (!nativeCfgBlockDragSession) return;
    if (e && nativeCfgBlockDragSession.pointerId != null && e.pointerId !== nativeCfgBlockDragSession.pointerId) return;
    const moved = nativeCfgBlockDragSession.moved;
    endNativeCfgBlockDragSession();
    // Suppress the following click after a real drag so we don't re-focus/animate.
    if (moved) {
      layer.dataset.suppressClick = '1';
      setTimeout(() => { delete layer.dataset.suppressClick; }, 0);
    }
  };
  layer.addEventListener('pointerup', endDrag);
  layer.addEventListener('pointercancel', endDrag);

  layer.addEventListener('click', (e) => {
    if (layer.dataset.suppressClick === '1') {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    const succ = e.target.closest?.('.cfg-succ');
    if (succ && layer.contains(succ)) {
      e.preventDefault();
      e.stopPropagation();
      const toId = Number(succ.getAttribute('data-cfg-to'));
      if (Number.isFinite(toId)) focusNativeCfgNode(toId);
      return;
    }
    const line = e.target.closest?.('.cfg-insn-line');
    if (line && layer.contains(line)) {
      const off = line.getAttribute('data-off');
      if (off != null) scrollAsmToOffset(off);
      const block = line.closest('.cfg-block');
      const id = block?.getAttribute('data-node-id');
      if (id != null) setNativeCfgBlockSelected(id);
      return;
    }
    // Header click (without drag) selects; don't animate-focus from body-less head clicks.
    const head = e.target.closest?.('.cfg-block-head');
    if (head) {
      const block = head.closest('.cfg-block');
      const id = block?.getAttribute('data-node-id');
      if (id != null) {
        setNativeCfgBlockSelected(id);
        const start = block.getAttribute('data-start-offset');
        if (start != null) scrollAsmToOffset(start);
      }
      return;
    }
    const block = e.target.closest?.('.cfg-block');
    if (block && layer.contains(block)) {
      const id = Number(block.getAttribute('data-node-id'));
      if (Number.isFinite(id)) focusNativeCfgNode(id);
    }
  });
}

function setMeta(msg) {
  const el = $('native-status-meta');
  if (el) el.textContent = msg || '';
}

function setDockCollapsed(pane, collapsed) {
  if (!pane) return;
  pane.dataset.collapsed = collapsed ? 'true' : 'false';
  const btn = pane.querySelector('.dock-toggle');
  if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
}

function renderAsmListing(fn) {
  const listing = $('native-asm-listing');
  const meta = $('native-asm-meta');
  const header = $('native-asm-col-header');
  const showHex = $('native-hex-toggle')?.checked !== false;
  if (!listing) return;
  const rows = Array.isArray(fn?.bytecode) ? fn.bytecode : [];
  if (meta) meta.textContent = rows.length ? `${rows.length} insn` : '';
  if (header) header.setAttribute('aria-hidden', rows.length ? 'false' : 'true');
  if (!rows.length) {
    listing.innerHTML =
      '<div class="code-empty"><div class="code-empty-title">No assembly</div><div class="code-empty-hint muted">Empty or failed decode</div></div>';
    return;
  }
  const workspace = $('native-workspace');
  if (workspace) workspace.classList.toggle('hide-hex', !showHex);
  let html = '';
  const fnVaddr = Number(fn?.vaddr || 0);
  for (const r of rows) {
    const opCls = armOpcodeClass(r.mnemonic);
    const lineKind = armInsnLineKind(r.mnemonic);
    const rel = Number(r.offset) >>> 0;
    const abs = fnVaddr ? fnVaddr + rel : rel;
    html +=
      `<div class="bytecode-line${lineKind ? ' cfg-insn-' + lineKind : ''}" data-offset="${rel}" data-vaddr="${abs}" title="${escapeHtml(formatVaddr(abs))}">` +
      `<span class="bc-offset" title="function-relative">${formatOff(rel)}</span>` +
      `<span class="bc-hex">${escapeHtml(String(r.hex || '').trim())}</span>` +
      `<span class="bc-mnemonic${opCls ? ' ' + opCls : ''}">${escapeHtml(r.mnemonic || '')}</span>` +
      `<span class="bc-operands">${highlightArmOperands(r.operands)}</span>` +
      `</div>`;
  }
  listing.innerHTML = html;
}

function renderSource(fn) {
  const pre = $('native-source-code');
  const meta = $('native-source-meta');
  const copyBtn = $('native-source-copy-btn');
  const src = typeof fn?.decompilation === 'string' ? fn.decompilation : '';
  nativeIdentHighlight = null;
  nativeIdentPinned = null;
  if (meta) meta.textContent = src ? `${src.split('\n').length} lines` : '';
  if (copyBtn) copyBtn.disabled = !src;
  if (!pre) return;
  if (!src) {
    pre.classList.remove('src-has-highlight');
    delete pre.dataset.hlIdent;
    pre.innerHTML =
      '<div class="code-empty"><div class="code-empty-title">No source</div><div class="code-empty-hint muted">Decompilation unavailable</div></div>';
    return;
  }
  pre.classList.add('src-has-highlight');
  delete pre.dataset.hlIdent;
  // Line-wrap so theme syntax colors + selection stay readable like the DEX source pane.
  const lines = src.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const body = lines.map((line, idx) => {
    const code = highlightCLike(line.length ? line : ' ');
    return `<div class="src-line" data-line="${idx + 1}"><span class="src-line-code">${code}</span></div>`;
  }).join('');
  pre.innerHTML = body;
}

/** Hover / click find-usages for ARM decompiled source (mirrors DEX source pane). */
let nativeIdentHighlight = null;
let nativeIdentPinned = null;
let nativeIdentHoverRaf = 0;

function clearNativeIdentHighlights(root) {
  if (!root) return;
  root.querySelectorAll('.src-ident.is-hl, .src-ident.is-hl-primary').forEach((el) => {
    el.classList.remove('is-hl', 'is-hl-primary');
  });
  delete root.dataset.hlIdent;
}

function nativeIdentSelector(ident) {
  try {
    return `.src-ident[data-ident="${CSS.escape(ident)}"]`;
  } catch (_) {
    return `.src-ident[data-ident="${String(ident).replace(/"/g, '\\"')}"]`;
  }
}

function updateNativeIdentMeta(ident, count) {
  const meta = $('native-source-meta');
  if (!meta || !currentFn?.decompilation) return;
  const lines = String(currentFn.decompilation).split('\n').length;
  if (!ident) {
    meta.textContent = `${lines} lines`;
    return;
  }
  const pin = nativeIdentPinned === ident ? ' · pinned' : '';
  meta.textContent = `${lines} lines · ${count}× ${ident}${pin}`;
}

function setNativeIdentHover(ident, scope, primaryEl = null) {
  if (!scope) return;
  if (nativeIdentPinned && ident && ident !== nativeIdentPinned) return;
  if (nativeIdentPinned && !ident) return;
  if (nativeIdentHighlight === ident && scope.dataset.hlIdent === ident) {
    scope.querySelectorAll('.src-ident.is-hl-primary').forEach((el) => el.classList.remove('is-hl-primary'));
    primaryEl?.classList.add('is-hl-primary');
    return;
  }
  clearNativeIdentHighlights(scope);
  nativeIdentHighlight = ident || null;
  if (!ident) {
    updateNativeIdentMeta(null, 0);
    return;
  }
  scope.dataset.hlIdent = ident;
  const hits = scope.querySelectorAll(nativeIdentSelector(ident));
  hits.forEach((el) => el.classList.add('is-hl'));
  primaryEl?.classList.add('is-hl-primary');
  updateNativeIdentMeta(ident, hits.length);
}

function pinNativeIdent(ident, scope, primaryEl = null) {
  if (!scope || !ident) return;
  if (nativeIdentPinned === ident) {
    nativeIdentPinned = null;
    clearNativeIdentHighlights(scope);
    nativeIdentHighlight = null;
    updateNativeIdentMeta(null, 0);
    return;
  }
  nativeIdentPinned = ident;
  setNativeIdentHover(ident, scope, primaryEl);
}

function clearPinnedNativeIdent() {
  const root = $('native-source-code');
  nativeIdentPinned = null;
  nativeIdentHighlight = null;
  clearNativeIdentHighlights(root);
  updateNativeIdentMeta(null, 0);
}

function wireNativeSourceIdentHighlight() {
  const root = $('native-source-code');
  if (!root || root.dataset.identHlBound === '1') return;
  root.dataset.identHlBound = '1';

  root.addEventListener('mousemove', (e) => {
    if (nativeIdentHoverRaf) cancelAnimationFrame(nativeIdentHoverRaf);
    nativeIdentHoverRaf = requestAnimationFrame(() => {
      nativeIdentHoverRaf = 0;
      if (!root.contains(e.target)) return;
      const identEl = e.target.closest?.('.src-ident[data-ident]');
      if (identEl && root.contains(identEl) && identEl.dataset.ident) {
        setNativeIdentHover(identEl.dataset.ident, root, identEl);
        return;
      }
      if (nativeIdentHighlight && !nativeIdentPinned) {
        clearNativeIdentHighlights(root);
        nativeIdentHighlight = null;
        updateNativeIdentMeta(null, 0);
      }
    });
  });

  root.addEventListener('mouseleave', () => {
    if (nativeIdentHoverRaf) cancelAnimationFrame(nativeIdentHoverRaf);
    nativeIdentHoverRaf = 0;
    if (nativeIdentPinned) return;
    clearNativeIdentHighlights(root);
    nativeIdentHighlight = null;
    updateNativeIdentMeta(null, 0);
  });

  root.addEventListener('click', (e) => {
    // Function links navigate; still allow Alt/Meta+click to pin usages.
    const link = e.target.closest?.('a.native-fn-link');
    if (link && !(e.altKey || e.metaKey)) return;
    const identEl = e.target.closest?.('.src-ident[data-ident]');
    if (identEl && root.contains(identEl) && identEl.dataset.ident) {
      e.preventDefault();
      e.stopPropagation();
      pinNativeIdent(identEl.dataset.ident, root, identEl);
      return;
    }
    if (nativeIdentPinned && !e.target.closest?.('.src-ident')) {
      clearPinnedNativeIdent();
    }
  }, true);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && nativeIdentPinned && !e.target.closest?.('input, textarea, select')) {
      clearPinnedNativeIdent();
    }
  });
}

function renderCfgLegend(show) {
  const legend = $('native-cfg-legend');
  if (!legend) return;
  if (!show) {
    legend.hidden = true;
    legend.setAttribute('aria-hidden', 'true');
    legend.innerHTML = '';
    return;
  }
  legend.hidden = false;
  legend.setAttribute('aria-hidden', 'false');
  const items = [
    ['block-entry', 'Entry'],
    ['block-exit', 'Return'],
    ['block-branch', 'Branch'],
    ['block-loop', 'Loop'],
    ['edge-fall', 'Fall-through'],
    ['edge-taken', 'True'],
    ['edge-fall-f', 'False'],
    ['edge-back', 'Back-edge'],
  ];
  legend.innerHTML = items
    .map(
      ([cls, text]) =>
        `<span class="cfg-legend-item"><span class="cfg-legend-swatch ${cls}"></span>${text}</span>`
    )
    .join('');
}

function renderCfg(fn) {
  destroyCfg();
  const meta = $('native-cfg-meta');
  const nodesRaw = fn?.cfg_nodes || fn?.cfgNodes || [];
  const edgesRaw = fn?.cfg_edges || fn?.cfgEdges || [];
  const bytecode = Array.isArray(fn?.bytecode) ? fn.bytecode : [];
  if (!nodesRaw.length) {
    showCfgEmpty(true);
    renderCfgLegend(false);
    if (meta) meta.textContent = '';
    return;
  }
  if (typeof vis === 'undefined') {
    showCfgEmpty(true);
    renderCfgLegend(false);
    if (meta) meta.textContent = 'vis-network missing';
    return;
  }
  showCfgEmpty(false);
  renderCfgLegend(true);
  if (meta) {
    meta.textContent = `${nodesRaw.length} blocks · ${edgesRaw.length} edges · ${bytecode.length} insn`;
  }

  const theme = cfgThemeColors();
  const levelMap = computeCfgLevels(nodesRaw, edgesRaw, 0);
  const loopHeaders = computeLoopHeaders(edgesRaw, levelMap);
  const outCount = {};
  const outEdges = {};
  for (const e of edgesRaw) {
    const from = e.from_id ?? e.fromId;
    const to = e.to_id ?? e.toId;
    outCount[from] = (outCount[from] || 0) + 1;
    if (!outEdges[from]) outEdges[from] = [];
    outEdges[from].push(to);
  }
  const outIdx = {};
  const blockKinds = new Map();
  const blockInsns = new Map();
  const nodeById = new Map();

  for (const n of nodesRaw) {
    const start = n.start_offset ?? n.startOffset ?? 0;
    const end = n.end_offset ?? n.endOffset ?? start;
    const endBound = end === 0 && start !== 0 ? Infinity : (end || Infinity);
    const insns = bytecode.filter((r) => r.offset >= start && r.offset < endBound);
    const kind = classifyArmCfgBlock(n.id, insns, loopHeaders);
    blockKinds.set(n.id, kind);
    blockInsns.set(n.id, insns);
    nodeById.set(n.id, n);
  }

  const layer = $('native-cfg-html-layer');
  const blockHtmlById = new Map();
  for (const n of nodesRaw) {
    const kind = blockKinds.get(n.id) || 'normal';
    const insns = blockInsns.get(n.id) || [];
    const succTags = buildArmCfgSuccessorTags(n.id, outEdges[n.id] || [], nodeById, kind);
    blockHtmlById.set(n.id, buildArmCfgBlockHtml(n, insns, kind, succTags, nativeCfgCompact));
  }
  if (layer) {
    layer.innerHTML = [...blockHtmlById.values()].join('');
    layer.hidden = false;
    layer.setAttribute('aria-hidden', 'false');
    bindNativeCfgHtmlInteractions();
  }

  const blockSizes = measureNativeCfgBlockSizes();
  const heightVals = Object.values(blockSizes).map((s) => s.height);
  const widthVals = Object.values(blockSizes).map((s) => s.width);
  const maxBlockH = heightVals.length ? Math.max(...heightVals) : 80;
  const maxBlockW = widthVals.length ? Math.max(...widthVals) : 220;
  // vis hierarchical spacing is center-to-center: need full size + gap, not a fraction.
  const hGap = nativeCfgCompact ? 48 : 72;
  const wGap = nativeCfgCompact ? 56 : 80;
  const levelSep = Math.round(Math.max(maxBlockH + hGap, nativeCfgCompact ? 140 : 160));
  const nodeSpace = Math.round(Math.max(maxBlockW + wGap, nativeCfgCompact ? 260 : 280));
  const treeSpace = Math.round(Math.max(maxBlockW + wGap * 1.5, nativeCfgCompact ? 340 : 380));
  const nodeDist = Math.round(Math.max(maxBlockH, maxBlockW) + (nativeCfgCompact ? 96 : 120));
  const nodeMargin = Math.round(Math.max(8, Math.min(16, (heightVals.length
    ? heightVals.reduce((a, b) => a + b, 0) / heightVals.length
    : 80) * 0.06)));

  const visNodes = nodesRaw.map((n) => {
    const size = blockSizes[n.id] || { width: 220, height: 64 };
    return {
      id: n.id,
      shape: 'box',
      label: '',
      level: levelMap[n.id],
      margin: nodeMargin,
      borderWidth: 0,
      widthConstraint: { minimum: size.width, maximum: size.width },
      heightConstraint: { minimum: size.height, maximum: size.height },
      color: {
        border: 'transparent',
        background: 'transparent',
        highlight: { border: 'transparent', background: 'rgba(99, 179, 237, 0.06)' },
        hover: { border: 'transparent', background: 'rgba(99, 179, 237, 0.04)' },
      },
      shapeProperties: { borderRadius: 0 },
      chosen: false,
    };
  });

  const visEdges = edgesRaw.map((e) => {
    const from = e.from_id ?? e.fromId;
    const to = e.to_id ?? e.toId;
    const outs = outCount[from] || 1;
    const idx = outIdx[from] || 0;
    outIdx[from] = idx + 1;
    const insns = blockInsns.get(from) || [];
    const lastMn = insns.length ? insns[insns.length - 1].mnemonic : '';
    const style = buildArmCfgEdgeStyle(
      from, to, idx, outs, levelMap,
      blockKinds.get(from), theme, lastMn
    );
    return {
      id: `e${from}-${to}-${idx}`,
      from,
      to,
      arrows: { to: false },
      color: { color: 'rgba(0,0,0,0)', highlight: 'rgba(0,0,0,0)', hover: 'rgba(0,0,0,0)', opacity: 0 },
      width: 0,
      hoverWidth: 0,
      selectionWidth: 0,
      label: undefined,
      smooth: false,
      chosen: false,
      _ortho: style,
      _edgeIdx: idx,
      _outCount: outs,
    };
  });

  cfgOrthoEdgeState = {
    bg: theme.bg,
    mono: theme.mono,
    sizes: blockSizes,
    edges: visEdges.map((ve) => {
      const style = ve._ortho || {};
      const lane = ve._edgeIdx || 0;
      const sideSign = ((ve.from + lane) % 2) === 0 ? 1 : -1;
      return {
        id: ve.id,
        from: ve.from,
        to: ve.to,
        color: style.color,
        highlight: style.highlight || theme.text,
        width: style.width || 2,
        opacity: style.opacity == null ? 1 : style.opacity,
        dashes: !!style.dashes,
        label: style.label || '',
        edgeKind: style.edgeKind || 'flow',
        lane,
        sideSign: style.edgeKind === 'back' ? sideSign : 1,
      };
    }),
  };

  const container = $('native-cfg-graph');
  if (!container) return;
  const nodes = new vis.DataSet(visNodes);
  const edges = new vis.DataSet(visEdges);
  cfgNetwork = new vis.Network(
    container,
    { nodes, edges },
    {
      autoResize: true,
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          levelSeparation: levelSep,
          nodeSpacing: nodeSpace,
          treeSpacing: treeSpace,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true,
        },
      },
      physics: {
        enabled: true,
        hierarchicalRepulsion: {
          nodeDistance: nodeDist,
          centralGravity: 0.03,
          springLength: nodeDist,
          springConstant: 0.01,
          damping: 0.3,
          avoidOverlap: 1,
        },
        stabilization: {
          enabled: true,
          iterations: nativeCfgCompact ? 160 : 220,
          fit: false,
        },
      },
      interaction: {
        hover: true,
        navigationButtons: false,
        keyboard: false,
        tooltipDelay: 80,
        selectConnectedEdges: true,
        zoomView: true,
        dragView: true,
        dragNodes: false,
      },
      nodes: {
        borderWidth: 0,
        shapeProperties: { borderRadius: 0 },
        shadow: false,
      },
      edges: {
        width: 0,
        selectionWidth: 0,
        hoverWidth: 0,
        smooth: false,
        color: { opacity: 0 },
      },
    }
  );

  cfgNetworkDrawHandler = (ctx) => {
    try {
      for (const n of visNodes) {
        const bb = cfgNetwork.getBoundingBox(n.id);
        if (bb && cfgOrthoEdgeState) {
          cfgOrthoEdgeState.sizes[n.id] = {
            width: Math.max(40, bb.right - bb.left),
            height: Math.max(24, bb.bottom - bb.top),
          };
        }
      }
    } catch (_) {}
    drawCfgOrthogonalEdges(ctx);
    syncNativeCfgHtmlOverlay();
  };
  cfgNetwork.on('afterDrawing', cfgNetworkDrawHandler);
  cfgNetwork.on('zoom', () => syncNativeCfgHtmlOverlay());
  cfgNetwork.on('dragging', () => syncNativeCfgHtmlOverlay());
  cfgNetwork.on('dragEnd', () => syncNativeCfgHtmlOverlay());
  cfgNetwork.on('click', (params) => {
    if (params.nodes?.length) {
      focusNativeCfgNode(params.nodes[0]);
      return;
    }
    setNativeCfgBlockSelected(null);
  });

  const finishNativeCfgLayout = () => {
    if (!cfgNetwork || finishNativeCfgLayout.done) return;
    finishNativeCfgLayout.done = true;
    try { cfgNetwork.setOptions({ physics: false }); } catch (_) {}
    // Pixel-snap centers for crisp orthogonal edges.
    try {
      const pos = cfgNetwork.getPositions();
      for (const [id, p] of Object.entries(pos)) {
        cfgNetwork.moveNode(id, Math.round(p.x), Math.round(p.y));
      }
    } catch (_) {}
    resolveNativeCfgOverlaps(blockSizes);
    const hadManual = nativeCfgBlockPositions.size > 0;
    applyNativeCfgBlockPositions();
    syncNativeCfgHtmlOverlay();
    requestAnimationFrame(() => {
      if (!hadManual) {
        try { cfgNetwork?.fit({ animation: false }); } catch (_) {}
      }
      syncNativeCfgHtmlOverlay();
    });
  };
  finishNativeCfgLayout.done = false;

  cfgNetwork.once('stabilizationIterationsDone', finishNativeCfgLayout);
  // Fallback if stabilization never fires (tiny graphs / already settled).
  setTimeout(finishNativeCfgLayout, 1800);
}

function fillFuncSelect(filter = '') {
  const sel = $('native-func-select');
  if (!sel) return;
  const q = String(filter || '').trim().toLowerCase();
  const funcs = Array.isArray(browseInfo?.functions) ? browseInfo.functions : [];
  const prev = selectedFuncIdx;
  sel.innerHTML = '';
  let firstVisible = -1;
  funcs.forEach((f, idx) => {
    const name = f.name || `func_${idx}`;
    const rel = formatFuncRel(f.vaddr);
    const abs = formatVaddr(f.vaddr);
    const label = `${name}  ${rel}  (${abs})`;
    if (q && !label.toLowerCase().includes(q) && !name.toLowerCase().includes(q)) return;
    if (firstVisible < 0) firstVisible = idx;
    const opt = document.createElement('option');
    opt.value = String(idx);
    opt.textContent = label;
    sel.appendChild(opt);
  });
  if (!sel.options.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = q ? 'No matches' : 'No functions';
    sel.appendChild(opt);
    return;
  }
  const want = String(prev >= 0 ? prev : firstVisible);
  if ([...sel.options].some((o) => o.value === want)) sel.value = want;
  else sel.value = String(firstVisible);
}

function fillLibSelect(paths, selected) {
  const sel = $('native-lib-select');
  if (!sel) return;
  apkLibPaths = Array.isArray(paths) ? paths.slice() : [];
  sel.innerHTML = '';
  if (!apkLibPaths.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'No ARM64 .so in APK';
    sel.appendChild(opt);
    return;
  }
  for (const p of apkLibPaths) {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p;
    sel.appendChild(opt);
  }
  if (selected && apkLibPaths.includes(selected)) sel.value = selected;
  else if (currentPath && apkLibPaths.includes(currentPath)) sel.value = currentPath;
}

async function loadFunction(idx) {
  if (!api || !currentBytes?.length || idx < 0) return;
  selectedFuncIdx = idx;
  setMeta('Disassembling…');
  try {
    const copy = currentBytes.slice();
    const options = nativeDecompileOptionsPayload();
    const raw = await api.runInParseWorker(
      'get_elf_function',
      {
        bytes: copy.buffer,
        funcIdx: idx >>> 0,
        options,
      },
      {
        timeoutMs: api.timeoutMs || 120000,
        transfer: [copy.buffer],
      }
    );
    await applyLoadedNativeFunction(raw, idx);
  } catch (e) {
    showNativeLoadError(e);
  }
}

/** Load a local helper at vaddr (sub_* not present in FUNC symbol list). */
async function loadFunctionAtVaddr(vaddr) {
  if (!api || !currentBytes?.length || !Number.isFinite(vaddr)) return;
  const addr = Number(vaddr) >>> 0;
  // Prefer an existing FUNC entry when present.
  const idx = (browseInfo?.functions || []).findIndex((f) => Number(f.vaddr) === addr);
  if (idx >= 0) {
    const sel = $('native-func-select');
    if (sel) {
      fillFuncSelect($('native-func-search')?.value || '');
      if (![...sel.options].some((o) => o.value === String(idx))) {
        const search = $('native-func-search');
        if (search) search.value = '';
        fillFuncSelect('');
      }
      sel.value = String(idx);
    }
    await loadFunction(idx);
    return;
  }
  selectedFuncIdx = -1;
  setMeta(`Disassembling sub_${addr.toString(16)}…`);
  try {
    const copy = currentBytes.slice();
    const options = nativeDecompileOptionsPayload();
    const raw = await api.runInParseWorker(
      'get_elf_function_at',
      {
        bytes: copy.buffer,
        vaddr: addr,
        options,
      },
      {
        timeoutMs: api.timeoutMs || 120000,
        transfer: [copy.buffer],
      }
    );
    await applyLoadedNativeFunction(raw, -1);
  } catch (e) {
    showNativeLoadError(e);
  }
}

async function applyLoadedNativeFunction(raw, funcIdx) {
  let result = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (typeof api.normalizeWasmResult === 'function') {
    result = api.normalizeWasmResult(result) || result;
    if (result?.data) result.data = api.normalizeWasmResult(result.data) || result.data;
  }
  if (!result?.ok || !result.data) {
    throw new Error(result?.error || 'get_elf_function failed');
  }
  currentFn = result.data;
  nativeCfgBlockPositions.clear();
  endNativeCfgBlockDragSession();
  // Keep synthetic locals discoverable in the dropdown for this session.
  if (
    funcIdx < 0 &&
    currentFn?.vaddr != null &&
    browseInfo &&
    Array.isArray(browseInfo.functions) &&
    !browseInfo.functions.some((f) => Number(f.vaddr) === Number(currentFn.vaddr))
  ) {
    browseInfo.functions.push({
      name: currentFn.name || `sub_${Number(currentFn.vaddr).toString(16)}`,
      vaddr: Number(currentFn.vaddr),
      size: Number(currentFn.size || 0),
    });
    browseInfo.functions.sort((a, b) => Number(a.vaddr) - Number(b.vaddr));
    const newIdx = browseInfo.functions.findIndex((f) => Number(f.vaddr) === Number(currentFn.vaddr));
    selectedFuncIdx = newIdx;
    fillFuncSelect($('native-func-search')?.value || '');
    const sel = $('native-func-select');
    if (sel && newIdx >= 0) sel.value = String(newIdx);
  }
  renderAsmListing(currentFn);
  renderCfg(currentFn);
  renderSource(currentFn);
  setMeta(
    `${currentFn.name || 'fn'} · ${formatFuncRel(currentFn.vaddr)} (${formatVaddr(currentFn.vaddr)}) · ${
      (currentFn.bytecode || []).length
    } insn`
  );
  if (typeof api.onFunctionSelected === 'function') {
    api.onFunctionSelected({
      path: currentPath,
      name: currentFn.name,
      funcIdx: selectedFuncIdx,
      browse: browseInfo,
    });
  }
}

function showNativeLoadError(e) {
  console.error('[native-ui]', e);
  currentFn = null;
  destroyCfg();
  showCfgEmpty(true);
  const listing = $('native-asm-listing');
  if (listing) listing.innerHTML = `<div class="muted">${escapeHtml(e.message || String(e))}</div>`;
  const src = $('native-source-code');
  if (src) src.innerHTML = '';
  setMeta(e.message || String(e));
}

/**
 * Load ELF browse info + optionally select first function.
 * @param {string} path
 * @param {Uint8Array} bytes
 * @param {object} [browse] pre-parsed ElfBrowseInfo
 */
export async function loadElf(path, bytes, browse) {
  currentPath = path || '';
  currentBytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  currentFn = null;
  selectedFuncIdx = -1;
  destroyCfg();

  const libSel = $('native-lib-select');
  if (libSel && currentPath) {
    if (![...libSel.options].some((o) => o.value === currentPath)) {
      const opt = document.createElement('option');
      opt.value = currentPath;
      opt.textContent = currentPath;
      libSel.appendChild(opt);
    }
    libSel.value = currentPath;
  }

  try {
    if (browse && Array.isArray(browse.functions)) {
      browseInfo = browse;
    } else {
      setMeta('Parsing ELF…');
      const copy = currentBytes.slice();
      const raw = await api.runInParseWorker(
        'parse_elf',
        { bytes: copy.buffer },
        { timeoutMs: api.timeoutMs || 120000, transfer: [copy.buffer] }
      );
      const result = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (result && result.ok === false) {
        throw new Error(result.error || 'parse_elf failed');
      }
      if (result?.ok && result.data) {
        browseInfo = result.data;
      } else if (Array.isArray(result?.functions)) {
        browseInfo = result;
      } else {
        throw new Error(result?.error || 'parse_elf failed');
      }
    }

    const n = browseInfo.functions?.length || 0;
    fillFuncSelect($('native-func-search')?.value || '');
    setMeta(`${currentPath || 'ELF'} · ${n} functions · ${browseInfo.arch || 'aarch64'}`);
    api.switchToCenterTab?.('native-tab');

    if (n > 0) {
      const pending = api?._pendingSymbol;
      if (pending && pending.libPath === currentPath) {
        api._pendingSymbol = null;
        const ok = await selectNativeSymbol(pending.symbol, pending.funcIdx);
        if (ok) return;
      }
      const idx = Number($('native-func-select')?.value ?? 0);
      await loadFunction(Number.isFinite(idx) ? idx : 0);
    } else {
      const listing = $('native-asm-listing');
      if (listing) {
        listing.innerHTML =
          '<div class="code-empty"><div class="code-empty-title">No functions</div><div class="code-empty-hint muted">Stripped binary or no FUNC symbols</div></div>';
      }
      renderSource(null);
      showCfgEmpty(true);
    }
  } catch (e) {
    console.error('[native-ui] loadElf', e);
    browseInfo = null;
    setMeta(e.message || String(e));
    const listing = $('native-asm-listing');
    if (listing) listing.innerHTML = `<div class="muted">${escapeHtml(e.message || String(e))}</div>`;
    api.switchToCenterTab?.('native-tab');
  }
}

export function listApkNativeLibs(files) {
  const names = (Array.isArray(files) ? files : [])
    .map((f) => (typeof f === 'string' ? f : f?.name))
    .filter((n) => typeof n === 'string' && /\.so$/i.test(n));
  const underLib = names.filter((n) => /^lib\//i.test(n));
  const pool = underLib.length ? underLib : names;
  const arm64 = pool.filter((n) => /\/arm64-v8a\//i.test(n) || /^lib\/arm64-v8a\//i.test(n));
  const prefer = arm64.length ? arm64 : pool;
  prefer.sort((a, b) => {
    const aArm = /arm64-v8a/i.test(a) ? 0 : 1;
    const bArm = /arm64-v8a/i.test(b) ? 0 : 1;
    if (aArm !== bArm) return aArm - bArm;
    return a.localeCompare(b);
  });
  return prefer;
}

export function renderNativeLibTree(files, onOpen, getLibBadge) {
  const tree = $('tree-content');
  const placeholder = $('tree-placeholder');
  if (!tree) return;
  const libs = listApkNativeLibs(files);
  fillLibSelect(libs, currentPath);
  if (placeholder) placeholder.style.display = 'none';
  tree.style.display = 'block';
  if (!libs.length) {
    tree.innerHTML =
      '<div class="muted" style="padding:0.5rem">No shared libraries (<code>.so</code>) in this APK.</div>';
    return;
  }
  // Group by ABI folder when present
  const byAbi = new Map();
  for (const name of libs) {
    const abi = (name.match(/(?:^|\/)lib\/([^/]+)\//i) || [])[1] || 'other';
    if (!byAbi.has(abi)) byAbi.set(abi, []);
    byAbi.get(abi).push(name);
  }
  let html = '<ul class="tree-list native-lib-tree">';
  for (const [abi, group] of byAbi) {
    html += `<li class="native-abi-group"><div class="tree-item apk-folder native-abi-head" data-abi="${escapeHtml(abi)}"><span class="arrow expanded">▼</span> ${escapeHtml(abi)} <span class="muted">(${group.length})</span></div><ul class="tree-list">`;
    for (const name of group) {
      const short = name.split('/').pop();
      const sel = name === currentPath ? ' selected' : '';
      const badge =
        typeof getLibBadge === 'function' ? getLibBadge(name) : '';
      html +=
        `<li><div class="tree-item apk-file native-lib${sel}" data-name="${escapeHtml(name)}" title="${escapeHtml(name)}">` +
        `<span class="tree-label">${escapeHtml(short)}</span>` +
        (badge ? ` <span class="jni-badge">${escapeHtml(badge)}</span>` : '') +
        `</div></li>`;
    }
    html += '</ul></li>';
  }
  html += '</ul>';
  tree.innerHTML = html;
  tree.querySelectorAll('.native-abi-head').forEach((el) => {
    el.addEventListener('click', () => {
      const ul = el.nextElementSibling;
      if (!ul || ul.tagName !== 'UL') return;
      const arrow = el.querySelector('.arrow');
      const collapsed = ul.style.display === 'none';
      ul.style.display = collapsed ? '' : 'none';
      arrow?.classList.toggle('collapsed', !collapsed);
      arrow?.classList.toggle('expanded', collapsed);
      if (arrow) arrow.textContent = collapsed ? '▼' : '▶';
    });
  });
  tree.querySelectorAll('.native-lib').forEach((el) => {
    el.addEventListener('click', () => {
      tree.querySelectorAll('.tree-item.selected').forEach((e) => e.classList.remove('selected'));
      el.classList.add('selected');
      const name = el.getAttribute('data-name');
      if (name && typeof onOpen === 'function') onOpen(name);
    });
  });
}

export function clearNativeView() {
  currentBytes = null;
  currentPath = '';
  browseInfo = null;
  currentFn = null;
  selectedFuncIdx = -1;
  destroyCfg();
  showCfgEmpty(true);
  setMeta('');
  if ($('native-asm-listing')) {
    $('native-asm-listing').innerHTML =
      '<div class="code-empty"><div class="code-empty-title">No assembly</div><div class="code-empty-hint muted">Open an ARM64 <code>.so</code></div></div>';
  }
  if ($('native-source-code')) {
    $('native-source-code').innerHTML =
      '<div class="code-empty"><div class="code-empty-title">No source yet</div></div>';
  }
}

/**
 * @param {{
 *   runInParseWorker: Function,
 *   switchToCenterTab: Function,
 *   timeoutMs?: number,
 *   onSelectLib?: (path: string) => void,
 * }} opts
 */
export function initNativeUi(opts) {
  api = opts || {};
  loadArmDecompileOptionsFromStorage();
  syncArmDecompileOptionsUi();
  loadNativeCfgCompactPref();
  wireNativeSourceIdentHighlight();

  $('native-func-select')?.addEventListener('change', () => {
    const idx = Number($('native-func-select').value);
    if (Number.isFinite(idx) && idx >= 0) loadFunction(idx);
  });
  $('native-func-search')?.addEventListener('input', () => {
    fillFuncSelect($('native-func-search').value);
  });
  $('native-decompile-mode')?.addEventListener('change', () => {
    reloadCurrentNativeDecompilation();
  });
  $('native-decompile-engine')?.addEventListener('change', (e) => {
    setArmDecompileEngine(e.target?.value);
  });
  $('settings-arm-engine')?.addEventListener('change', (e) => {
    setArmDecompileEngine(e.target?.value);
  });
  $('native-cfg-compact')?.addEventListener('change', (e) => {
    nativeCfgCompact = !!e.target?.checked;
    saveNativeCfgCompactPref();
    if (currentFn) renderCfg(currentFn);
  });
  $('native-hex-toggle')?.addEventListener('change', () => {
    if (currentFn) renderAsmListing(currentFn);
  });
  $('native-cfg-fit-btn')?.addEventListener('click', () => {
    try {
      cfgNetwork?.fit({ animation: true });
      syncNativeCfgHtmlOverlay();
    } catch (_) {}
  });
  $('native-cfg-reset-layout-btn')?.addEventListener('click', () => {
    resetNativeCfgLayout();
  });
  $('native-source-copy-btn')?.addEventListener('click', async () => {
    const text = currentFn?.decompilation || '';
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {}
  });
  $('native-lib-select')?.addEventListener('change', () => {
    const path = $('native-lib-select').value;
    if (path && typeof api.onSelectLib === 'function') api.onSelectLib(path);
  });

  const onNativeFnLinkClick = (e) => {
    const a = e.target.closest?.('.native-fn-link');
    if (!a) return;
    e.preventDefault();
    e.stopPropagation();
    const idxRaw = a.getAttribute('data-func-idx');
    const idx = idxRaw === '' || idxRaw == null ? NaN : Number(idxRaw);
    const vaddrRaw = a.getAttribute('data-vaddr');
    const vaddr = vaddrRaw === '' || vaddrRaw == null ? NaN : Number(vaddrRaw);
    if (Number.isFinite(idx) && idx >= 0) {
      const sel = $('native-func-select');
      if (sel) {
        fillFuncSelect($('native-func-search')?.value || '');
        if (![...sel.options].some((o) => o.value === String(idx))) {
          const search = $('native-func-search');
          if (search) search.value = '';
          fillFuncSelect('');
        }
        sel.value = String(idx);
      }
      loadFunction(idx);
      return;
    }
    if (Number.isFinite(vaddr)) {
      loadFunctionAtVaddr(vaddr);
    }
  };
  // Bind on stable parents — listing/source innerHTML is replaced often.
  $('native-asm-pane')?.addEventListener('click', onNativeFnLinkClick);
  $('native-source-pane')?.addEventListener('click', onNativeFnLinkClick);
  $('native-asm-listing')?.addEventListener('click', onNativeFnLinkClick);
  $('native-source-code')?.addEventListener('click', onNativeFnLinkClick);

  for (const [btnId, paneId] of [
    ['native-asm-collapse-btn', 'native-asm-pane'],
    ['native-cfg-collapse-btn', 'native-cfg-pane'],
    ['native-source-collapse-btn', 'native-source-pane'],
  ]) {
    $(btnId)?.addEventListener('click', () => {
      const pane = $(paneId);
      if (!pane) return;
      setDockCollapsed(pane, pane.dataset.collapsed !== 'true');
    });
  }
}

export function getCurrentNativePath() {
  return currentPath;
}

export function getArmDecompileEngineOption() {
  return getArmDecompileEngine();
}

export function applyArmDecompileOptionsFromStorage() {
  loadArmDecompileOptionsFromStorage();
  syncArmDecompileOptionsUi();
}

export function getCurrentNativeBrowse() {
  return browseInfo;
}

/**
 * Open a library and select a function by symbol name (or funcIdx).
 * @param {string} libPath
 * @param {{ symbol?: string, funcIdx?: number, bytes?: Uint8Array, browse?: object }} opts
 */
export async function navigateToNativeSymbol(libPath, opts = {}) {
  if (!libPath) return false;
  if (typeof api?.onSelectLib === 'function' && (!opts.bytes || currentPath !== libPath)) {
    // Parent opens via showApkFile → loadElf; then we select.
    api._pendingSymbol = { libPath, symbol: opts.symbol, funcIdx: opts.funcIdx };
    api.onSelectLib(libPath);
    return true;
  }
  if (opts.bytes) {
    await loadElf(libPath, opts.bytes, opts.browse);
  }
  return selectNativeSymbol(opts.symbol, opts.funcIdx);
}

export async function selectNativeSymbol(symbol, funcIdx) {
  if (!browseInfo?.functions?.length) return false;
  let idx = Number.isFinite(funcIdx) && funcIdx >= 0 ? funcIdx : -1;
  if (idx < 0 && symbol) {
    idx = browseInfo.functions.findIndex((f) => f.name === symbol);
    if (idx < 0) {
      idx = browseInfo.functions.findIndex(
        (f) => f.name === symbol || String(f.name || '').startsWith(String(symbol) + '__')
      );
    }
  }
  if (idx < 0) return false;
  const sel = $('native-func-select');
  if (sel) {
    fillFuncSelect($('native-func-search')?.value || '');
    if (![...sel.options].some((o) => o.value === String(idx))) {
      // Clear filter so the option appears
      const search = $('native-func-search');
      if (search) search.value = '';
      fillFuncSelect('');
    }
    sel.value = String(idx);
  }
  await loadFunction(idx);
  api.switchToCenterTab?.('native-tab');
  return true;
}

/** Consume pending symbol selection after loadElf. */
export async function consumePendingNativeSymbol() {
  const pending = api?._pendingSymbol;
  if (!pending || pending.libPath !== currentPath) return false;
  api._pendingSymbol = null;
  return selectNativeSymbol(pending.symbol, pending.funcIdx);
}

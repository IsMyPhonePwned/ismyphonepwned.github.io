/**
 * Native tab — ARM64 ELF (.so) assembly / CFG / decompilation.
 */

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
    'class="native-fn-link bc-addr-link"',
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
  '_Bool', '_Complex', '_Imaginary', 'true', 'false', 'NULL',
]);

const C_TYPES = new Set([
  'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t',
  'int64_t', 'size_t', 'ssize_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t', 'bool',
  'u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'usize',
]);

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

/** Lightweight C-like highlighter for arm_decompiler output. */
function highlightCLike(source) {
  if (!source || typeof source !== 'string') return '';
  let html = '';
  let i = 0;
  const n = source.length;
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
      html += `<span class="src-label">${escapeHtml(m[1])}</span>:`;
      i += m[0].length;
      continue;
    }
    if (/[0-9]/.test(source[i]) || (source[i] === '0' && (source[i + 1] === 'x' || source[i + 1] === 'X'))) {
      const m = source.slice(i).match(/^(0[xX][0-9a-fA-F]+|\d+\.\d*([eE][+-]?\d+)?|\d+)/);
      if (m) {
        html += `<span class="src-number">${escapeHtml(m[0])}</span>`;
        i += m[0].length;
        continue;
      }
    }
    if (/[A-Za-z_]/.test(source[i])) {
      const m = source.slice(i).match(/^[A-Za-z_][\w]*/);
      const id = m[0];
      if (C_KEYWORDS.has(id)) {
        html += `<span class="src-keyword">${escapeHtml(id)}</span>`;
      } else if (C_TYPES.has(id)) {
        html += `<span class="src-type">${escapeHtml(id)}</span>`;
      } else {
        // Heuristic: call if followed by (
        let k = i + id.length;
        while (k < n && /\s/.test(source[k])) k++;
        const isCall = source[k] === '(';
        const isSub = /^sub_/i.test(id);
        if ((isCall || isSub || id.startsWith('Java_')) && (isSub || resolveNativeCalleeIndex(id) >= 0 || resolveNativeCalleeVaddr(id) != null)) {
          const linked = nativeCalleeLinkHtml(id, id);
          html += linked.includes('<a ')
            ? linked.replace('class="native-fn-link bc-addr-link"', 'class="native-fn-link src-call"')
            : (isCall ? `<span class="src-call">${escapeHtml(id)}</span>` : `<span class="src-ident">${escapeHtml(id)}</span>`);
        } else if (isCall) {
          html += `<span class="src-call">${escapeHtml(id)}</span>`;
        } else {
          html += `<span class="src-ident">${escapeHtml(id)}</span>`;
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
/** @type {string[]} */
let apkLibPaths = [];

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

function destroyCfg() {
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
  const g = $('native-cfg-graph');
  if (g) g.innerHTML = '';
}

function showCfgEmpty(show) {
  const empty = $('native-cfg-empty');
  const graph = $('native-cfg-graph');
  if (empty) empty.hidden = !show;
  if (graph) graph.style.display = show ? 'none' : '';
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
  if (meta) meta.textContent = src ? `${src.split('\n').length} lines` : '';
  if (copyBtn) copyBtn.disabled = !src;
  if (!pre) return;
  if (!src) {
    pre.classList.remove('src-has-highlight');
    pre.innerHTML =
      '<div class="code-empty"><div class="code-empty-title">No source</div><div class="code-empty-hint muted">Decompilation unavailable</div></div>';
    return;
  }
  pre.classList.add('src-has-highlight');
  pre.innerHTML = highlightCLike(src);
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
    meta.textContent = `${nodesRaw.length} blocks · ${edgesRaw.length} edges`;
  }

  const theme = cfgThemeColors();
  const levelMap = computeCfgLevels(nodesRaw, edgesRaw, 0);
  const loopHeaders = computeLoopHeaders(edgesRaw, levelMap);
  const outCount = {};
  for (const e of edgesRaw) {
    const from = e.from_id ?? e.fromId;
    outCount[from] = (outCount[from] || 0) + 1;
  }
  const outIdx = {};
  const blockKinds = new Map();
  const blockInsns = new Map();
  const blockSizes = {};

  const visNodes = nodesRaw.map((n) => {
    const start = n.start_offset ?? n.startOffset ?? 0;
    const end = n.end_offset ?? n.endOffset ?? start;
    const endBound = end === 0 && start !== 0 ? Infinity : end || Infinity;
    const insns = bytecode.filter((r) => r.offset >= start && r.offset < endBound);
    const kind = classifyArmCfgBlock(n.id, insns, loopHeaders);
    blockKinds.set(n.id, kind);
    blockInsns.set(n.id, insns);
    const kindTag = kind !== 'normal' && kind !== 'empty' ? ` · ${kind}` : '';
    const lines = insns.slice(0, 10).map((r) => {
      const op = (r.operands || '').trim();
      return `${formatOff(r.offset)}  ${r.mnemonic || ''}${op ? '  ' + op : ''}`;
    });
    if (insns.length > 10) lines.push(`… +${insns.length - 10} more`);
    const label = `${n.label || formatOff(start)}${kindTag}\n` + (lines.join('\n') || '(empty)');
    const size = estimateCfgNodeSize(label);
    blockSizes[n.id] = size;
    const colors = blockKindColors(kind, theme);
    return {
      id: n.id,
      label,
      shape: 'box',
      level: levelMap[n.id],
      font: {
        multi: true,
        face: 'monospace',
        size: 11,
        align: 'left',
        color: theme.text,
      },
      margin: 10,
      borderWidth: 2,
      color: colors,
      shapeProperties: { borderRadius: 4 },
      widthConstraint: { minimum: size.width, maximum: size.width },
      heightConstraint: { minimum: size.height, maximum: size.height },
    };
  });

  const visEdges = edgesRaw.map((e, i) => {
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
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          levelSeparation: 130,
          nodeSpacing: 180,
          treeSpacing: 220,
        },
      },
      physics: false,
      interaction: {
        hover: true,
        navigationButtons: false,
        keyboard: false,
        tooltipDelay: 80,
        selectConnectedEdges: true,
      },
      nodes: { shadow: false },
      edges: {
        width: 0,
        selectionWidth: 0,
        hoverWidth: 0,
        smooth: false,
      },
    }
  );

  cfgNetworkDrawHandler = (ctx) => {
    // Refresh sizes from vis bounding boxes when available.
    try {
      for (const n of visNodes) {
        const bb = cfgNetwork.getBoundingBox(n.id);
        if (bb) {
          blockSizes[n.id] = {
            width: Math.max(40, bb.right - bb.left),
            height: Math.max(24, bb.bottom - bb.top),
          };
        }
      }
      if (cfgOrthoEdgeState) cfgOrthoEdgeState.sizes = blockSizes;
    } catch (_) {}
    drawCfgOrthogonalEdges(ctx);
  };
  cfgNetwork.on('afterDrawing', cfgNetworkDrawHandler);
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
    const mode = $('native-decompile-mode')?.value || 'restructure';
    const raw = await api.runInParseWorker(
      'get_elf_function',
      {
        bytes: copy.buffer,
        funcIdx: idx >>> 0,
        options: { mode },
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
    const mode = $('native-decompile-mode')?.value || 'restructure';
    const raw = await api.runInParseWorker(
      'get_elf_function_at',
      {
        bytes: copy.buffer,
        vaddr: addr,
        options: { mode },
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

  $('native-func-select')?.addEventListener('change', () => {
    const idx = Number($('native-func-select').value);
    if (Number.isFinite(idx) && idx >= 0) loadFunction(idx);
  });
  $('native-func-search')?.addEventListener('input', () => {
    fillFuncSelect($('native-func-search').value);
  });
  $('native-decompile-mode')?.addEventListener('change', () => {
    if (selectedFuncIdx >= 0) loadFunction(selectedFuncIdx);
  });
  $('native-hex-toggle')?.addEventListener('change', () => {
    if (currentFn) renderAsmListing(currentFn);
  });
  $('native-cfg-fit-btn')?.addEventListener('click', () => {
    try {
      cfgNetwork?.fit({ animation: true });
    } catch (_) {}
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

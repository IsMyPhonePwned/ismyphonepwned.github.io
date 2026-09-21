/**
 * GIF89a encoder for mirror frames.
 * Indexed to a fixed 6×6×6 palette with Floyd–Steinberg dithering.
 */

const LEVELS = [0, 51, 102, 153, 204, 255];

export function palette216() {
  const pal = new Uint8Array(256 * 3);
  let i = 0;
  for (let r = 0; r < 6; r++) {
    for (let g = 0; g < 6; g++) {
      for (let b = 0; b < 6; b++) {
        pal[i++] = LEVELS[r];
        pal[i++] = LEVELS[g];
        pal[i++] = LEVELS[b];
      }
    }
  }
  return pal;
}

function clampByte(v) {
  if (v < 0) return 0;
  if (v > 255) return 255;
  return v;
}

function nearest(v) {
  const q = Math.round(clampByte(v) / 51);
  return q < 0 ? 0 : q > 5 ? 5 : q;
}

/** @param {Uint8ClampedArray | Uint8Array} rgba */
export function quantize(rgba, width, height) {
  const src = new Float32Array(rgba.length);
  for (let i = 0; i < rgba.length; i++) src[i] = rgba[i];
  const idx = new Uint8Array(width * height);
  const w = width;
  const h = height;
  function add(x, y, er, eg, eb, f) {
    if (x < 0 || y < 0 || x >= w || y >= h) return;
    const i = (y * w + x) * 4;
    src[i] += er * f;
    src[i + 1] += eg * f;
    src[i + 2] += eb * f;
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      const r = clampByte(src[i]);
      const g = clampByte(src[i + 1]);
      const b = clampByte(src[i + 2]);
      const ir = nearest(r);
      const ig = nearest(g);
      const ib = nearest(b);
      idx[y * w + x] = ir * 36 + ig * 6 + ib;
      const er = r - LEVELS[ir];
      const eg = g - LEVELS[ig];
      const eb = b - LEVELS[ib];
      add(x + 1, y, er, eg, eb, 7 / 16);
      add(x - 1, y + 1, er, eg, eb, 3 / 16);
      add(x, y + 1, er, eg, eb, 5 / 16);
      add(x + 1, y + 1, er, eg, eb, 1 / 16);
    }
  }
  return idx;
}

/**
 * @param {{ indices: Uint8Array, delayCs: number }[]} frames
 * @param {Uint8Array} [palette]
 */
export function encodeGif(frames, width, height, palette = palette216()) {
  const bytes = [];
  const push = (...ns) => {
    for (const n of ns) bytes.push(n & 255);
  };
  const le16 = (n) => push(n, n >> 8);
  bytes.push(0x47, 0x49, 0x46, 0x38, 0x39, 0x61);
  le16(width);
  le16(height);
  push(0xf7, 0x00, 0x00);
  for (let i = 0; i < 768; i++) bytes.push(palette[i] || 0);
  // Loop forever.
  push(0x21, 0xff, 0x0b);
  for (const c of 'NETSCAPE2.0') bytes.push(c.charCodeAt(0));
  push(0x03, 0x01, 0x00, 0x00, 0x00);
  for (const frame of frames) {
    const delay = frame.delayCs || 10;
    push(0x21, 0xf9, 0x04, 0x00, delay, delay >> 8, 0x00, 0x00);
    push(0x2c);
    le16(0);
    le16(0);
    le16(width);
    le16(height);
    push(0x00);
    const packed = lzw(frame.indices, 8);
    push(8);
    for (let i = 0; i < packed.length; i += 255) {
      const n = Math.min(255, packed.length - i);
      push(n);
      for (let j = 0; j < n; j++) bytes.push(packed[i + j]);
    }
    push(0);
  }
  push(0x3b);
  return new Uint8Array(bytes);
}

function lzw(indices, minCodeSize) {
  const clear = 1 << minCodeSize;
  const eoi = clear + 1;
  let codeSize = minCodeSize + 1;
  let nextCode = eoi + 1;
  /** @type {Map<string, number>} */
  let table = new Map();
  const out = [];
  let acc = 0;
  let bits = 0;
  function write(code) {
    acc |= code << bits;
    bits += codeSize;
    while (bits >= 8) {
      out.push(acc & 255);
      acc >>>= 8;
      bits -= 8;
    }
  }
  function reset() {
    table = new Map();
    codeSize = minCodeSize + 1;
    nextCode = eoi + 1;
  }
  write(clear);
  if (!indices.length) {
    write(eoi);
    if (bits) out.push(acc & 255);
    return out;
  }
  let prefix = indices[0];
  for (let i = 1; i < indices.length; i++) {
    const k = indices[i];
    const key = `${prefix},${k}`;
    const found = table.get(key);
    if (found !== undefined) {
      prefix = found;
      continue;
    }
    write(prefix);
    table.set(key, nextCode);
    nextCode += 1;
    if (nextCode === 4096) {
      write(clear);
      reset();
    } else if (nextCode > 1 << codeSize) {
      codeSize += 1;
    }
    prefix = k;
  }
  write(prefix);
  write(eoi);
  if (bits) out.push(acc & 255);
  return out;
}

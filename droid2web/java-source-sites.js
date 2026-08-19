/**
 * Locate Java call / field sites in a decompiled source line.
 * String and comment spans are masked so `"android.permission.FOO"` is not a field access.
 */

const SOURCE_CALL_SKIP = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'throw',
  'assert', 'new', 'typeof', 'instanceof', 'case', 'else',
]);

/** Mask of positions inside `"…"` / `'…'` or comments on a single Java line. */
export function javaLineStringCommentMask(line) {
  const s = String(line || '');
  const mask = new Uint8Array(s.length);
  let inStr = null;
  let inLineComment = false;
  let inBlockComment = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    if (inLineComment) {
      mask[i] = 1;
      continue;
    }
    if (inBlockComment) {
      mask[i] = 1;
      if (c === '*' && next === '/') {
        mask[i + 1] = 1;
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inStr) {
      mask[i] = 1;
      if (c === '\\' && i + 1 < s.length) {
        mask[i + 1] = 1;
        i++;
        continue;
      }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '/' && next === '/') {
      mask[i] = 1;
      mask[i + 1] = 1;
      inLineComment = true;
      i++;
      continue;
    }
    if (c === '/' && next === '*') {
      mask[i] = 1;
      mask[i + 1] = 1;
      inBlockComment = true;
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      mask[i] = 1;
      inStr = c;
    }
  }
  return mask;
}

export function javaIndexInStringOrComment(mask, index) {
  return index >= 0 && index < mask.length && mask[index] !== 0;
}

/** Find call / `new` sites on a source line (plain text). */
export function findSourceCallSites(line) {
  const sites = [];
  const hidden = javaLineStringCommentMask(line);
  const newRe = /\bnew\s+((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\s*\(/g;
  let m;
  while ((m = newRe.exec(line))) {
    const start = m.index + m[0].indexOf(m[1]);
    if (javaIndexInStringOrComment(hidden, start)) continue;
    sites.push({
      start,
      end: m.index + m[0].length - 1,
      kind: 'new',
      receiver: m[1],
      methodName: '<init>',
      display: m[1],
    });
  }
  const callRe = /((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\.([A-Za-z_][\w]*)\s*\(/g;
  while ((m = callRe.exec(line))) {
    if (SOURCE_CALL_SKIP.has(m[2])) continue;
    if (javaIndexInStringOrComment(hidden, m.index)) continue;
    const before = line.slice(Math.max(0, m.index - 4), m.index);
    if (/\bnew\s*$/.test(before)) continue;
    sites.push({
      start: m.index,
      end: m.index + m[1].length + 1 + m[2].length,
      kind: 'call',
      receiver: m[1],
      methodName: m[2],
      display: `${m[1]}.${m[2]}`,
    });
  }
  sites.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const s of sites) {
    if (s.start < lastEnd) continue;
    out.push(s);
    lastEnd = s.end;
  }
  return out;
}

/** Field reads/writes: `obj.field` / `Type.field` not followed by `(`. */
export function findSourceFieldSites(line) {
  const sites = [];
  const hidden = javaLineStringCommentMask(line);
  const re = /((?:[A-Za-z_][\w]*\.)*[A-Za-z_][\w]*)\.([A-Za-z_][\w]*)(?!\s*\()/g;
  let m;
  while ((m = re.exec(line))) {
    const receiver = m[1];
    const fieldName = m[2];
    if (SOURCE_CALL_SKIP.has(fieldName)) continue;
    if (javaIndexInStringOrComment(hidden, m.index)) continue;
    if (/^(?:import|package)\b/.test(line.trim())) continue;
    sites.push({
      start: m.index,
      end: m.index + m[0].length,
      kind: 'field',
      receiver,
      fieldName,
      display: `${receiver}.${fieldName}`,
    });
  }
  sites.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const s of sites) {
    if (s.start < lastEnd) continue;
    out.push(s);
    lastEnd = s.end;
  }
  return out;
}

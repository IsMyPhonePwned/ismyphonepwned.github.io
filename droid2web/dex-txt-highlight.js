/**
 * dex-txt syntax highlighting for the Patch editor.
 * Grammar aligned with apk-patch docs/DEX-TXT.md (mnemonic-first).
 */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ESC[c]);
}

const DIRECTIVES = new Set([
  '.class', '.super', '.source', '.implements', '.annotation', '.end',
  '.field', '.value', '.method', '.registers', '.locals', '.param',
  '.line', '.local', '.prologue', '.epilogue', '.code',
  '.array-data', '.packed-switch', '.sparse-switch',
  '.catch', '.catchall',
]);

const ACCESS = new Set([
  'public', 'private', 'protected', 'static', 'final', 'abstract', 'synthetic',
  'constructor', 'declared-synchronized', 'interface', 'enum', 'annotation',
  'synchronized', 'bridge', 'varargs', 'native', 'strictfp', 'volatile',
  'transient', 'build', 'runtime', 'system',
]);

const MNEMONICS = new Set([
  'nop', 'move', 'move/from16', 'move/16', 'move-wide', 'move-wide/from16', 'move-wide/16',
  'move-object', 'move-object/from16', 'move-object/16', 'move-result', 'move-result-wide',
  'move-result-object', 'move-exception', 'return-void', 'return', 'return-wide',
  'return-object', 'const/4', 'const/16', 'const', 'const/high16', 'const-wide/16',
  'const-wide/32', 'const-wide', 'const-wide/high16', 'const-string', 'const-string/jumbo',
  'const-class', 'monitor-enter', 'monitor-exit', 'check-cast', 'instance-of',
  'array-length', 'new-instance', 'new-array', 'filled-new-array', 'filled-new-array/range',
  'fill-array-data', 'throw', 'goto', 'goto/16', 'goto/32', 'packed-switch', 'sparse-switch',
  'cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double', 'cmp-long',
  'if-eq', 'if-ne', 'if-lt', 'if-ge', 'if-gt', 'if-le',
  'if-eqz', 'if-nez', 'if-ltz', 'if-gez', 'if-gtz', 'if-lez',
  'aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short',
  'aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short',
  'iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short',
  'iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short',
  'sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short',
  'sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short',
  'invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface',
  'invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range',
  'invoke-interface/range', 'invoke-polymorphic', 'invoke-polymorphic/range',
  'invoke-custom', 'invoke-custom/range', 'const-method-handle', 'const-method-type',
  'neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
  'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float',
  'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double',
  'double-to-int', 'double-to-long', 'double-to-float',
  'int-to-byte', 'int-to-char', 'int-to-short',
  'add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int',
  'shl-int', 'shr-int', 'ushr-int',
  'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long',
  'xor-long', 'shl-long', 'shr-long', 'ushr-long',
  'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float',
  'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double',
  'add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr',
  'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr',
  'ushr-int/2addr',
  'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr',
  'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr',
  'ushr-long/2addr',
  'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr',
  'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr',
  'add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16',
  'and-int/lit16', 'or-int/lit16', 'xor-int/lit16',
  'add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8',
  'and-int/lit8', 'or-int/lit8', 'xor-int/lit8', 'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8',
]);

function highlightTokenStream(line) {
  let out = '';
  let i = 0;
  const n = line.length;

  while (i < n) {
    const ch = line[i];

    // Hex commentary after #
    if (ch === '#') {
      out += `<span class="dxt-cm">${esc(line.slice(i))}</span>`;
      break;
    }

    // Strings
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (line[j] === '\\' && j + 1 < n) {
          j += 2;
          continue;
        }
        if (line[j] === '"') {
          j += 1;
          break;
        }
        j += 1;
      }
      out += `<span class="dxt-str">${esc(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Labels :L_…
    if (ch === ':') {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(line[j])) j += 1;
      out += `<span class="dxt-label">${esc(line.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // Directives .class / .method …
    if (ch === '.') {
      let j = i + 1;
      while (j < n && /[a-z-]/.test(line[j])) j += 1;
      const tok = line.slice(i, j);
      if (DIRECTIVES.has(tok) || tok.startsWith('.end')) {
        out += `<span class="dxt-dir">${esc(tok)}</span>`;
        i = j;
        continue;
      }
    }

    // Registers v0 / p1
    if ((ch === 'v' || ch === 'p') && i + 1 < n && /[0-9]/.test(line[i + 1])) {
      let j = i + 1;
      while (j < n && /[0-9]/.test(line[j])) j += 1;
      // avoid matching words like "void" — only if prev is start/punct
      const prev = i === 0 ? ' ' : line[i - 1];
      if (/[\s,{(\[]/.test(prev) || i === 0) {
        out += `<span class="dxt-reg">${esc(line.slice(i, j))}</span>`;
        i = j;
        continue;
      }
    }

    // Type / method / field descriptors starting with L or [
    if (ch === 'L' || ch === '[') {
      const prev = i === 0 ? ' ' : line[i - 1];
      if (/[\s,{(->]/.test(prev) || i === 0) {
        let j = i;
        // Walk descriptor + optional ->name:type / ->name(proto)ret
        while (j < n && !/[\s,#]/.test(line[j])) j += 1;
        const tok = line.slice(i, j);
        if (/^[\[*]*L[\w/$]+;/.test(tok) || /^[\[*]+[ZBSCIJFD]/.test(tok) || tok.includes(';->')) {
          out += `<span class="dxt-type">${esc(tok)}</span>`;
          i = j;
          continue;
        }
      }
    }

    // Numbers
    if (/[0-9-]/.test(ch) && (i === 0 || /[\s,={]/.test(line[i - 1]))) {
      let j = i;
      if (line[j] === '-') j += 1;
      if (j < n && /[0-9]/.test(line[j])) {
        while (j < n && /[0-9a-fxA-FX._LldDfF]/.test(line[j])) j += 1;
        out += `<span class="dxt-num">${esc(line.slice(i, j))}</span>`;
        i = j;
        continue;
      }
    }

    // Words: mnemonics, access flags, identifiers
    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_/$<>;:-]/.test(line[j])) j += 1;
      // trim trailing punctuation that shouldn't be in mnemonic
      let tok = line.slice(i, j);
      // Prefer longest mnemonic match (e.g. invoke-virtual)
      let mnemEnd = i;
      for (let k = j; k > i; k--) {
        const cand = line.slice(i, k);
        if (MNEMONICS.has(cand)) {
          mnemEnd = k;
          break;
        }
      }
      if (mnemEnd > i) {
        out += `<span class="dxt-op">${esc(line.slice(i, mnemEnd))}</span>`;
        i = mnemEnd;
        continue;
      }
      // Access flags (single word)
      const wordEnd = (() => {
        let k = i;
        while (k < n && /[A-Za-z-]/.test(line[k])) k += 1;
        return k;
      })();
      const word = line.slice(i, wordEnd);
      if (ACCESS.has(word)) {
        out += `<span class="dxt-access">${esc(word)}</span>`;
        i = wordEnd;
        continue;
      }
      // Primitive type chars alone
      if (/^[ZBSCIJFDV]$/.test(word) && (i === 0 || /[\s:(]/.test(line[i - 1] || ' '))) {
        out += `<span class="dxt-type">${esc(word)}</span>`;
        i = wordEnd;
        continue;
      }
      out += `<span class="dxt-id">${esc(tok)}</span>`;
      i = j;
      continue;
    }

    // Punctuation
    if (/[{}(),;->]/.test(ch) || ch === '/') {
      let j = i + 1;
      // group -> as one
      if (line.slice(i, i + 2) === '->') {
        out += `<span class="dxt-punct">-&gt;</span>`;
        i += 2;
        continue;
      }
      out += `<span class="dxt-punct">${esc(ch)}</span>`;
      i = j;
      continue;
    }

    out += esc(ch);
    i += 1;
  }
  return out;
}

/**
 * Highlight a full dex-txt (or generic text) document to HTML.
 * Non-dex-txt paths get light comment/string highlighting only.
 */
export function highlightDexTxt(source, { mode = 'dextxt' } = {}) {
  const text = source.endsWith('\n') ? source : `${source}\n`;
  const lines = text.split('\n');
  // drop trailing empty from forced newline for join fidelity
  if (lines.length && lines[lines.length - 1] === '') lines.pop();

  return lines
    .map((line) => {
      if (mode !== 'dextxt') {
        // Generic: comments + strings
        if (line.trimStart().startsWith('#')) {
          return `<span class="dxt-cm">${esc(line)}</span>`;
        }
        return esc(line);
      }
      const trimmed = line.trimStart();
      if (trimmed.startsWith('#')) {
        return `<span class="dxt-cm">${esc(line)}</span>`;
      }
      return highlightTokenStream(line);
    })
    .join('\n');
}

export function isDexTxtPath(path) {
  return /\.dex\.txt$/i.test(path || '') || /(^|\/)dex(_|$)/i.test(path || '');
}

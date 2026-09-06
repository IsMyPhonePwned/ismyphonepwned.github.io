/**
 * Lightweight JS highlighter for goauld Device scripts (Frida-shaped JS).
 * Prefer Prism when loaded; otherwise a small token highlighter.
 */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ESC[c]);
}

const KEYWORDS = new Set([
  'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
  'delete', 'do', 'else', 'export', 'extends', 'false', 'finally', 'for',
  'function', 'if', 'import', 'in', 'instanceof', 'let', 'new', 'null',
  'return', 'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof',
  'undefined', 'var', 'void', 'while', 'with', 'yield', 'async', 'await',
  'of', 'static', 'get', 'set',
]);

const GOAULD_API = new Set([
  'send', 'recv', 'rpc', 'exports', 'Interceptor', 'Module', 'Memory', 'Process',
  'Java', 'NativePointer', 'NativeFunction', 'NativeCallback', 'ptr', 'NULL',
  'hexdump', 'Console', 'Thread', 'File', 'Socket',
]);

function highlightFallback(source) {
  const text = String(source ?? '');
  let out = '';
  let i = 0;
  const n = text.length;

  while (i < n) {
    const ch = text[i];

    // line / block comments
    if (ch === '/' && text[i + 1] === '/') {
      let j = i;
      while (j < n && text[j] !== '\n') j++;
      out += `<span class="gjs-cm">${esc(text.slice(i, j))}</span>`;
      i = j;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      let j = i + 2;
      while (j < n && !(text[j] === '*' && text[j + 1] === '/')) j++;
      j = Math.min(n, j + 2);
      out += `<span class="gjs-cm">${esc(text.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // strings
    if (ch === '"' || ch === "'" || ch === '`') {
      const q = ch;
      let j = i + 1;
      while (j < n) {
        if (text[j] === '\\') {
          j += 2;
          continue;
        }
        if (text[j] === q) {
          j++;
          break;
        }
        if (q !== '`' && text[j] === '\n') break;
        j++;
      }
      out += `<span class="gjs-str">${esc(text.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // numbers
    if (/[0-9]/.test(ch) && (i === 0 || !/[A-Za-z_$]/.test(text[i - 1]))) {
      let j = i;
      while (j < n && /[0-9xa-fA-F._]/.test(text[j])) j++;
      out += `<span class="gjs-num">${esc(text.slice(i, j))}</span>`;
      i = j;
      continue;
    }

    // identifiers / keywords
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$]/.test(text[j])) j++;
      const id = text.slice(i, j);
      let cls = 'gjs-id';
      if (KEYWORDS.has(id)) cls = 'gjs-kw';
      else if (GOAULD_API.has(id)) cls = 'gjs-api';
      out += `<span class="${cls}">${esc(id)}</span>`;
      i = j;
      continue;
    }

    out += esc(ch);
    i++;
  }
  return out;
}

/**
 * @param {string} source
 * @returns {string} HTML
 */
export function highlightGoauldScript(source) {
  const text = String(source ?? '');
  const Prism = typeof window !== 'undefined' ? window.Prism : null;
  if (Prism?.languages?.javascript && typeof Prism.highlight === 'function') {
    try {
      // Prism escapes HTML itself.
      return Prism.highlight(text, Prism.languages.javascript, 'javascript');
    } catch {
      /* fall through */
    }
  }
  return highlightFallback(text);
}

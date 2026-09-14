/**
 * JNI / loadLibrary bridges between DEX (Code) and ELF .so (Native).
 *
 * - ACC_NATIVE methods ↔ Java_* symbols in arm64 libs
 * - System.loadLibrary("foo") string sites ↔ libfoo.so
 */

import { listApkNativeLibs } from './native-ui.js';

const ACC_NATIVE = 0x100;

/** @type {null | {
 *   builtAt: number,
 *   libs: string[],
 *   bySymbol: Map<string, JniHit[]>,
 *   byLib: Map<string, JniHit[]>,
 *   byDexMethod: Map<string, JniHit[]>,
 *   loadLibrary: LoadLibHit[],
 *   nativeMethods: NativeMethodRef[],
 * }} */
let indexState = null;
let buildPromise = null;

/**
 * @typedef {{
 *   kind: 'jni'|'loadLibrary',
 *   className: string,
 *   methodName: string,
 *   dexName?: string,
 *   dexFile?: string,
 *   classIdx?: number,
 *   methodIdx?: number,
 *   libPath: string,
 *   symbol?: string,
 *   funcIdx?: number,
 *   libShort?: string,
 * }} JniHit
 */

/**
 * @typedef {{
 *   className: string,
 *   methodName: string,
 *   dexName: string,
 *   dexFile: string,
 *   classIdx: number,
 *   methodIdx: number,
 *   mangled: string,
 * }} NativeMethodRef
 */

/**
 * @typedef {{
 *   libShort: string,
 *   libPath: string,
 *   stringValue: string,
 * }} LoadLibHit
 */

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** JNI identifier escape (simplified JVM → JNI). */
export function jniEscapeIdent(s) {
  let out = '';
  for (const ch of String(s || '')) {
    if (ch === '_') out += '_1';
    else if (ch === ';') out += '_2';
    else if (ch === '[') out += '_3';
    else if (/[A-Za-z0-9]/.test(ch)) out += ch;
    else {
      const cp = ch.codePointAt(0);
      out += '_0' + cp.toString(16).padStart(4, '0');
    }
  }
  return out;
}

/**
 * Class display name `com.foo.Bar` or descriptor `Lcom/foo/Bar;` → JNI class part.
 */
export function jniClassPart(className) {
  let n = String(className || '').trim();
  if (n.startsWith('L') && n.endsWith(';')) n = n.slice(1, -1);
  n = n.replace(/\./g, '/');
  return n
    .split('/')
    .map((p) => jniEscapeIdent(p))
    .join('_');
}

/** Mangle to `Java_pkg_Class_method` (no overload suffix). */
export function mangleJavaNative(className, methodName) {
  const cls = jniClassPart(className);
  const meth = jniEscapeIdent(methodName);
  if (!cls || !meth || meth === '<init>' || meth === '<clinit>') return '';
  return `Java_${cls}_${meth}`;
}

/** Best-effort demangle `Java_com_foo_Bar_baz` → { className, methodName }. */
export function demangleJavaNative(symbol) {
  const s = String(symbol || '');
  if (!s.startsWith('Java_')) return null;
  const body = s.slice(5);
  // Prefer matching against known native methods; fallback: last _ segment = method.
  const parts = [];
  let i = 0;
  while (i < body.length) {
    if (body[i] === '_' && body[i + 1] === '1') {
      parts.push('_');
      i += 2;
      continue;
    }
    if (body[i] === '_' && body[i + 1] === '2') {
      parts.push(';');
      i += 2;
      continue;
    }
    if (body[i] === '_' && body[i + 1] === '3') {
      parts.push('[');
      i += 2;
      continue;
    }
    if (body[i] === '_' && body[i + 1] === '0' && /^_0[0-9a-fA-F]{4}/.test(body.slice(i))) {
      const hex = body.slice(i + 2, i + 6);
      parts.push(String.fromCodePoint(parseInt(hex, 16)));
      i += 6;
      continue;
    }
    if (body[i] === '_') {
      parts.push('\0'); // package / class separator marker
      i += 1;
      continue;
    }
    parts.push(body[i]);
    i += 1;
  }
  const segs = [];
  let cur = '';
  for (const p of parts) {
    if (p === '\0') {
      segs.push(cur);
      cur = '';
    } else cur += p;
  }
  if (cur) segs.push(cur);
  if (segs.length < 2) return null;
  const methodName = segs[segs.length - 1];
  const className = segs.slice(0, -1).join('.');
  return { className, methodName };
}

export function libShortFromPath(path) {
  const base = String(path || '').split('/').pop() || '';
  return base.replace(/^lib/, '').replace(/\.so$/i, '');
}

export function resolveLibPathForName(libName, libPaths) {
  const raw = String(libName || '').trim();
  if (!raw) return null;
  let short = raw.replace(/^lib/, '').replace(/\.so$/i, '');
  const paths = Array.isArray(libPaths) ? libPaths : [];
  const arm64 = paths.filter((p) => /arm64-v8a/i.test(p));
  const pool = arm64.length ? arm64 : paths;
  const hit =
    pool.find((p) => libShortFromPath(p) === short) ||
    paths.find((p) => libShortFromPath(p) === short) ||
    pool.find((p) => (p.split('/').pop() || '') === raw) ||
    pool.find((p) => (p.split('/').pop() || '') === `lib${short}.so`);
  return hit || null;
}

function dexMethodKey(dexFile, className, methodName) {
  return `${dexFile || ''}::${className}#${methodName}`;
}

function isNativeMethod(m) {
  return !!(m?.is_native || m?.isNative || ((m?.access_flags ?? m?.accessFlags ?? 0) & ACC_NATIVE));
}

/**
 * @param {{
 *   getApkFiles: () => any[],
 *   listDexNames: () => string[],
 *   getApkFileContent: (name: string) => Uint8Array|null,
 *   parseFileInWorker: (bytes: Uint8Array, name: string) => Promise<any>,
 *   parseElfInWorker: (bytes: Uint8Array) => Promise<any>,
 *   getCachedDexBrowse?: (dexName: string) => any|null,
 * }} api
 */
export async function buildJniLinkIndex(api) {
  if (buildPromise) return buildPromise;
  buildPromise = (async () => {
    const files = api.getApkFiles?.() || [];
    const libs = listApkNativeLibs(files);
    /** @type {NativeMethodRef[]} */
    const nativeMethods = [];
    /** @type {Map<string, { path: string, functions: {name:string,vaddr:number,size:number}[] }>} */
    const elfByPath = new Map();

    const dexNames = api.listDexNames?.() || [];
    for (const dexName of dexNames) {
      let browse = api.getCachedDexBrowse?.(dexName) || null;
      if (!browse?.classes) {
        const bytes = api.getApkFileContent?.(dexName);
        if (!bytes?.length) continue;
        try {
          const result = await api.parseFileInWorker(bytes, dexName);
          browse = result?.ok ? result.data : result?.data || result;
        } catch (_) {
          continue;
        }
      }
      const classes = Array.isArray(browse?.classes) ? browse.classes : [];
      for (let ci = 0; ci < classes.length; ci++) {
        const cls = classes[ci];
        const className = cls?.name || '';
        const methods = Array.isArray(cls?.methods) ? cls.methods : [];
        for (let mi = 0; mi < methods.length; mi++) {
          const m = methods[mi];
          if (!isNativeMethod(m)) continue;
          const methodName = m.dex_name || m.dexName || m.name || '';
          const mangled = mangleJavaNative(className, methodName);
          if (!mangled) continue;
          nativeMethods.push({
            className,
            methodName,
            dexName: methodName,
            dexFile: dexName,
            classIdx: ci,
            methodIdx: mi,
            mangled,
          });
        }
      }
    }

    // Prefer arm64 libs for symbol matching (already ordered by listApkNativeLibs).
    const preferLibs = libs.filter((p) => /arm64-v8a/i.test(p));
    const scanLibs = preferLibs.length ? preferLibs : libs.slice(0, 12);

    for (const path of scanLibs) {
      const bytes = api.getApkFileContent?.(path);
      if (!bytes?.length) continue;
      try {
        const raw = await api.parseElfInWorker(bytes);
        const data = raw?.ok ? raw.data : raw?.data || raw;
        const functions = Array.isArray(data?.functions) ? data.functions : [];
        elfByPath.set(path, { path, functions });
      } catch (_) {
        /* skip */
      }
    }

    /** @type {Map<string, JniHit[]>} */
    const bySymbol = new Map();
    /** @type {Map<string, JniHit[]>} */
    const byLib = new Map();
    /** @type {Map<string, JniHit[]>} */
    const byDexMethod = new Map();

    const pushHit = (hit) => {
      if (hit.symbol) {
        if (!bySymbol.has(hit.symbol)) bySymbol.set(hit.symbol, []);
        bySymbol.get(hit.symbol).push(hit);
      }
      if (hit.libPath) {
        if (!byLib.has(hit.libPath)) byLib.set(hit.libPath, []);
        byLib.get(hit.libPath).push(hit);
      }
      const dk = dexMethodKey(hit.dexFile, hit.className, hit.methodName);
      if (!byDexMethod.has(dk)) byDexMethod.set(dk, []);
      byDexMethod.get(dk).push(hit);
    };

    for (const nm of nativeMethods) {
      let matched = false;
      for (const [path, elf] of elfByPath) {
        const funcs = elf.functions;
        // Exact, then overload prefix Java_..._meth__
        let idx = funcs.findIndex((f) => f.name === nm.mangled);
        if (idx < 0) {
          idx = funcs.findIndex(
            (f) => f.name === nm.mangled || f.name.startsWith(nm.mangled + '__')
          );
        }
        if (idx < 0) continue;
        matched = true;
        pushHit({
          kind: 'jni',
          className: nm.className,
          methodName: nm.methodName,
          dexName: nm.dexName,
          dexFile: nm.dexFile,
          classIdx: nm.classIdx,
          methodIdx: nm.methodIdx,
          libPath: path,
          symbol: funcs[idx].name,
          funcIdx: idx,
          libShort: libShortFromPath(path),
        });
      }
      if (!matched) {
        // Keep unresolved native methods so UI can still hint.
        pushHit({
          kind: 'jni',
          className: nm.className,
          methodName: nm.methodName,
          dexName: nm.dexName,
          dexFile: nm.dexFile,
          classIdx: nm.classIdx,
          methodIdx: nm.methodIdx,
          libPath: '',
          symbol: nm.mangled,
          libShort: '',
        });
      }
    }

    /** @type {LoadLibHit[]} */
    const loadLibrary = [];
    // Infer loadLibrary targets from lib basenames (call sites resolved lazily via strings UI).
    for (const path of libs) {
      const short = libShortFromPath(path);
      if (!short) continue;
      loadLibrary.push({
        libShort: short,
        libPath: path,
        stringValue: short,
      });
    }

    indexState = {
      builtAt: Date.now(),
      libs,
      bySymbol,
      byLib,
      byDexMethod,
      loadLibrary,
      nativeMethods,
    };
    return indexState;
  })().finally(() => {
    buildPromise = null;
  });
  return buildPromise;
}

export function getJniLinkIndex() {
  return indexState;
}

export function clearJniLinkIndex() {
  indexState = null;
  buildPromise = null;
}

export function hitsForDexMethod(className, methodName, dexFile = '') {
  const idx = indexState;
  if (!idx) return [];
  const k = dexMethodKey(dexFile, className, methodName);
  let hits = idx.byDexMethod.get(k) || [];
  if (!hits.length) {
    // Fallback without dex file
    hits = idx.byDexMethod.get(dexMethodKey('', className, methodName)) || [];
  }
  if (!hits.length) {
    const mangled = mangleJavaNative(className, methodName);
    hits = (idx.bySymbol.get(mangled) || []).slice();
  }
  return hits.filter((h) => h.libPath);
}

export function hitsForSymbol(symbol) {
  if (!indexState || !symbol) return [];
  return indexState.bySymbol.get(symbol) || [];
}

export function hitsForLib(libPath) {
  if (!indexState || !libPath) return [];
  return (indexState.byLib.get(libPath) || []).filter((h) => h.kind === 'jni' && h.className);
}

export function resolveLoadLibraryTarget(stringValue) {
  if (!indexState) return null;
  return resolveLibPathForName(stringValue, indexState.libs);
}

/** Render a compact chip row for Code / Native toolbars. */
export function renderJniLinkChips(hits, { direction = 'to-native' } = {}) {
  if (!hits?.length) return '';
  return hits
    .slice(0, 8)
    .map((h) => {
      if (direction === 'to-native') {
        const label = `${h.libShort || libShortFromPath(h.libPath) || 'lib'}${h.symbol ? ' · ' + h.symbol : ''}`;
        return `<button type="button" class="btn btn-small jni-link-chip" data-jni-nav="native" data-lib="${escapeHtml(h.libPath)}" data-symbol="${escapeHtml(h.symbol || '')}" data-func-idx="${h.funcIdx ?? ''}" title="${escapeHtml(h.libPath)}">${escapeHtml(label)}</button>`;
      }
      const label = `${(h.className || '').split('.').pop() || h.className}.${h.methodName}`;
      return `<button type="button" class="btn btn-small jni-link-chip" data-jni-nav="dex" data-class="${escapeHtml(h.className)}" data-method="${escapeHtml(h.methodName)}" data-dex="${escapeHtml(h.dexFile || '')}" data-class-idx="${h.classIdx ?? ''}" data-method-idx="${h.methodIdx ?? ''}" title="${escapeHtml(h.className + '#' + h.methodName)}">${escapeHtml(label)}</button>`;
    })
    .join('');
}

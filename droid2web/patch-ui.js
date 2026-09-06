/**
 * Patch tab — decode / edit / build / sign via apk-patch WASM + IndexedDB.
 */

import {
  deletePatchProject,
  getDebugKeystore,
  listPatchFiles,
  listPatchProjects,
  newPatchProjectId,
  putPatchFiles,
  savePatchProject,
  setDebugKeystore,
} from './patch-store.js';
import { highlightDexTxt, isDexTxtPath } from './dex-txt-highlight.js';
import { resolveGoauldBinary } from './goauld-assets.js';

let wasm = null;
let getApkBytes = () => null;
let getApkName = () => 'app.apk';
let currentProjectId = null;
let currentFiles = [];
let selectedPath = null;
let dirty = false;
let highlightRaf = 0;

function $(id) {
  return document.getElementById(id);
}

function setStatus(msg) {
  const el = $('patch-status');
  if (el) el.textContent = msg;
}

function decodeOptions() {
  const frameTag = ($('patch-opt-frame-tag')?.value || '').trim();
  return {
    force: $('patch-opt-force')?.checked ?? true,
    noSrc: $('patch-opt-no-src')?.checked ?? false,
    noRes: $('patch-opt-no-res')?.checked ?? false,
    noAssets: $('patch-opt-no-assets')?.checked ?? false,
    allSrc: $('patch-opt-all-src')?.checked ?? false,
    onlyManifest: $('patch-opt-only-manifest')?.checked ?? false,
    keepBrokenRes: $('patch-opt-keep-broken')?.checked ?? false,
    noDebugInfo: $('patch-opt-no-debug')?.checked ?? false,
    ignoreRawValues: $('patch-opt-ignore-raw')?.checked ?? false,
    frameTag: frameTag || null,
    resResolveMode: $('patch-opt-res-mode')?.value || 'default',
    jobs: 2,
  };
}

function buildOptions(keystoreB64) {
  return {
    force: true,
    sign: $('patch-opt-sign')?.checked ?? true,
    v1: $('patch-opt-v1')?.checked ?? false,
    v2: $('patch-opt-v2')?.checked ?? true,
    v3: $('patch-opt-v3')?.checked ?? true,
    debuggable: $('patch-opt-debuggable')?.checked ?? false,
    netSecConf: $('patch-opt-netsec')?.checked ?? false,
    copyOriginal: $('patch-opt-copy-original')?.checked ?? false,
    rebuildResources: $('patch-opt-rebuild-res')?.checked ?? false,
    skipAapt2: true,
    useAapt2: false,
    noApk: $('patch-opt-no-apk')?.checked ?? false,
    jobs: 2,
    keystoreB64: keystoreB64 || null,
  };
}

function renderFileTree(files) {
  const ul = $('patch-file-tree');
  if (!ul) return;
  ul.innerHTML = '';
  currentFiles = files.slice().sort();
  for (const path of currentFiles) {
    const li = document.createElement('li');
    li.textContent = path;
    li.title = path;
    li.tabIndex = 0;
    if (path === selectedPath) li.classList.add('active');
    li.addEventListener('click', () => openFile(path));
    ul.appendChild(li);
  }
}

function isTextPath(path) {
  return /\.(xml|yml|yaml|txt|json|properties|smali|js|css|html|md)$/i.test(path)
    || path === 'apktool.yml'
    || path === 'apkpatch.yml'
    || path.endsWith('.dex.txt');
}

function syncEditorHighlight() {
  const editor = $('patch-editor');
  const pre = $('patch-editor-highlight');
  if (!editor || !pre) return;
  const mode = isDexTxtPath(selectedPath) ? 'dextxt' : 'plain';
  const html = highlightDexTxt(editor.value || '', { mode });
  pre.innerHTML = html + '\n';
  pre.scrollTop = editor.scrollTop;
  pre.scrollLeft = editor.scrollLeft;
}

function scheduleHighlight() {
  if (highlightRaf) cancelAnimationFrame(highlightRaf);
  highlightRaf = requestAnimationFrame(() => {
    highlightRaf = 0;
    syncEditorHighlight();
  });
}

function setEditorHint(path) {
  const hint = $('patch-editor-hint');
  if (!hint) return;
  const show = isDexTxtPath(path);
  hint.hidden = !show;
}

async function openFile(path) {
  if (!wasm?.patch_read) return;
  selectedPath = path;
  renderFileTree(currentFiles);
  const pathEl = $('patch-editor-path');
  const editor = $('patch-editor');
  const saveBtn = $('patch-editor-save');
  if (pathEl) pathEl.textContent = path;
  setEditorHint(path);
  try {
    const data = wasm.patch_read(path);
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (isTextPath(path)) {
      editor.disabled = false;
      saveBtn.disabled = false;
      editor.value = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      scheduleHighlight();
    } else {
      editor.disabled = true;
      saveBtn.disabled = true;
      editor.value = `Binary file (${bytes.length} bytes). Replace via decode or download from Files.`;
      const pre = $('patch-editor-highlight');
      if (pre) pre.textContent = editor.value;
    }
  } catch (e) {
    setStatus(`Read failed: ${e}`);
  }
}

async function applyEdit() {
  if (!selectedPath || !wasm?.patch_write) return;
  if (!isTextPath(selectedPath)) return;
  const editor = $('patch-editor');
  const bytes = new TextEncoder().encode(editor.value);
  try {
    wasm.patch_write(selectedPath, bytes);
    dirty = true;
    setStatus(`Updated ${selectedPath} — ready to Build & download`);
  } catch (e) {
    setStatus(`Write failed: ${e}`);
  }
}

async function ensureDebugKey() {
  let existing = await getDebugKeystore();
  const arr = existing ? new Uint8Array(existing) : null;
  let out = wasm.patch_debug_keystore_bytes(arr || undefined);
  const bytes = out instanceof Uint8Array ? out : new Uint8Array(out);
  await setDebugKeystore(bytes);
  // base64 for build options
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

async function decodeBytes(bytes, name) {
  if (!wasm?.patch_decode) throw new Error('WASM patch API missing — rebuild web package');
  setStatus('Decoding…');
  const result = wasm.patch_decode(bytes, name || 'app.apk', JSON.stringify(decodeOptions()));
  const files = Array.from(result.files || []);
  renderFileTree(files);
  $('patch-build-btn').disabled = false;
  $('patch-persist-btn').disabled = false;
  $('patch-clear-btn').disabled = false;
  $('patch-goauld-btn').disabled = false;
  $('patch-goauld-session-btn').disabled = false;
  currentProjectId = newPatchProjectId();
  dirty = true;
  setStatus(`Decoded ${result.entryCount} entries, ${result.dexClassCount} classes · ${files.length} files`);
  await refreshSavedList();
}

async function decodeLoaded() {
  const bytes = getApkBytes();
  if (!bytes || !bytes.length) {
    setStatus('Load an APK first (or use Decode file…)');
    return;
  }
  try {
    await decodeBytes(bytes, getApkName());
  } catch (e) {
    console.error(e);
    setStatus(`Decode failed: ${e}`);
  }
}

async function decodeUpload(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  try {
    await decodeBytes(buf, file.name);
  } catch (e) {
    console.error(e);
    setStatus(`Decode failed: ${e}`);
  }
}

async function persistProject() {
  if (!wasm?.patch_list || !currentProjectId) return;
  setStatus('Saving to IndexedDB…');
  const files = Array.from(wasm.patch_list() || []);
  const entries = [];
  for (const path of files) {
    const data = wasm.patch_read(path);
    entries.push({ path, data: data instanceof Uint8Array ? data : new Uint8Array(data) });
  }
  await putPatchFiles(currentProjectId, entries);
  await savePatchProject({
    id: currentProjectId,
    name: getApkName() || currentProjectId,
    apkName: getApkName() || 'app.apk',
    fileCount: entries.length,
    updatedAt: Date.now(),
  });
  dirty = false;
  setStatus(`Saved ${entries.length} files to browser storage`);
  await refreshSavedList();
}

async function restoreProject(projectId) {
  if (!wasm?.patch_write || !wasm?.patch_clear) return;
  setStatus('Restoring from IndexedDB…');
  wasm.patch_clear();
  // Need an empty session: decode a tiny stub is heavy — write files after a minimal decode.
  // Re-hydrate by creating session via decode of empty is not available.
  // Workaround: user must have wasm session; we decode from stored original if present.
  const paths = await listPatchFiles(projectId);
  const orig = paths.find((p) => p === 'original/classes.dex' || p.endsWith('/classes.dex'));
  // Build a fake APK is complex; instead require re-decode. Show message.
  // Better: add patch_import — for now load files after decode_apk_bytes of a minimal zip.
  // Simplest UX: list projects for delete/info; restore writes require active empty MemVfs.
  // Add patch_new_empty via writing apktool.yml after clear won't work without session.

  // Create session by decoding stored original APK pieces is too hard.
  // Store the unsigned/source APK bytes in IDB meta for restore.
  setStatus(`Project ${projectId} has ${paths.length} files. Re-decode the APK, then use Save. (Full restore needs a stored base APK — use Save after decode.)`);
  await refreshSavedList();
}

async function refreshSavedList() {
  const ul = $('patch-saved-list');
  if (!ul) return;
  const projects = await listPatchProjects();
  ul.innerHTML = '';
  for (const p of projects.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))) {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${escapeHtml(p.name || p.id)}</strong> · ${p.fileCount || 0} files · ${new Date(p.updatedAt || 0).toLocaleString()}`;
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn btn-small';
    del.textContent = 'Delete';
    del.addEventListener('click', async () => {
      await deletePatchProject(p.id);
      await refreshSavedList();
    });
    li.appendChild(del);
    ul.appendChild(li);
  }
  if (!projects.length) {
    ul.innerHTML = '<li class="muted">No saved projects</li>';
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/vnd.android.package-archive' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function buildApkBytes() {
  if (!wasm?.patch_build) throw new Error('WASM patch_build missing');
  if (selectedPath && isTextPath(selectedPath) && !$('patch-editor')?.disabled) {
    await applyEdit();
  }
  const keyB64 = await ensureDebugKey();
  const out = wasm.patch_build(JSON.stringify(buildOptions(keyB64)));
  const bytes = out instanceof Uint8Array ? out : new Uint8Array(out);
  if (!bytes.length) throw new Error('Build produced no APK (no-apk mode or empty)');
  return bytes;
}

async function buildApk() {
  try {
    setStatus('Building & signing (dex-txt assemble-from-scratch)…');
    const bytes = await buildApkBytes();
    const name = (getApkName() || 'app.apk').replace(/\.apk$/i, '') + '-patched.apk';
    downloadBytes(bytes, name);
    dirty = false;
    setStatus(`Built ${bytes.length} bytes → ${name}`);
  } catch (e) {
    console.error(e);
    setStatus(`Build failed: ${e}`);
  }
}

async function readGoauldSo() {
  return resolveGoauldBinary($('patch-goauld-so'), 'agent');
}

async function injectGoauldSession() {
  if (!wasm?.patch_inject_goauld_session) {
    setStatus('Session inject API missing — rebuild WASM');
    return;
  }
  try {
    const so = await readGoauldSo();
    setStatus('Injecting goauld into session…');
    wasm.patch_inject_goauld_session(so);
    dirty = true;
    const files = Array.from(wasm.patch_list() || []);
    renderFileTree(files);
    setStatus('Goauld injected into session — Build & download, or use Device tab to install');
  } catch (e) {
    console.error(e);
    setStatus(`Session inject failed: ${e}`);
  }
}

async function injectGoauldBytes() {
  const so = await readGoauldSo();
  const apk = getApkBytes();
  if (!apk?.length) throw new Error('Load an APK first');
  const keyB64 = await ensureDebugKey();
  const out = wasm.patch_inject_goauld(
    apk,
    so,
    getApkName() || 'app.apk',
    JSON.stringify(buildOptions(keyB64)),
  );
  return out instanceof Uint8Array ? out : new Uint8Array(out);
}

async function injectGoauld() {
  try {
    setStatus('Injecting goauld…');
    const bytes = await injectGoauldBytes();
    downloadBytes(bytes, (getApkName() || 'app.apk').replace(/\.apk$/i, '') + '-goauld.apk');
    setStatus(`Injected goauld → ${bytes.length} bytes`);
  } catch (e) {
    console.error(e);
    setStatus(`Goauld inject failed: ${e}`);
  }
}

function clearSession() {
  wasm?.patch_clear?.();
  currentProjectId = null;
  currentFiles = [];
  selectedPath = null;
  renderFileTree([]);
  const editor = $('patch-editor');
  if (editor) {
    editor.value = '';
    editor.disabled = true;
  }
  const pre = $('patch-editor-highlight');
  if (pre) pre.textContent = '';
  setEditorHint(null);
  $('patch-editor-save').disabled = true;
  $('patch-build-btn').disabled = true;
  $('patch-persist-btn').disabled = true;
  $('patch-clear-btn').disabled = true;
  $('patch-goauld-btn').disabled = true;
  $('patch-goauld-session-btn').disabled = true;
  setStatus('Session cleared');
}

/**
 * @param {object} api wasm exports
 * @param {{ getApkBytes: () => Uint8Array|null, getApkName: () => string }} ctx
 */
export function initPatchUi(api, ctx) {
  wasm = api;
  getApkBytes = ctx.getApkBytes || getApkBytes;
  getApkName = ctx.getApkName || getApkName;

  $('patch-decode-btn')?.addEventListener('click', () => decodeLoaded());
  $('patch-decode-upload-btn')?.addEventListener('click', () => $('patch-decode-file')?.click());
  $('patch-decode-file')?.addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (f) decodeUpload(f);
    e.target.value = '';
  });
  $('patch-build-btn')?.addEventListener('click', () => buildApk());
  $('patch-persist-btn')?.addEventListener('click', () => persistProject());
  $('patch-clear-btn')?.addEventListener('click', () => clearSession());
  $('patch-editor-save')?.addEventListener('click', () => applyEdit());
  $('patch-goauld-btn')?.addEventListener('click', () => injectGoauld());
  $('patch-goauld-session-btn')?.addEventListener('click', () => injectGoauldSession());

  const editor = $('patch-editor');
  editor?.addEventListener('input', () => {
    dirty = true;
    scheduleHighlight();
  });
  editor?.addEventListener('scroll', () => {
    const pre = $('patch-editor-highlight');
    if (pre && editor) {
      pre.scrollTop = editor.scrollTop;
      pre.scrollLeft = editor.scrollLeft;
    }
  });
  // Tab inserts spaces in dex-txt
  editor?.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !editor.disabled) {
      e.preventDefault();
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      const v = editor.value;
      editor.value = `${v.slice(0, start)}    ${v.slice(end)}`;
      editor.selectionStart = editor.selectionEnd = start + 4;
      dirty = true;
      scheduleHighlight();
    }
  });

  refreshSavedList().catch(() => {});
}

export function openPatchTabWithLoadedApk(switchTab) {
  switchTab?.('patch-tab');
  if (getApkBytes()?.length) {
    setStatus('Ready — click Decode loaded APK');
  }
}

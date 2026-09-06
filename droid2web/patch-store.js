/** IndexedDB persistence for apk-patch projects + debug signing key. */

const DB_NAME = 'droid2web-patch-v1';
const DB_VERSION = 1;
const STORE_PROJECTS = 'projects';
const STORE_FILES = 'files';
const STORE_META = 'meta';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_PROJECTS)) {
        db.createObjectStore(STORE_PROJECTS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_FILES)) {
        const files = db.createObjectStore(STORE_FILES, { keyPath: ['projectId', 'path'] });
        files.createIndex('byProject', 'projectId', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'key' });
      }
    };
    req.onsuccess = () => resolve(req.result);
  });
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error('IndexedDB tx failed'));
    tx.onabort = () => reject(tx.error || new Error('IndexedDB tx aborted'));
  });
}

export async function listPatchProjects() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PROJECTS, 'readonly');
    const req = tx.objectStore(STORE_PROJECTS).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

export async function savePatchProject({ id, name, apkName, createdAt, updatedAt, fileCount }) {
  const db = await openDb();
  const tx = db.transaction(STORE_PROJECTS, 'readwrite');
  tx.objectStore(STORE_PROJECTS).put({
    id,
    name: name || id,
    apkName: apkName || 'app.apk',
    createdAt: createdAt || Date.now(),
    updatedAt: updatedAt || Date.now(),
    fileCount: fileCount || 0,
  });
  await txDone(tx);
}

export async function deletePatchProject(projectId) {
  const db = await openDb();
  const tx = db.transaction([STORE_PROJECTS, STORE_FILES], 'readwrite');
  tx.objectStore(STORE_PROJECTS).delete(projectId);
  const idx = tx.objectStore(STORE_FILES).index('byProject');
  const req = idx.openCursor(IDBKeyRange.only(projectId));
  req.onsuccess = () => {
    const cursor = req.result;
    if (cursor) {
      cursor.delete();
      cursor.continue();
    }
  };
  await txDone(tx);
}

export async function putPatchFile(projectId, path, data) {
  const db = await openDb();
  const tx = db.transaction(STORE_FILES, 'readwrite');
  const blob = data instanceof Blob ? data : new Blob([data]);
  tx.objectStore(STORE_FILES).put({ projectId, path, blob });
  await txDone(tx);
}

export async function putPatchFiles(projectId, entries) {
  const db = await openDb();
  const tx = db.transaction(STORE_FILES, 'readwrite');
  const store = tx.objectStore(STORE_FILES);
  for (const { path, data } of entries) {
    const blob = data instanceof Blob ? data : new Blob([data]);
    store.put({ projectId, path, blob });
  }
  await txDone(tx);
}

export async function listPatchFiles(projectId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FILES, 'readonly');
    const idx = tx.objectStore(STORE_FILES).index('byProject');
    const req = idx.getAll(IDBKeyRange.only(projectId));
    req.onsuccess = () => {
      const rows = req.result || [];
      resolve(rows.map((r) => r.path).sort());
    };
    req.onerror = () => reject(req.error);
  });
}

export async function getPatchFile(projectId, path) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_FILES, 'readonly');
    const req = tx.objectStore(STORE_FILES).get([projectId, path]);
    req.onsuccess = async () => {
      const row = req.result;
      if (!row) {
        resolve(null);
        return;
      }
      const buf = await row.blob.arrayBuffer();
      resolve(new Uint8Array(buf));
    };
    req.onerror = () => reject(req.error);
  });
}

export async function getDebugKeystore() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_META, 'readonly');
    const req = tx.objectStore(STORE_META).get('debug-keystore');
    req.onsuccess = async () => {
      const row = req.result;
      if (!row?.blob) {
        resolve(null);
        return;
      }
      resolve(new Uint8Array(await row.blob.arrayBuffer()));
    };
    req.onerror = () => reject(req.error);
  });
}

export async function setDebugKeystore(bytes) {
  const db = await openDb();
  const tx = db.transaction(STORE_META, 'readwrite');
  tx.objectStore(STORE_META).put({
    key: 'debug-keystore',
    blob: new Blob([bytes]),
  });
  await txDone(tx);
}

export function newPatchProjectId() {
  return `proj-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

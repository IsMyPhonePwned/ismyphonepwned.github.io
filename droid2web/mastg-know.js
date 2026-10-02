/**
 * OWASP MASTG Knowledge Base helpers for the Security scan UI.
 * Catalog: https://mas.owasp.org/MASTG/knowledge/
 * Article URLs: https://mas.owasp.org/MASTG-KNOW-NNNN
 * Chains through MASWE → MASTG KNOW / BEST: see ./maswe.js
 */

import {
  MASWE_INDEX,
  MASTG_BEST_INDEX,
  MASTG_DEMO_INDEX,
  resolveMasChain,
  resolveMaswe,
  masweUrl,
  masvsFamilySlug,
  masweProfiles,
  masweTests,
  masProfileLabel,
  masProfileTitle,
  stripMasLocationNoise,
} from './maswe.js';

export const MASTG_KNOWLEDGE_INDEX = 'https://mas.owasp.org/MASTG/knowledge/';
export { MASWE_INDEX, MASTG_BEST_INDEX, MASTG_DEMO_INDEX, resolveMaswe, masweUrl };

/** Android MASTG-KNOW articles (current) used for Security scan deep-links. */
export const MASTG_KNOW_ANDROID = {
  'MASTG-KNOW-0001': { title: 'Biometric Authentication', category: 'MASVS-AUTH' },
  'MASTG-KNOW-0002': { title: 'FingerprintManager', category: 'MASVS-AUTH' },
  'MASTG-KNOW-0003': { title: 'App Signing', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0004': { title: 'Third-Party Libraries', category: 'MASVS-CODE' },
  'MASTG-KNOW-0005': { title: 'Memory Corruption Bugs', category: 'MASVS-CODE' },
  'MASTG-KNOW-0006': { title: 'Binary Protection Mechanisms', category: 'MASVS-CODE' },
  'MASTG-KNOW-0007': { title: 'Debuggable Apps', category: 'MASVS-CODE' },
  'MASTG-KNOW-0008': { title: 'Debugging Information and Debug Symbols', category: 'MASVS-CODE' },
  'MASTG-KNOW-0009': { title: 'StrictMode', category: 'MASVS-CODE' },
  'MASTG-KNOW-0010': { title: 'Exception Handling', category: 'MASVS-CODE' },
  'MASTG-KNOW-0011': { title: 'Security Provider', category: 'MASVS-CRYPTO' },
  'MASTG-KNOW-0012': { title: 'Key Generation', category: 'MASVS-CRYPTO' },
  'MASTG-KNOW-0013': { title: 'Random Number Generation', category: 'MASVS-CRYPTO' },
  'MASTG-KNOW-0014': { title: 'Android Network Security Configuration', category: 'MASVS-NETWORK' },
  'MASTG-KNOW-0015': { title: 'Certificate Pinning', category: 'MASVS-NETWORK' },
  'MASTG-KNOW-0017': { title: 'App Permissions', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0018': { title: 'WebViews', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0019': { title: 'Deep Links', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0020': { title: 'Inter-Process Communication (IPC) Mechanisms', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0021': { title: 'Object Serialization', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0022': { title: 'Overlay Attacks', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0023': { title: 'Enforced Updating', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0024': { title: 'Pending Intents', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0025': { title: 'Explicit vs Implicit Intents', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0026': { title: 'Third-party Services Embedded in the App', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0027': { title: 'Root Detection', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0028': { title: 'Anti-Debugging', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0029': { title: 'File Integrity Checks', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0030': { title: 'Reverse Engineering Tool Detection', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0031': { title: 'Emulator Detection', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0032': { title: 'Runtime Integrity Verification', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0033': { title: 'Obfuscation', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0034': { title: 'Device Binding', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0035': { title: 'Google Play Integrity API', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0036': { title: 'Shared Preferences', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0037': { title: 'SQLite Database', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0038': { title: 'SQLCipher Database', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0039': { title: 'Firebase Real-time Databases', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0040': { title: 'Realm Databases', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0041': { title: 'Internal Storage', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0042': { title: 'External Storage', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0043': { title: 'Android KeyStore', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0044': { title: 'Key Attestation', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0045': { title: 'Secure Key Import into Keystore', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0047': { title: 'Cryptographic Key Storage', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0048': { title: 'KeyChain', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0049': { title: 'Logs', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0050': { title: 'Backups', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0051': { title: 'Process Memory', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0052': { title: 'User Interface Components', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0053': { title: 'Screenshots', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0054': { title: 'App Notifications', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0055': { title: 'Keyboard Cache', category: 'MASVS-STORAGE' },
  'MASTG-KNOW-0117': { title: 'Android ContentProvider', category: 'MASVS-CODE' },
  'MASTG-KNOW-0118': { title: 'Runtime Application Self-Protection (RASP)', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0132': { title: 'Android Activities', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0133': { title: 'Android Services', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0134': { title: 'Android Broadcast Receivers', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0135': { title: 'Virtual Devices Detection', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0138': { title: 'URI Schemes in Android Intent Results', category: 'MASVS-CODE' },
  'MASTG-KNOW-0142': { title: 'Android DataStore', category: 'MASVS-STORAGE' },
};

/** Prefix / keyword → MASTG-KNOW IDs (rule_id, vuln category, message). */
const RULE_HINTS = [
  [/biometric|fingerprint|local.?auth|device.?credential|passcode/i, ['MASTG-KNOW-0001']],
  [/debuggable|allow.?debug/i, ['MASTG-KNOW-0007']],
  [/debugger|tracerpid|ptrace|anti.?debug/i, ['MASTG-KNOW-0008', 'MASTG-KNOW-0028']],
  [/strictmode/i, ['MASTG-KNOW-0009']],
  [/key.?gen|keygen|asymmetric.?key|key.?length|keystore|keychain|crypto.?key|hardcoded.?crypto/i, ['MASTG-KNOW-0012', 'MASTG-KNOW-0043', 'MASTG-KNOW-0047']],
  [/non.?random|random.?apis|math\.random|java\.util\.random|securerandom|insufficient.?entropy/i, ['MASTG-KNOW-0013']],
  [/network.?security|cleartext|trust.?anchor|insecure.?trust/i, ['MASTG-KNOW-0014']],
  [/hostname.?verif|ssl.?error|checkservertrusted|certificate.?pin|ssl.?socket|cert(?:ificate)?.?pinning|ssl.?pinning|pinning.?bypass/i, ['MASTG-KNOW-0015', 'MASTG-KNOW-0014']],
  [/dangerous.?permission|uses.?permission|runtime.?permission|app.?permission|permission.?protect|detect-dangerous-android-permissions/i, ['MASTG-KNOW-0017']],
  [/webview|javascript.?interface|allowfileaccess|setAllowFileAccess|safebrowsing|cookiemanager|http.?cookie|session.?cookie|webview.?cookie|custom.?tabs/i, ['MASTG-KNOW-0018']],
  [/deeplink|deep.?link|autoverify|custom.?scheme|intent.?filter/i, ['MASTG-KNOW-0019']],
  [/content.?provider|provider.?exported|fileprovider/i, ['MASTG-KNOW-0117', 'MASTG-KNOW-0020']],
  [/serializ|object.?input|parcelable/i, ['MASTG-KNOW-0021']],
  [/overlay.?attack|system.?alert.?window|draw.?over|tapjack|hideoverlay|filtertouches/i, ['MASTG-KNOW-0022']],
  [/sdk.?version|target.?sdk|min.?sdk|enforced.?updat/i, ['MASTG-KNOW-0023']],
  [/pending.?intent/i, ['MASTG-KNOW-0024']],
  [/implicit.?intent|intent.?leak/i, ['MASTG-KNOW-0025', 'MASTG-KNOW-0020']],
  [/broadcast.?receiver|BroadcastReceiver|registerreceiver|sendbroadcast|sticky.?broadcast|ordered.?broadcast/i, ['MASTG-KNOW-0134', 'MASTG-KNOW-0020']],
  [/\bipc\b|ipc_|exported.?activit|exported.?service/i, ['MASTG-KNOW-0020', 'MASTG-KNOW-0132']],
  [/root.?detect|jailbreak/i, ['MASTG-KNOW-0027']],
  [/emulator|virtual.?device/i, ['MASTG-KNOW-0031', 'MASTG-KNOW-0135']],
  [/obfuscat/i, ['MASTG-KNOW-0033']],
  [/play.?integrity|safety.?net|device.?binding/i, ['MASTG-KNOW-0035', 'MASTG-KNOW-0034']],
  [/shared.?prefer|local.?storage|datastore/i, ['MASTG-KNOW-0036', 'MASTG-KNOW-0142']],
  [/sql.?inject|sqlite|contentprovider.*sql/i, ['MASTG-KNOW-0037']],
  [/sqlcipher/i, ['MASTG-KNOW-0038']],
  [/firebase/i, ['MASTG-KNOW-0039']],
  [/io\.realm|\brealm\.|realm.?database|RealmConfiguration/i, ['MASTG-KNOW-0040']],
  [/external.?storage|shared.?storage|MediaStore\.|getExternal(?:Files|Storage|Cache)/i, ['MASTG-KNOW-0042']],
  [/internal.?storage|getfilesdir|openfileoutput/i, ['MASTG-KNOW-0041']],
  [/logcat|insecure.?logging|android\.util\.log|\blogging\b/i, ['MASTG-KNOW-0049']],
  [/backup|allowbackup|fullbackup|dataextraction/i, ['MASTG-KNOW-0050']],
  [/screenshot|flag_secure|secure.?flag/i, ['MASTG-KNOW-0053']],
  [/NotificationManager|NotificationCompat|notification_sensitive|sensitive.?data.?in.?notification|post.?notification|android\.permission\.POST_NOTIFICATIONS/i, ['MASTG-KNOW-0054']],
  [/keyboard.?cache|input.?type|textpassword|textnonsuggestion/i, ['MASTG-KNOW-0055']],
  [/input.?field|edittext|autofill/i, ['MASTG-KNOW-0052']],
  [/zip.?slip|path.?traversal|zipentry/i, ['MASTG-KNOW-0042', 'MASTG-KNOW-0041']],
  [/encryption|cipher|\baes\b|\bdes\b|\brc4\b|broken.?encrypt/i, ['MASTG-KNOW-0012', 'MASTG-KNOW-0011']],
  [/tracker|analytics|third.?party.?service/i, ['MASTG-KNOW-0026']],
  [/uri.?scheme|intent.?result|setresult|grant.?uri|fileprovider|path.?scope/i, ['MASTG-KNOW-0138', 'MASTG-KNOW-0020', 'MASTG-KNOW-0117']],
  [/app.?sign|signing|v1.?sig|v2.?sig/i, ['MASTG-KNOW-0003']],
  [/third.?party.?librar|dependency|supply.?chain/i, ['MASTG-KNOW-0004']],
  [/memory.?corrupt|buffer.?overflow|use.?after.?free|rce_dynamic|dexclassloader|pathclassloader|runtime\.exec|reflection_rce|dynamic.?load|dynamic.?code/i, ['MASTG-KNOW-0005']],
  [/binary.?protect|nx|pie|relro|stack.?canary/i, ['MASTG-KNOW-0006']],
  [/exception.?handl|uncaught/i, ['MASTG-KNOW-0010']],
  [/file.?integrit|checksum|hash.?check/i, ['MASTG-KNOW-0029']],
  [/reverse.?engineer|frida|xposed|magisk|hook.?detect/i, ['MASTG-KNOW-0030']],
  [/runtime.?integrit|rasp/i, ['MASTG-KNOW-0032', 'MASTG-KNOW-0118']],
  [/key.?attest/i, ['MASTG-KNOW-0044']],
  [/secure.?key.?import|wrapped.?key/i, ['MASTG-KNOW-0045']],
  [/process.?memory|heap.?dump|core.?dump/i, ['MASTG-KNOW-0051']],
];

const MASVS_CATEGORY_DEFAULTS = {
  'MASVS-AUTH': ['MASTG-KNOW-0001'],
  'MASVS-CRYPTO': ['MASTG-KNOW-0012', 'MASTG-KNOW-0013'],
  'MASVS-NETWORK': ['MASTG-KNOW-0014', 'MASTG-KNOW-0015'],
  'MASVS-PLATFORM': ['MASTG-KNOW-0020'],
  'MASVS-STORAGE': ['MASTG-KNOW-0041', 'MASTG-KNOW-0036'],
  'MASVS-CODE': ['MASTG-KNOW-0007'],
  'MASVS-RESILIENCE': ['MASTG-KNOW-0028', 'MASTG-KNOW-0027'],
  'MASVS-PRIVACY': ['MASTG-KNOW-0017'],
};

export function mastgKnowUrl(id) {
  return `https://mas.owasp.org/${id}`;
}

export function extractMasvsTags(text) {
  const s = String(text || '');
  const out = [];
  const re = /MASVS-[A-Z]+-\d+/gi;
  let m;
  while ((m = re.exec(s))) {
    const tag = m[0].toUpperCase();
    if (!out.includes(tag)) out.push(tag);
  }
  return out;
}

function masvsFamily(tag) {
  const t = String(tag || '').toUpperCase();
  const m = t.match(/^(MASVS-[A-Z]+)/);
  return m ? m[1] : '';
}

/**
 * Resolve relevant Android MASTG-KNOW articles for a finding / rule.
 * @param {{ ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string }} ctx
 * @returns {{ id: string, title: string, category: string, url: string }[]}
 */
export function resolveMastgKnowledge(ctx = {}) {
  const blob = stripMasLocationNoise(
    [ctx.ruleId, ctx.category, ctx.vulnClass, ctx.title, ctx.message]
      .filter(Boolean)
      .join(' ')
  );

  const ids = new Set();

  for (const [re, list] of RULE_HINTS) {
    if (re.test(blob)) list.forEach((id) => ids.add(id));
  }

  for (const tag of extractMasvsTags(blob)) {
    const fam = masvsFamily(tag);
    (MASVS_CATEGORY_DEFAULTS[fam] || []).forEach((id) => ids.add(id));
  }

  // Prefer specific rule-name matches already covered; if nothing matched but it's a mastg rule, link index.
  const out = [];
  for (const id of ids) {
    const meta = MASTG_KNOW_ANDROID[id];
    if (!meta) continue;
    out.push({ id, title: meta.title, category: meta.category, url: mastgKnowUrl(id) });
  }
  return out.slice(0, 4);
}

/**
 * HTML block with MASWE → MASTG Knowledge / Best-Practice links (stopPropagation on click).
 * @param {{ ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string }} ctx
 * @param {{ escapeHtml: (s: string) => string, escapeAttr: (s: string) => string }} esc
 */
/**
 * HTML block with MASWE → MASVS → MASTG Knowledge / Best-Practice links.
 * Prefers native fields from dex-decompiler (`maswe` / `masvs` / `mastg_know` / `mastg_best`)
 * when present; falls back to client-side resolveMasChain for older caches / MT findings.
 *
 * @param {{
 *   ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string,
 *   maswe?: Array<{id:string,title?:string,family?:string,url?:string}>,
 *   masvs?: Array<{id:string,title?:string,family?:string,url?:string,label?:string}>,
 *   mastg_know?: Array<{id:string,title?:string,category?:string,family?:string,url?:string}>,
 *   mastg_best?: Array<{id:string,title?:string,url?:string}>,
 * }} ctx
 * @param {{ escapeHtml: (s: string) => string, escapeAttr: (s: string) => string }} esc
 */
export function renderMastgKnowledgeHtml(ctx, esc) {
  const nativeMaswe = Array.isArray(ctx.maswe) ? ctx.maswe : [];
  const nativeMasvs = Array.isArray(ctx.masvs) ? ctx.masvs : [];
  const nativeKnow = Array.isArray(ctx.mastg_know) ? ctx.mastg_know : [];
  const nativeBest = Array.isArray(ctx.mastg_best) ? ctx.mastg_best : [];
  const hasNative = nativeMaswe.length || nativeMasvs.length || nativeKnow.length || nativeBest.length;

  let masweList = [];
  let masvsList = [];
  let knowList = [];
  let bestList = [];

  if (hasNative) {
    masweList = nativeMaswe;
    masvsList = nativeMasvs.map((c) => ({
      ...c,
      label: c.label || c.title || String(c.id || '').replace(/^MASVS-/, ''),
      family: c.family || String(c.id || '').replace(/-\d+$/, ''),
    }));
    knowList = nativeKnow.map((l) => ({
      ...l,
      category: l.category || l.family || '',
      url: l.url || mastgKnowUrl(l.id),
    }));
    bestList = nativeBest;
  } else {
    const links = resolveMastgKnowledge(ctx);
    const chain = resolveMasChain(ctx, links);
    masweList = chain.maswe || [];
    masvsList = chain.masvs || [];
    const knowById = new Map(links.map((l) => [l.id, l]));
    for (const id of chain.knowIds || []) {
      if (!knowById.has(id) && MASTG_KNOW_ANDROID[id]) {
        const meta = MASTG_KNOW_ANDROID[id];
        knowById.set(id, { id, title: meta.title, category: meta.category, url: mastgKnowUrl(id) });
      }
    }
    knowList = [...knowById.values()].slice(0, 3);
    bestList = chain.best || [];
  }

  const hasMaswe = masweList.length > 0;
  const hasMasvs = masvsList.length > 0;
  if (!knowList.length && !hasMasvs && !hasMaswe && !bestList.length && !/^mastg-/i.test(String(ctx.ruleId || ''))) {
    return '';
  }

  const chip = (href, label, title, cls, id) =>
    `<a class="mas-chip ${cls}" href="${esc.escapeAttr(href)}" target="_blank" rel="noopener noreferrer" data-mas-id="${esc.escapeAttr(id)}" title="${esc.escapeAttr(`${title} · click to filter · ⌘/Ctrl+click to open`)}" onclick="event.stopPropagation()">${esc.escapeHtml(label)}</a>`;

  const masvsChips = masvsList
    .map((c) => {
      const slug = masvsFamilySlug(c.family);
      const cls = slug ? `masvs masvs-${slug}` : 'masvs';
      return chip(c.url, c.label || c.id.replace(/^MASVS-/, ''), `${c.id} · ${c.url}`, cls, c.family || c.id);
    })
    .join('');

  const masweChips = masweList
    .map((w) => {
      const slug = masvsFamilySlug(w.family);
      const cls = slug ? `maswe masvs-${slug}` : 'maswe';
      const profs = masweProfiles(w.id).map(masProfileLabel).join(' · ');
      return chip(w.url, w.id, `${w.id}: ${w.title || ''} (${w.family || ''})${profs ? ` · ${profs}` : ''}`, cls, w.id);
    })
    .join('');
  const profileIds = [...new Set(masweList.flatMap((w) => masweProfiles(w.id)))];
  const profileChips = profileIds
    .map((code) =>
      `<a class="mas-chip profile profile-${esc.escapeAttr(code.toLowerCase())}" href="https://mas.owasp.org/MASTG/0x03b-Testing-Profiles/" target="_blank" rel="noopener noreferrer" data-mas-profile="${esc.escapeAttr(code)}" title="${esc.escapeAttr(`${masProfileTitle(code)} · click to toggle this profile · ⌘/Ctrl+click to open`)}" onclick="event.stopPropagation()">${esc.escapeHtml(masProfileLabel(code))}</a>`
    )
    .join('');
  const testMode = ctx.detectionMode === 'dynamic' ? 'dynamic' : 'static';
  const testList = [...new Map(
    masweList.flatMap((w) => masweTests(w.id, { mode: testMode })).map((t) => [t.id, t])
  ).values()].slice(0, 8);
  const testChips = testList
    .map((t) => chip(t.url, t.id.replace(/^MASTG-TEST-/, 'TEST-'), `${t.id}: ${t.title || ''}`, 'test', t.id))
    .join('');
  const knowChips = knowList.length
    ? knowList
        .map((l) => chip(l.url, l.id.replace(/^MASTG-KNOW-/, 'KNOW-'), `${l.id}: ${l.title || ''}`, 'know', l.id))
        .join('')
    : chip(MASTG_KNOWLEDGE_INDEX, 'Knowledge', 'MASTG Knowledge Base', 'know', '');
  const bestChips = bestList
    .map((b) => chip(b.url, b.id.replace(/^MASTG-BEST-/, 'BEST-'), `${b.id}: ${b.title || ''}`, 'best', b.id))
    .join('');

  return `<div class="security-finding-detail security-finding-mastg" onclick="event.stopPropagation()">
    <div class="mas-chain-head">
      <span class="security-finding-k">OWASP MAS</span>
    </div>
    <div class="mas-chain">
      ${hasMasvs ? `<div class="mas-chain-row"><span class="mas-chain-label">MASVS</span><div class="mas-chip-row">${masvsChips}</div></div>` : ''}
      ${hasMaswe ? `<div class="mas-chain-row"><span class="mas-chain-label">MASWE</span><div class="mas-chip-row">${masweChips}</div></div>` : ''}
      ${profileChips ? `<div class="mas-chain-row"><span class="mas-chain-label">Profile</span><div class="mas-chip-row">${profileChips}</div></div>` : ''}
      ${testChips ? `<div class="mas-chain-row"><span class="mas-chain-label">TEST</span><div class="mas-chip-row">${testChips}</div></div>` : ''}
      <div class="mas-chain-row"><span class="mas-chain-label">KNOW</span><div class="mas-chip-row">${knowChips}</div></div>
      ${bestChips ? `<div class="mas-chain-row"><span class="mas-chain-label">BEST</span><div class="mas-chip-row">${bestChips}</div></div>` : ''}
    </div>
  </div>`;
}

/**
 * OWASP MASTG Knowledge Base helpers for the Security scan UI.
 * Catalog: https://mas.owasp.org/MASTG/knowledge/
 * Article URLs: https://mas.owasp.org/MASTG-KNOW-NNNN
 */

export const MASTG_KNOWLEDGE_INDEX = 'https://mas.owasp.org/MASTG/knowledge/';

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
  'MASTG-KNOW-0132': { title: 'Android Activities', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0133': { title: 'Android Services', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0134': { title: 'Android Broadcast Receivers', category: 'MASVS-PLATFORM' },
  'MASTG-KNOW-0135': { title: 'Virtual Devices Detection', category: 'MASVS-RESILIENCE' },
  'MASTG-KNOW-0142': { title: 'Android DataStore', category: 'MASVS-STORAGE' },
};

/** Prefix / keyword → MASTG-KNOW IDs (rule_id, vuln category, message). */
const RULE_HINTS = [
  [/biometric|fingerprint|local.?auth|device.?credential|passcode/i, ['MASTG-KNOW-0001']],
  [/debuggable|allow.?debug/i, ['MASTG-KNOW-0007']],
  [/debugger|tracerpid|ptrace|anti.?debug/i, ['MASTG-KNOW-0008', 'MASTG-KNOW-0028']],
  [/strictmode/i, ['MASTG-KNOW-0009']],
  [/key.?gen|keygen|asymmetric.?key|key.?length|keystore|keychain|crypto.?key|hardcoded.?crypto/i, ['MASTG-KNOW-0012', 'MASTG-KNOW-0043', 'MASTG-KNOW-0047']],
  [/random|entropy|securerandom/i, ['MASTG-KNOW-0013']],
  [/network.?security|cleartext|trust.?anchor|insecure.?trust/i, ['MASTG-KNOW-0014']],
  [/hostname.?verif|ssl.?error|checkservertrusted|certificate.?pin|ssl.?socket/i, ['MASTG-KNOW-0015', 'MASTG-KNOW-0014']],
  [/permission/i, ['MASTG-KNOW-0017']],
  [/webview|javascript.?interface|file.?access|safebrowsing|cookie/i, ['MASTG-KNOW-0018']],
  [/deeplink|deep.?link|autoverify|custom.?scheme|intent.?filter/i, ['MASTG-KNOW-0019']],
  [/content.?provider|provider.?exported|fileprovider/i, ['MASTG-KNOW-0117', 'MASTG-KNOW-0020']],
  [/serializ|object.?input|parcelable/i, ['MASTG-KNOW-0021']],
  [/overlay|system.?alert.?window|draw.?over/i, ['MASTG-KNOW-0022']],
  [/sdk.?version|target.?sdk|min.?sdk|enforced.?updat/i, ['MASTG-KNOW-0023']],
  [/pending.?intent/i, ['MASTG-KNOW-0024']],
  [/implicit.?intent|intent.?leak/i, ['MASTG-KNOW-0025', 'MASTG-KNOW-0020']],
  [/broadcast|receiver/i, ['MASTG-KNOW-0134', 'MASTG-KNOW-0020']],
  [/ipc|exported.?activit|exported.?service/i, ['MASTG-KNOW-0020', 'MASTG-KNOW-0132']],
  [/root.?detect|jailbreak/i, ['MASTG-KNOW-0027']],
  [/emulator|virtual.?device/i, ['MASTG-KNOW-0031', 'MASTG-KNOW-0135']],
  [/obfuscat/i, ['MASTG-KNOW-0033']],
  [/play.?integrity|safety.?net|device.?binding/i, ['MASTG-KNOW-0035', 'MASTG-KNOW-0034']],
  [/shared.?prefer|local.?storage|datastore/i, ['MASTG-KNOW-0036', 'MASTG-KNOW-0142']],
  [/sql.?inject|sqlite|contentprovider.*sql/i, ['MASTG-KNOW-0037']],
  [/sqlcipher/i, ['MASTG-KNOW-0038']],
  [/firebase/i, ['MASTG-KNOW-0039']],
  [/realm/i, ['MASTG-KNOW-0040']],
  [/external.?storage|shared.?storage|mediastore|getexternal/i, ['MASTG-KNOW-0042']],
  [/internal.?storage|getfilesdir|openfileoutput/i, ['MASTG-KNOW-0041']],
  [/logcat|logging|android\.util\.log/i, ['MASTG-KNOW-0049']],
  [/backup|allowbackup|fullbackup|dataextraction/i, ['MASTG-KNOW-0050']],
  [/screenshot|flag_secure|secure.?flag/i, ['MASTG-KNOW-0053']],
  [/notification/i, ['MASTG-KNOW-0054']],
  [/keyboard.?cache|input.?type|textpassword|textnonsuggestion/i, ['MASTG-KNOW-0055']],
  [/input.?field|edittext|autofill/i, ['MASTG-KNOW-0052']],
  [/zip.?slip|path.?traversal|zipentry/i, ['MASTG-KNOW-0042', 'MASTG-KNOW-0041']],
  [/custom.?tabs/i, ['MASTG-KNOW-0018']],
  [/encryption|cipher|aes|des|rc4|broken.?encrypt/i, ['MASTG-KNOW-0012', 'MASTG-KNOW-0011']],
  [/tracker|analytics|third.?party.?service/i, ['MASTG-KNOW-0026']],
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
  const blob = [
    ctx.ruleId,
    ctx.category,
    ctx.vulnClass,
    ctx.title,
    ctx.message,
  ]
    .filter(Boolean)
    .join(' ');

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
 * HTML block with MASTG knowledge links (stopPropagation on click).
 * @param {{ ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string }} ctx
 * @param {{ escapeHtml: (s: string) => string, escapeAttr: (s: string) => string }} esc
 */
export function renderMastgKnowledgeHtml(ctx, esc) {
  const links = resolveMastgKnowledge(ctx);
  const masvs = extractMasvsTags([ctx.message, ctx.title, ctx.ruleId].filter(Boolean).join(' '));
  if (!links.length && !masvs.length && !/^mastg-/i.test(String(ctx.ruleId || ''))) {
    return '';
  }
  const badges = masvs
    .map(
      (t) =>
        `<span class="security-badge mastg-masvs" title="OWASP MASVS control">${esc.escapeHtml(t)}</span>`
    )
    .join('');
  const knowLinks = links.length
    ? links
        .map(
          (l) =>
            `<a class="mastg-know-link" href="${esc.escapeAttr(l.url)}" target="_blank" rel="noopener noreferrer" data-mastg-know="${esc.escapeAttr(l.id)}" title="${esc.escapeAttr(`${l.id}: ${l.title}`)}">${esc.escapeHtml(l.id)}</a><span class="muted"> ${esc.escapeHtml(l.title)}</span>`
        )
        .join('<br>')
    : `<a class="mastg-know-link" href="${esc.escapeAttr(MASTG_KNOWLEDGE_INDEX)}" target="_blank" rel="noopener noreferrer">MASTG Knowledge Base</a>`;
  return `<div class="security-finding-detail security-finding-mastg" onclick="event.stopPropagation()">
    <span class="security-finding-k">MASTG</span> ${badges}
    <div class="mastg-know-links">${knowLinks}
      <div class="muted mastg-know-index"><a class="mastg-know-link" href="${esc.escapeAttr(MASTG_KNOWLEDGE_INDEX)}" target="_blank" rel="noopener noreferrer">Knowledge index →</a></div>
    </div>
  </div>`;
}

/**
 * OWASP MASWE / MASVS / MASTG helpers for Security UI display.
 * Catalog resolution lives natively in dex-decompiler (`detectors/mas.rs` → enrich_mas);
 * findings carry `maswe` / `masvs` / `mastg_know` / `mastg_best`. This module keeps
 * chip rendering, graph layout, family colors, and a JS fallback for older caches.
 */

export const MASWE_INDEX = 'https://mas.owasp.org/MASWE/';
export const MASTG_BEST_INDEX = 'https://mas.owasp.org/MASTG/best-practices/';
export const MASTG_DEMO_INDEX = 'https://mas.owasp.org/MASTG/demos/';
export const MASTG_TEST_INDEX = 'https://mas.owasp.org/MASTG/tests/';

export {
  MAS_PROFILE_IDS,
  MAS_PROFILE_META,
  MASWE_PROFILES,
  MASWE_TO_TESTS,
  MASTG_TEST_ANDROID,
} from './mas-catalog.js';
import {
  MAS_PROFILE_IDS,
  MAS_PROFILE_META,
  MASWE_PROFILES,
  MASWE_TO_TESTS,
  MASTG_TEST_ANDROID,
} from './mas-catalog.js';

/**
 * Official MASVS family chip colors from mas.owasp.org/stylesheets/extra.css
 * (--tag-color-masvs-*). MASWE entries inherit the color of their MASVS family.
 */
export const MASVS_FAMILY_COLORS = {
  'MASVS-STORAGE': '#DF5C8D',
  'MASVS-CRYPTO': '#F65928',
  'MASVS-AUTH': '#F09236',
  'MASVS-NETWORK': '#F2C200',
  'MASVS-PLATFORM': '#4FB991',
  'MASVS-CODE': '#5FACD3',
  'MASVS-RESILIENCE': '#317CC0',
  'MASVS-PRIVACY': '#8B5F9E',
};

/** @type {Record<string, { title: string, family: string }>} */
export const MASWE_CATALOG = {
  'MASWE-0001': { title: 'Sensitive Data Stored Unencrypted in Private Storage', family: 'MASVS-STORAGE' },
  'MASWE-0002': { title: 'Sensitive Data Stored Unencrypted Outside of Private Storage', family: 'MASVS-STORAGE' },
  'MASWE-0003': { title: 'Cryptographic Keys Stored Outside of Platform Keystore', family: 'MASVS-STORAGE' },
  'MASWE-0004': { title: 'Sensitive Data Hardcoded in the App Package', family: 'MASVS-STORAGE' },
  'MASWE-0005': { title: 'Insertion of Sensitive Data into Logs', family: 'MASVS-STORAGE' },
  'MASWE-0006': { title: 'Sensitive Data Not Excluded From Backup', family: 'MASVS-STORAGE' },
  'MASWE-0007': { title: 'Improper Encryption', family: 'MASVS-CRYPTO' },
  'MASWE-0008': { title: 'Improper Hashing', family: 'MASVS-CRYPTO' },
  'MASWE-0009': { title: 'Improper Use of Message Authentication Code (MAC)', family: 'MASVS-CRYPTO' },
  'MASWE-0010': { title: 'Improper Generation of Cryptographic Signatures', family: 'MASVS-CRYPTO' },
  'MASWE-0011': { title: 'Improper Verification of Cryptographic Signature', family: 'MASVS-CRYPTO' },
  'MASWE-0012': { title: 'Improper Random Number Generation', family: 'MASVS-CRYPTO' },
  'MASWE-0013': { title: 'Improper Cryptographic Key Generation', family: 'MASVS-CRYPTO' },
  'MASWE-0014': { title: 'Improper Cryptographic Key Derivation', family: 'MASVS-CRYPTO' },
  'MASWE-0015': { title: 'Cryptographic Key Rotation Not Implemented', family: 'MASVS-CRYPTO' },
  'MASWE-0016': { title: 'Cryptographic Key Access Not Restricted', family: 'MASVS-CRYPTO' },
  'MASWE-0017': { title: 'Device Secure Lock Not Enforced', family: 'MASVS-CRYPTO' },
  'MASWE-0018': { title: 'Lack of Authentication or Authorization on App Components', family: 'MASVS-AUTH' },
  'MASWE-0019': { title: 'Lack of Auto-fill Support for Credential Providers', family: 'MASVS-AUTH' },
  'MASWE-0020': { title: 'Local Authentication Can Be Bypassed', family: 'MASVS-AUTH' },
  'MASWE-0021': { title: 'Fallback to Non-biometric Credentials Allowed for Sensitive Transactions', family: 'MASVS-AUTH' },
  'MASWE-0022': { title: 'Crypto Keys Not Invalidated on New Biometric Enrollment', family: 'MASVS-AUTH' },
  'MASWE-0023': { title: 'Step-Up Authentication Not Implemented for Sensitive Actions', family: 'MASVS-AUTH' },
  'MASWE-0024': { title: 'Sensitive Data Accessible After Session Termination', family: 'MASVS-AUTH' },
  'MASWE-0025': { title: 'Lack of Non-Repudiation for Critical Actions', family: 'MASVS-AUTH' },
  'MASWE-0026': { title: 'Network Traffic Not Encrypted', family: 'MASVS-NETWORK' },
  'MASWE-0027': { title: 'Insecure Certificate Validation', family: 'MASVS-NETWORK' },
  'MASWE-0028': { title: 'Insecure Identity Pinning', family: 'MASVS-NETWORK' },
  'MASWE-0029': { title: 'Insecure Deep Links', family: 'MASVS-PLATFORM' },
  'MASWE-0030': { title: 'Improper Use of the Clipboard', family: 'MASVS-PLATFORM' },
  'MASWE-0031': { title: 'Allowing Untrusted App Extensions', family: 'MASVS-PLATFORM' },
  'MASWE-0032': { title: 'Insecure Intents', family: 'MASVS-PLATFORM' },
  'MASWE-0033': { title: 'Sensitive Native Functionality Exposed in WebViews', family: 'MASVS-PLATFORM' },
  'MASWE-0034': { title: 'WebViews Allow Access to Local Resources with Untrusted Content', family: 'MASVS-PLATFORM' },
  'MASWE-0035': { title: 'WebViews Loading Untrusted Content', family: 'MASVS-PLATFORM' },
  'MASWE-0036': { title: 'Unnecessary Exposure of Sensitive Data via the User Interface', family: 'MASVS-PLATFORM' },
  'MASWE-0037': { title: 'Unnecessary Exposure of Sensitive Data via Notifications', family: 'MASVS-PLATFORM' },
  'MASWE-0038': { title: 'Insufficient Protection of Sensitive Data from Screenshots or Screen Recordings', family: 'MASVS-PLATFORM' },
  'MASWE-0039': { title: 'App Vulnerable to Overlay Attacks', family: 'MASVS-PLATFORM' },
  'MASWE-0040': { title: 'Sensitive Data Leaked via Accessibility Services', family: 'MASVS-PLATFORM' },
  'MASWE-0041': { title: 'Running on a Recent Platform Version Not Ensured', family: 'MASVS-CODE' },
  'MASWE-0042': { title: 'Latest Platform Version Not Targeted', family: 'MASVS-CODE' },
  'MASWE-0043': { title: 'Enforced Updating Not Implemented', family: 'MASVS-CODE' },
  'MASWE-0044': { title: 'Dependencies with Known Vulnerabilities', family: 'MASVS-CODE' },
  'MASWE-0045': { title: 'Compiler-Provided Security Features Not Used', family: 'MASVS-CODE' },
  'MASWE-0046': { title: 'Use of Deprecated APIs or Functionality', family: 'MASVS-CODE' },
  'MASWE-0047': { title: 'Using Non-Standard APIs for Security-Critical Functionality', family: 'MASVS-CODE' },
  'MASWE-0048': { title: 'Malicious Code Included in the App', family: 'MASVS-CODE' },
  'MASWE-0049': { title: 'Unsafe Dynamic Code Loading', family: 'MASVS-CODE' },
  'MASWE-0050': { title: 'Unsafe Handling of Untrusted Data', family: 'MASVS-CODE' },
  'MASWE-0051': { title: 'Root/Jailbreak Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0052': { title: 'App Virtualization Environment Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0053': { title: 'Emulated or Virtual Device Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0054': { title: 'Device Attestation Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0055': { title: 'Malware Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0056': { title: 'App Attestation Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0057': { title: 'App Resources Integrity Not Verified', family: 'MASVS-RESILIENCE' },
  'MASWE-0058': { title: 'Runtime Code Integrity Not Verified', family: 'MASVS-RESILIENCE' },
  'MASWE-0059': { title: 'Code Obfuscation Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0060': { title: 'Resource Obfuscation Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0061': { title: 'Debug Artifacts Not Removed', family: 'MASVS-RESILIENCE' },
  'MASWE-0062': { title: 'No Application-Level Payload Encryption', family: 'MASVS-RESILIENCE' },
  'MASWE-0063': { title: 'Debug Mechanisms Not Disabled', family: 'MASVS-RESILIENCE' },
  'MASWE-0064': { title: 'Debugger Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0065': { title: 'Dynamic Analysis Tools Detection Not Implemented', family: 'MASVS-RESILIENCE' },
  'MASWE-0066': { title: 'Inadequate Permission Management', family: 'MASVS-PRIVACY' },
  'MASWE-0067': { title: 'Lack of Anonymization or Pseudonymisation Measures', family: 'MASVS-PRIVACY' },
  'MASWE-0068': { title: 'Incorrect Use of Identifiers for User Tracking', family: 'MASVS-PRIVACY' },
  'MASWE-0069': { title: 'Usage of Non-Privacy-Preserving Functionality', family: 'MASVS-PRIVACY' },
  'MASWE-0070': { title: 'Inadequate Awareness for Privacy Relevant Actions', family: 'MASVS-PRIVACY' },
  'MASWE-0071': { title: 'Inadequate Defaults for Privacy Relevant Actions', family: 'MASVS-PRIVACY' },
  'MASWE-0072': { title: 'Inadequate Privacy Policy', family: 'MASVS-PRIVACY' },
  'MASWE-0073': { title: 'Inadequate Data Collection Declarations', family: 'MASVS-PRIVACY' },
  'MASWE-0074': { title: 'Inadequate Tracking Domains Declarations', family: 'MASVS-PRIVACY' },
  'MASWE-0075': { title: 'Non-Reproducible Builds', family: 'MASVS-PRIVACY' },
  'MASWE-0076': { title: 'Lack of Proper Data Management Controls', family: 'MASVS-PRIVACY' },
  'MASWE-0077': { title: 'Inadequate Data Visibility Controls', family: 'MASVS-PRIVACY' },
  'MASWE-0078': { title: 'Inadequate or Ambiguous User Consent Mechanisms', family: 'MASVS-PRIVACY' },
};

/** CSS slug for a MASVS family, e.g. MASVS-STORAGE → storage */
export function masvsFamilySlug(family) {
  const m = String(family || '').match(/^MASVS-([A-Z]+)$/i);
  return m ? m[1].toLowerCase() : '';
}

/** Hex color for a MASVS family (or a MASWE id that belongs to one). */
export function masvsFamilyColor(familyOrMasweId) {
  const raw = String(familyOrMasweId || '');
  if (MASVS_FAMILY_COLORS[raw]) return MASVS_FAMILY_COLORS[raw];
  const meta = MASWE_CATALOG[raw];
  if (meta?.family && MASVS_FAMILY_COLORS[meta.family]) return MASVS_FAMILY_COLORS[meta.family];
  const fam = raw.match(/MASVS-([A-Z]+)/i);
  if (fam) {
    const key = `MASVS-${fam[1].toUpperCase()}`;
    if (MASVS_FAMILY_COLORS[key]) return MASVS_FAMILY_COLORS[key];
  }
  return MASVS_FAMILY_COLORS['MASVS-PLATFORM'];
}

/** Short label for chips / graph: MASVS-STORAGE → STORAGE */
export function masvsFamilyShort(family) {
  const m = String(family || '').match(/^MASVS-([A-Z]+)$/i);
  return m ? m[1].toUpperCase() : String(family || '');
}

/**
 * Docs URL for a MASVS control or family.
 * Controls: https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/
 * Families fall back to the first control (…-1) — family pages do not exist.
 */
export function masvsControlUrl(tagOrFamily) {
  const raw = String(tagOrFamily || '').toUpperCase().trim();
  const control = raw.match(/^(MASVS-[A-Z]+)-(\d+)$/);
  if (control) {
    return `https://mas.owasp.org/MASVS/controls/${control[1]}-${control[2]}/`;
  }
  const fam = raw.match(/^(MASVS-[A-Z]+)$/);
  if (fam && MASVS_FAMILY_COLORS[fam[1]]) {
    return `https://mas.owasp.org/MASVS/controls/${fam[1]}-1/`;
  }
  return 'https://mas.owasp.org/MASVS/';
}

/** @deprecated use masvsControlUrl — kept as alias for family/graph open-docs */
export function masvsFamilyUrl(family) {
  return masvsControlUrl(family);
}

/** Ordered MASVS family ids (catalog order). */
export const MASVS_FAMILY_ORDER = Object.keys(MASVS_FAMILY_COLORS);

/** Android-relevant best practices (subset used for finding deep-links). */
export const MASTG_BEST_ANDROID = {
  'MASTG-BEST-0001': { title: 'Use Secure Random Number Generator APIs' },
  'MASTG-BEST-0002': { title: 'Remove Logging Code' },
  'MASTG-BEST-0004': { title: 'Exclude Sensitive Data from Backups' },
  'MASTG-BEST-0005': { title: 'Use Secure Encryption Modes' },
  'MASTG-BEST-0007': { title: 'Debuggable Flag Disabled in the AndroidManifest' },
  'MASTG-BEST-0008': { title: 'Debugging Disabled for WebViews' },
  'MASTG-BEST-0009': { title: 'Use Secure Encryption Algorithms' },
  'MASTG-BEST-0010': { title: 'Use Up-to-Date minSdkVersion' },
  'MASTG-BEST-0011': { title: 'Securely Load File Content in a WebView' },
  'MASTG-BEST-0012': { title: 'Disable JavaScript in WebViews' },
  'MASTG-BEST-0013': { title: 'Disable Content Provider Access in WebViews' },
  'MASTG-BEST-0014': { title: 'Preventing Screenshots and Screen Recording' },
  'MASTG-BEST-0016': { title: 'Use SECURE_FLAG to Prevent Screenshots and Screen Recording' },
  'MASTG-BEST-0019': { title: 'Use Non-Caching Input Types for Sensitive Fields' },
  'MASTG-BEST-0020': { title: 'Update the GMS Security Provider' },
  'MASTG-BEST-0022': { title: 'Disable Verbose and Debug Logging in Production Builds' },
  'MASTG-BEST-0023': { title: 'Exclude Sensitive Information from Backups' },
  'MASTG-BEST-0024': { title: 'Store Data Encrypted in App Sandbox Directory' },
  'MASTG-BEST-0026': { title: 'Preventing Keyboard Caching for Sensitive Text Inputs' },
  'MASTG-BEST-0027': { title: 'Preventing Sensitive Data Exposure in Notifications' },
  'MASTG-BEST-0029': { title: 'Implementing Resilience and RASP Signals' },
  'MASTG-BEST-0030': { title: 'Implementing Root Detection' },
  'MASTG-BEST-0031': { title: 'Enforce Strong Biometrics for Sensitive Operations' },
  'MASTG-BEST-0036': { title: 'Use Cryptographic Binding for Biometric Authentication' },
  'MASTG-BEST-0037': { title: 'Invalidate Biometric Keys on Enrollment Changes' },
  'MASTG-BEST-0038': { title: 'Require Explicit User Confirmation for Biometric Authentication' },
  'MASTG-BEST-0039': { title: 'Prevent SQL Injection in ContentProviders' },
  'MASTG-BEST-0040': { title: 'Preventing Overlay Attacks' },
};

/**
 * Official MASWE → MASVS v2 control mappings (from OWASP/maswe frontmatter mappings.masvs-v2).
 * Control pages: https://mas.owasp.org/MASVS/controls/MASVS-XXXX-N/
 * @type {Record<string, string[]>}
 */
export const MASWE_TO_MASVS = {
  'MASWE-0001': ['MASVS-STORAGE-1', 'MASVS-STORAGE-2', 'MASVS-CRYPTO-2'],
  'MASWE-0002': ['MASVS-STORAGE-1', 'MASVS-STORAGE-2'],
  'MASWE-0003': ['MASVS-STORAGE-1', 'MASVS-CRYPTO-2'],
  'MASWE-0004': ['MASVS-STORAGE-1'],
  'MASWE-0005': ['MASVS-STORAGE-2'],
  'MASWE-0006': ['MASVS-STORAGE-2'],
  'MASWE-0007': ['MASVS-CRYPTO-1', 'MASVS-CRYPTO-2'],
  'MASWE-0008': ['MASVS-CRYPTO-1'],
  'MASWE-0009': ['MASVS-CRYPTO-1', 'MASVS-CRYPTO-2'],
  'MASWE-0010': ['MASVS-CRYPTO-1', 'MASVS-CRYPTO-2'],
  'MASWE-0011': ['MASVS-CRYPTO-1'],
  'MASWE-0012': ['MASVS-CRYPTO-1'],
  'MASWE-0013': ['MASVS-CRYPTO-2'],
  'MASWE-0014': ['MASVS-CRYPTO-2'],
  'MASWE-0015': ['MASVS-CRYPTO-2'],
  'MASWE-0016': ['MASVS-CRYPTO-2', 'MASVS-AUTH-2', 'MASVS-AUTH-3'],
  'MASWE-0017': ['MASVS-CRYPTO-2'],
  'MASWE-0018': ['MASVS-AUTH-1', 'MASVS-PLATFORM-1', 'MASVS-STORAGE-2'],
  'MASWE-0019': ['MASVS-AUTH-1', 'MASVS-AUTH-3'],
  'MASWE-0020': ['MASVS-AUTH-2', 'MASVS-CRYPTO-2'],
  'MASWE-0021': ['MASVS-AUTH-2'],
  'MASWE-0022': ['MASVS-AUTH-2', 'MASVS-CRYPTO-2'],
  'MASWE-0023': ['MASVS-AUTH-3', 'MASVS-PLATFORM-3'],
  'MASWE-0024': ['MASVS-AUTH-3'],
  'MASWE-0025': ['MASVS-AUTH-3'],
  'MASWE-0026': ['MASVS-NETWORK-1'],
  'MASWE-0027': ['MASVS-NETWORK-1'],
  'MASWE-0028': ['MASVS-NETWORK-2'],
  'MASWE-0029': ['MASVS-PLATFORM-1', 'MASVS-STORAGE-2', 'MASVS-CODE-4'],
  'MASWE-0030': ['MASVS-PLATFORM-1', 'MASVS-STORAGE-2'],
  'MASWE-0031': ['MASVS-PLATFORM-1', 'MASVS-STORAGE-2'],
  'MASWE-0032': ['MASVS-PLATFORM-1', 'MASVS-STORAGE-2'],
  'MASWE-0033': ['MASVS-PLATFORM-2', 'MASVS-STORAGE-2'],
  'MASWE-0034': ['MASVS-PLATFORM-2', 'MASVS-STORAGE-2', 'MASVS-CODE-4'],
  'MASWE-0035': ['MASVS-PLATFORM-2', 'MASVS-CODE-4'],
  'MASWE-0036': ['MASVS-PLATFORM-3', 'MASVS-STORAGE-2'],
  'MASWE-0037': ['MASVS-PLATFORM-3', 'MASVS-STORAGE-2'],
  'MASWE-0038': ['MASVS-PLATFORM-3', 'MASVS-STORAGE-2'],
  'MASWE-0039': ['MASVS-PLATFORM-3', 'MASVS-CODE-1'],
  'MASWE-0040': ['MASVS-PLATFORM-3', 'MASVS-STORAGE-2'],
  'MASWE-0041': ['MASVS-CODE-1'],
  'MASWE-0042': ['MASVS-CODE-1'],
  'MASWE-0043': ['MASVS-CODE-2'],
  'MASWE-0044': ['MASVS-CODE-3'],
  'MASWE-0045': ['MASVS-CODE-3', 'MASVS-CODE-4'],
  'MASWE-0046': ['MASVS-CODE-3', 'MASVS-CRYPTO-2'],
  'MASWE-0047': ['MASVS-CODE-3', 'MASVS-AUTH-1', 'MASVS-CRYPTO-1', 'MASVS-NETWORK-1'],
  'MASWE-0048': ['MASVS-CODE-3'],
  'MASWE-0049': ['MASVS-CODE-4'],
  'MASWE-0050': ['MASVS-CODE-4'],
  'MASWE-0051': ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-4'],
  'MASWE-0052': ['MASVS-RESILIENCE-1'],
  'MASWE-0053': ['MASVS-RESILIENCE-1', 'MASVS-RESILIENCE-4'],
  'MASWE-0054': ['MASVS-RESILIENCE-1'],
  'MASWE-0055': ['MASVS-RESILIENCE-2'],
  'MASWE-0056': ['MASVS-RESILIENCE-2'],
  'MASWE-0057': ['MASVS-RESILIENCE-2', 'MASVS-CODE-4'],
  'MASWE-0058': ['MASVS-RESILIENCE-2'],
  'MASWE-0059': ['MASVS-RESILIENCE-3'],
  'MASWE-0060': ['MASVS-RESILIENCE-3'],
  'MASWE-0061': ['MASVS-RESILIENCE-3'],
  'MASWE-0062': ['MASVS-RESILIENCE-3', 'MASVS-NETWORK-1'],
  'MASWE-0063': ['MASVS-RESILIENCE-4', 'MASVS-PLATFORM-2'],
  'MASWE-0064': ['MASVS-RESILIENCE-4'],
  'MASWE-0065': ['MASVS-RESILIENCE-4'],
  'MASWE-0066': ['MASVS-PRIVACY-1'],
  'MASWE-0067': ['MASVS-PRIVACY-2'],
  'MASWE-0068': ['MASVS-PRIVACY-2'],
  'MASWE-0069': ['MASVS-PRIVACY-2'],
  'MASWE-0070': ['MASVS-PRIVACY-2'],
  'MASWE-0071': ['MASVS-PRIVACY-2'],
  'MASWE-0072': ['MASVS-PRIVACY-3'],
  'MASWE-0073': ['MASVS-PRIVACY-3', 'MASVS-PRIVACY-1'],
  'MASWE-0074': ['MASVS-PRIVACY-3'],
  'MASWE-0075': ['MASVS-PRIVACY-3'],
  'MASWE-0076': ['MASVS-PRIVACY-4'],
  'MASWE-0077': ['MASVS-PRIVACY-4'],
  'MASWE-0078': ['MASVS-PRIVACY-4'],
};
/**
 * MASWE → related Android MASTG-KNOW / MASTG-BEST (curated for static-scan UI).
 * @type {Record<string, { know?: string[], best?: string[] }>}
 */
export const MASWE_TO_MASTG = {
  'MASWE-0001': { know: ['MASTG-KNOW-0036', 'MASTG-KNOW-0041', 'MASTG-KNOW-0142'], best: ['MASTG-BEST-0024'] },
  'MASWE-0002': { know: ['MASTG-KNOW-0042'], best: ['MASTG-BEST-0024'] },
  'MASWE-0003': { know: ['MASTG-KNOW-0043', 'MASTG-KNOW-0047'], best: [] },
  'MASWE-0004': { know: ['MASTG-KNOW-0047', 'MASTG-KNOW-0012'], best: [] },
  'MASWE-0005': { know: ['MASTG-KNOW-0049'], best: ['MASTG-BEST-0002', 'MASTG-BEST-0022'] },
  'MASWE-0006': { know: ['MASTG-KNOW-0050'], best: ['MASTG-BEST-0004', 'MASTG-BEST-0023'] },
  'MASWE-0007': { know: ['MASTG-KNOW-0012', 'MASTG-KNOW-0011'], best: ['MASTG-BEST-0005', 'MASTG-BEST-0009'] },
  'MASWE-0009': { know: ['MASTG-KNOW-0012'], best: ['MASTG-BEST-0005'] },
  'MASWE-0012': { know: ['MASTG-KNOW-0013'], best: ['MASTG-BEST-0001'] },
  'MASWE-0013': { know: ['MASTG-KNOW-0012', 'MASTG-KNOW-0043'], best: ['MASTG-BEST-0009'] },
  'MASWE-0016': { know: ['MASTG-KNOW-0043', 'MASTG-KNOW-0001'], best: ['MASTG-BEST-0031', 'MASTG-BEST-0036'] },
  'MASWE-0017': { know: ['MASTG-KNOW-0001'], best: ['MASTG-BEST-0031'] },
  'MASWE-0018': { know: ['MASTG-KNOW-0020', 'MASTG-KNOW-0117', 'MASTG-KNOW-0132'], best: [] },
  'MASWE-0020': { know: ['MASTG-KNOW-0001'], best: ['MASTG-BEST-0036'] },
  'MASWE-0021': { know: ['MASTG-KNOW-0001'], best: ['MASTG-BEST-0031'] },
  'MASWE-0022': { know: ['MASTG-KNOW-0001', 'MASTG-KNOW-0043'], best: ['MASTG-BEST-0037'] },
  'MASWE-0027': { know: ['MASTG-KNOW-0014', 'MASTG-KNOW-0015'], best: [] },
  'MASWE-0028': { know: ['MASTG-KNOW-0015'], best: [] },
  'MASWE-0029': { know: ['MASTG-KNOW-0019'], best: [] },
  'MASWE-0032': { know: ['MASTG-KNOW-0020', 'MASTG-KNOW-0025', 'MASTG-KNOW-0024'], best: [] },
  'MASWE-0033': { know: ['MASTG-KNOW-0018'], best: ['MASTG-BEST-0012'] },
  'MASWE-0034': { know: ['MASTG-KNOW-0018'], best: ['MASTG-BEST-0011', 'MASTG-BEST-0013'] },
  'MASWE-0035': { know: ['MASTG-KNOW-0018'], best: ['MASTG-BEST-0008', 'MASTG-BEST-0012'] },
  'MASWE-0036': { know: ['MASTG-KNOW-0052', 'MASTG-KNOW-0055'], best: ['MASTG-BEST-0019', 'MASTG-BEST-0026'] },
  'MASWE-0037': { know: ['MASTG-KNOW-0054'], best: ['MASTG-BEST-0027'] },
  'MASWE-0038': { know: ['MASTG-KNOW-0053'], best: ['MASTG-BEST-0014', 'MASTG-BEST-0016'] },
  'MASWE-0039': { know: ['MASTG-KNOW-0022'], best: ['MASTG-BEST-0040'] },
  'MASWE-0041': { know: ['MASTG-KNOW-0023'], best: ['MASTG-BEST-0010'] },
  'MASWE-0042': { know: ['MASTG-KNOW-0023'], best: ['MASTG-BEST-0010'] },
  'MASWE-0049': { know: ['MASTG-KNOW-0005'], best: [] },
  'MASWE-0050': { know: ['MASTG-KNOW-0021', 'MASTG-KNOW-0117'], best: ['MASTG-BEST-0039'] },
  'MASWE-0051': { know: ['MASTG-KNOW-0027'], best: ['MASTG-BEST-0030'] },
  'MASWE-0053': { know: ['MASTG-KNOW-0031', 'MASTG-KNOW-0135'], best: ['MASTG-BEST-0029'] },
  'MASWE-0058': { know: ['MASTG-KNOW-0032', 'MASTG-KNOW-0118'], best: ['MASTG-BEST-0029'] },
  'MASWE-0061': { know: ['MASTG-KNOW-0007', 'MASTG-KNOW-0008'], best: ['MASTG-BEST-0007'] },
  'MASWE-0063': { know: ['MASTG-KNOW-0007', 'MASTG-KNOW-0009'], best: ['MASTG-BEST-0007'] },
  'MASWE-0064': { know: ['MASTG-KNOW-0028'], best: ['MASTG-BEST-0029'] },
  'MASWE-0066': { know: ['MASTG-KNOW-0017'], best: [] },
};

/** Keyword / rule hints → MASWE IDs (ordered; first hits preferred). */
const MASWE_HINTS = [
  [/backup|allowbackup|fullbackup|dataextraction|backup.?rules/i, ['MASWE-0006']],
  [/logcat|logging_pii|insecure_logging|android\.util\.log|sensitive.?data.?in.?log/i, ['MASWE-0005']],
  [/hardcoded.?secret|hardcoded.?crypto|secretkeyspec|hardcoded.?aes|hardcoded.?key/i, ['MASWE-0004', 'MASWE-0003']],
  [/shared.?storage|external.?storage|mediastore|getexternal|scoped.?storage/i, ['MASWE-0002']],
  [/shared.?prefer|datastore|sqlite|sqlcipher|internal.?storage|openfileoutput|sandbox/i, ['MASWE-0001']],
  [/broken.?encrypt|encryption.?mode|encryption.?algorithm|weak_crypto|cipher\.getinstance|ecb/i, ['MASWE-0007']],
  [/hmac|mac.?valid/i, ['MASWE-0009']],
  [/non.?random|random.?apis|math\.random|java\.util\.random|securerandom|insufficient.?entropy/i, ['MASWE-0012']],
  [/key.?generation|key.?length|keygenparameterspec|asymmetric.?key/i, ['MASWE-0013']],
  [/security.?provider|providers?\.get/i, ['MASWE-0007']],
  [/keystore|keychain|user.?auth|setuserauthentication/i, ['MASWE-0016', 'MASWE-0003']],
  [/biometric.?device.?credential|device.?credential.?fallback/i, ['MASWE-0021']],
  [/biometric.?invalidat|invalidatedbybiometric/i, ['MASWE-0022']],
  [/biometric|passcode|local.?auth|event.?bound|no.?confirmation|validity.?duration/i, ['MASWE-0020', 'MASWE-0016']],
  [/ssl.?trust|trust.?all|checkservertrusted|hostname.?verif|onreceivedsslerror|trust.?anchor|pinning|network.?security|cleartext/i, ['MASWE-0027', 'MASWE-0028']],
  [/deeplink|deep.?link|autoverify|custom.?scheme|intent.?filter/i, ['MASWE-0029']],
  [/pending.?intent/i, ['MASWE-0032']],
  [/implicit.?intent|intent.?leak|intent.?redirect|intent.?spoof|icc_|ipc_intent|broadcast/i, ['MASWE-0032']],
  [/content.?provider|provider.?exported|fileprovider|sql.?inject/i, ['MASWE-0018', 'MASWE-0050']],
  [/javascript.?interface|js.?bridge|addjavascriptinterface|webview.?bridges/i, ['MASWE-0033']],
  [/webview.?file|file.?access|allowfileaccess|content.?access|webview.?settings/i, ['MASWE-0034']],
  [/webview|loadurl|safebrowsing|webviewclient/i, ['MASWE-0035', 'MASWE-0034']],
  [/keyboard.?cache|input.?type|textpassword|textnonsuggestion|input.?field/i, ['MASWE-0036']],
  [/notification/i, ['MASWE-0037']],
  [/flag.?secure|screenshot|setsecure|recents.?screenshot/i, ['MASWE-0038']],
  [/overlay|system.?alert.?window|hideoverlay|filtertouches/i, ['MASWE-0039']],
  [/minsdk|sdk.?version|target.?sdk/i, ['MASWE-0041', 'MASWE-0042']],
  [/debuggable|strictmode/i, ['MASWE-0061', 'MASWE-0063']],
  [/debugger|tracerpid|ptrace|anti.?debug/i, ['MASWE-0064']],
  [/root.?detect|su.?binary|test.?keys/i, ['MASWE-0051']],
  [/emulator|virtual.?device/i, ['MASWE-0053']],
  [/deserial|object.?input|serializable/i, ['MASWE-0050']],
  [/rce_dynamic|dexclassloader|pathclassloader|dynamic.?code|reflection_rce/i, ['MASWE-0049']],
  [/path.?traversal|zip.?slip|uri.?permission|uri.?grant/i, ['MASWE-0050', 'MASWE-0018']],
  [/permission|dangerous.?android.?permissions/i, ['MASWE-0066']],
];

export function masweUrl(id) {
  const meta = MASWE_CATALOG[id];
  if (!meta) return `${MASWE_INDEX}`;
  return `https://mas.owasp.org/MASWE/${meta.family}/${id}/`;
}

export function mastgTestUrl(id) {
  return `https://mas.owasp.org/${id}`;
}

export function mastgBestUrl(id) {
  return `https://mas.owasp.org/${id}`;
}

/** Official MASWE profiles, excluding vendor extras such as EUDIW. */
export function masweProfiles(id) {
  return (MASWE_PROFILES[id] || []).filter((p) => MAS_PROFILE_IDS.includes(p));
}

export function masProfileLabel(code) {
  return MAS_PROFILE_META[code]?.label || `MAS-${code}`;
}

export function masProfileTitle(code) {
  const meta = MAS_PROFILE_META[code];
  return meta ? `${meta.label} · ${meta.title}` : String(code || '');
}

/** Android MASTG-TEST mappings for a MASWE (static/code first). */
export function masweTests(id) {
  const ids = MASWE_TO_TESTS[id] || [];
  const rank = (types) => (types.includes('static') || types.includes('code') ? 0 : 1);
  return ids
    .map((tid) => {
      const meta = MASTG_TEST_ANDROID[tid] || { title: tid, type: [] };
      return { id: tid, title: meta.title || tid, type: meta.type || [], url: mastgTestUrl(tid) };
    })
    .sort((a, b) => rank(a.type) - rank(b.type) || a.id.localeCompare(b.id));
}

export function masweMatchesProfiles(id, selected) {
  if (!selected || !selected.length) return true;
  const have = masweProfiles(id);
  if (!have.length) return false;
  return selected.some((p) => have.includes(p));
}

export function mastgDemoUrl(id) {
  return `https://mas.owasp.org/${id}`;
}

/**
 * Resolve MASWE weaknesses for a finding / rule.
 * @param {{ ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string }} ctx
 * @returns {{ id: string, title: string, family: string, url: string }[]}
 */
export function resolveMaswe(ctx = {}) {
  const blob = [ctx.ruleId, ctx.category, ctx.vulnClass, ctx.title, ctx.message]
    .filter(Boolean)
    .join(' ');
  const ids = new Set();
  for (const [re, list] of MASWE_HINTS) {
    if (re.test(blob)) list.forEach((id) => ids.add(id));
  }
  // MASVS family fallback from message tags
  const fam = String(blob).match(/MASVS-([A-Z]+)/i);
  if (fam && !ids.size) {
    const prefix = `MASVS-${fam[1].toUpperCase()}`;
    for (const [id, meta] of Object.entries(MASWE_CATALOG)) {
      if (meta.family === prefix) ids.add(id);
      if (ids.size >= 2) break;
    }
  }
  const out = [];
  for (const id of ids) {
    const meta = MASWE_CATALOG[id];
    if (!meta) continue;
    out.push({ id, title: meta.title, family: meta.family, url: masweUrl(id) });
  }
  return out.slice(0, 3);
}

/**
 * Full chain: finding → MASVS controls → MASWE → MASTG KNOW/BEST.
 * @param {{ ruleId?: string, category?: string, message?: string, title?: string, vulnClass?: string }} ctx
 * @param {{ id: string, title: string, category: string, url: string }[]} knowLinks
 */
export function resolveMasChain(ctx = {}, knowLinks = []) {
  const maswe = resolveMaswe(ctx);
  const bestIds = new Set();
  const knowIds = new Set(knowLinks.map((k) => k.id));
  const masvsIds = new Set();
  // Controls mentioned explicitly in finding text
  const blob = [ctx.ruleId, ctx.category, ctx.vulnClass, ctx.title, ctx.message]
    .filter(Boolean)
    .join(' ');
  for (const m of String(blob).matchAll(/MASVS-[A-Z]+-\d+/gi)) {
    masvsIds.add(m[0].toUpperCase());
  }
  for (const w of maswe) {
    const map = MASWE_TO_MASTG[w.id];
    if (map) {
      (map.best || []).forEach((id) => bestIds.add(id));
      (map.know || []).forEach((id) => knowIds.add(id));
    }
    (MASWE_TO_MASVS[w.id] || []).forEach((id) => masvsIds.add(id));
  }
  const masvs = [...masvsIds]
    .sort()
    .map((id) => {
      const fam = id.match(/^(MASVS-[A-Z]+)/)?.[1] || '';
      return {
        id,
        family: fam,
        label: id.replace(/^MASVS-/, ''),
        url: masvsControlUrl(id),
      };
    })
    .slice(0, 6);
  const best = [...bestIds]
    .map((id) => {
      const meta = MASTG_BEST_ANDROID[id];
      if (!meta) return null;
      return { id, title: meta.title, url: mastgBestUrl(id) };
    })
    .filter(Boolean)
    .slice(0, 4);
  return { maswe, masvs, best, knowIds: [...knowIds] };
}

/**
 * Build vis-network nodes/edges for Security overview graph.
 * Layers: Findings → finding groups → MASVS family → MASWE → KNOW/BEST
 * @param {{ id: string, label: string, masweIds: string[], count: number }[]} findingGroups
 */
export function buildMasGraph(findingGroups = []) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const addNode = (id, label, group, title, extra = {}) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, group, title: title || label, ...extra });
  };
  const addEdge = (from, to, kind = '') => {
    edges.push({ from, to, arrows: 'to', kind });
  };

  addNode('root-findings', 'Findings', 'root', 'Detected issues', { level: 0 });
  let linked = 0;
  for (const g of findingGroups) {
    const fid = `f:${g.id}`;
    const shortLabel = String(g.label || 'finding').length > 28
      ? `${String(g.label).slice(0, 26)}…`
      : String(g.label || 'finding');
    addNode(fid, `${shortLabel}\n×${g.count}`, 'finding', `${g.label} · ${g.count} finding(s)`, { level: 1 });
    addEdge('root-findings', fid, 'root');
    for (const mid of g.masweIds || []) {
      const meta = MASWE_CATALOG[mid];
      if (!meta) continue;
      linked += 1;
      const family = meta.family;
      const famColor = masvsFamilyColor(family);
      const famSlug = masvsFamilySlug(family);
      addNode(
        family,
        masvsFamilyShort(family),
        'masvs',
        `${family} · click to filter`,
        { level: 2, family, familySlug: famSlug, color: famColor }
      );
      addEdge(fid, family, 'to-family');
      addNode(
        mid,
        mid,
        'maswe',
        `${mid}: ${meta.title} · ${family} · ${masweProfiles(mid).map(masProfileLabel).join(' ') || 'no profile'}`,
        { level: 3, family, familySlug: famSlug, color: famColor }
      );
      addEdge(family, mid, 'to-maswe');
      const map = MASWE_TO_MASTG[mid] || {};
      for (const kid of (map.know || []).slice(0, 2)) {
        addNode(kid, kid.replace('MASTG-KNOW-', 'KNOW-'), 'know', kid, { level: 4 });
        addEdge(mid, kid, 'to-know');
      }
      for (const bid of (map.best || []).slice(0, 2)) {
        addNode(bid, bid.replace('MASTG-BEST-', 'BEST-'), 'best', bid, { level: 4 });
        addEdge(mid, bid, 'to-best');
      }
      for (const test of masweTests(mid).slice(0, 2)) {
        addNode(test.id, test.id.replace('MASTG-TEST-', 'TEST-'), 'test', `${test.id}: ${test.title}`, { level: 4 });
        addEdge(mid, test.id, 'to-test');
      }
    }
  }
  return { nodes, edges, linked };
}

/**
 * Android MASTG demos that static Semgrep/vuln scanning can cover (semgrep-oriented).
 * Runtime/Frida-only demos are intentionally omitted.
 */
export const MASTG_DEMO_STATIC_COVERAGE = [
  { demo: 'MASTG-DEMO-0003', rules: ['mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-public'], topic: 'External storage (public)' },
  { demo: 'MASTG-DEMO-0004', rules: ['mastg-android-data-unencrypted-shared-storage-no-user-interaction-external-api-scoped'], topic: 'External storage (scoped)' },
  { demo: 'MASTG-DEMO-0005', rules: ['mastg-android-data-unencrypted-shared-storage-no-user-interaction-mediastore'], topic: 'MediaStore write' },
  { demo: 'MASTG-DEMO-0007', rules: ['mastg-android-random-apis-insufficient-entropy'], topic: 'Insecure random' },
  { demo: 'MASTG-DEMO-0008', rules: ['mastg-android-non-random-use'], topic: 'Non-random sources' },
  { demo: 'MASTG-DEMO-0012', rules: ['mastg-android-key-generation-with-insufficient-key-length'], topic: 'Weak key length' },
  { demo: 'MASTG-DEMO-0017', rules: ['mastg-android-hardcoded-crypto-keys-usage'], topic: 'Hardcoded AES key' },
  { demo: 'MASTG-DEMO-0022', rules: ['mastg-android-broken-encryption-algorithms'], topic: 'Broken crypto algorithms' },
  { demo: 'MASTG-DEMO-0023', rules: ['mastg-android-broken-encryption-modes'], topic: 'Broken crypto modes' },
  { demo: 'MASTG-DEMO-0025', rules: ['mastg-android-sdk-version', 'mastg-android-minsdkversion'], topic: 'SDK version' },
  { demo: 'MASTG-DEMO-0028', rules: ['mastg-android-device-passcode-present'], topic: 'Device lock' },
  { demo: 'MASTG-DEMO-0029', rules: ['mastg-android-webview-settings'], topic: 'WebView content access' },
  { demo: 'MASTG-DEMO-0032', rules: ['mastg-android-webview-settings'], topic: 'WebView file access' },
  { demo: 'MASTG-DEMO-0033', rules: ['detect-dangerous-android-permissions'], topic: 'Dangerous permissions' },
  { demo: 'MASTG-DEMO-0034', rules: ['mastg-android-backup-manifest-allow-backup', 'mastg-android-backup-manifest-backup-rules'], topic: 'Backup' },
  { demo: 'MASTG-DEMO-0039', rules: ['mastg-android-strictmode'], topic: 'StrictMode' },
  { demo: 'MASTG-DEMO-0040', rules: ['mastg-android-debuggable-flag'], topic: 'Debuggable' },
  { demo: 'MASTG-DEMO-0048', rules: ['mastg-android-ssl-socket-hostnameverifier'], topic: 'SSLSocket hostname' },
  { demo: 'MASTG-DEMO-0054', rules: ['mastg-android-network-checkservertrusted'], topic: 'TrustManager' },
  { demo: 'MASTG-DEMO-0055', rules: ['mastg-android-network-hostname-verification'], topic: 'HostnameVerifier' },
  { demo: 'MASTG-DEMO-0056', rules: ['mastg-android-network-onreceivedsslerror'], topic: 'onReceivedSslError' },
  { demo: 'MASTG-DEMO-0057', rules: ['mastg-android-network-insecure-trust-anchors'], topic: 'Trust anchors' },
  { demo: 'MASTG-DEMO-0058', rules: ['mastg-android-broken-encryption-modes'], topic: 'ECB KeyGen' },
  { demo: 'MASTG-DEMO-0061', rules: ['mastg-android-flag-secure-enable-flags'], topic: 'FLAG_SECURE' },
  { demo: 'MASTG-DEMO-0064', rules: ['mastg-android-non-caching-input-types', 'mastg-android-input-field-usage'], topic: 'Keyboard cache' },
  { demo: 'MASTG-DEMO-0071', rules: ['mastg-android-asymmetric-key-pair-used-for-multiple-purposes'], topic: 'Key multipurpose' },
  { demo: 'MASTG-DEMO-0075', rules: ['mastg-android-hardcoded-security-provider'], topic: 'Security provider' },
  { demo: 'MASTG-DEMO-0078', rules: ['mastg-android-sensitive-data-in-notifications', 'mastg-android-sensitive-data-in-notifications-manifest'], topic: 'Notifications' },
  { demo: 'MASTG-DEMO-0079', rules: ['mastg-android-input-field-usage', 'mastg-android-non-caching-input-types'], topic: 'Sensitive input fields' },
  { demo: 'MASTG-DEMO-0087', rules: ['mastg-android-root-detection-file-checks', 'mastg-android-root-detection-runtime-exec'], topic: 'Root detection' },
  { demo: 'MASTG-DEMO-0089', rules: ['mastg-android-biometric-device-credential-fallback'], topic: 'Biometric fallback' },
  { demo: 'MASTG-DEMO-0090', rules: ['mastg-android-biometric-event-bound'], topic: 'Event-bound biometric' },
  { demo: 'MASTG-DEMO-0091', rules: ['mastg-android-biometric-invalidated-enrollment'], topic: 'Biometric invalidation' },
  { demo: 'MASTG-DEMO-0092', rules: ['mastg-android-biometric-no-confirmation-required'], topic: 'Biometric confirmation' },
  { demo: 'MASTG-DEMO-0093', rules: ['mastg-android-biometric-validity-duration'], topic: 'Biometric validity' },
  { demo: 'MASTG-DEMO-0097', rules: ['mastg-android-webview-bridges-javascriptinterface', 'mastg-android-webview-bridges-setup'], topic: 'JS bridges' },
  { demo: 'MASTG-DEMO-0100', rules: ['mastg-android-object-deserialization'], topic: 'Deserialization' },
  { demo: 'MASTG-DEMO-0102', rules: ['mastg-android-sql-injection-contentprovider'], topic: 'Provider SQLi' },
  { demo: 'MASTG-DEMO-0103', rules: ['mastg-android-overlay-protection-setfiltertoucheswhenobscured', 'mastg-android-overlay-protection-xml-attribute'], topic: 'Overlay protection' },
  { demo: 'MASTG-DEMO-0104', rules: ['mastg-android-system-alert-window-permission'], topic: 'SYSTEM_ALERT_WINDOW' },
  { demo: 'MASTG-DEMO-0105', rules: ['mastg-android-overlay-protection-sethideoverlaywindows', 'mastg-android-overlay-protection-hide-overlay-windows-permission'], topic: 'Hide overlay windows' },
  { demo: 'MASTG-DEMO-0115', rules: ['mastg-android-debugger-checks'], topic: 'JDWP / debugger checks' },
  { demo: 'MASTG-DEMO-0116', rules: ['mastg-android-native-debugger-checks'], topic: 'Native anti-debug' },
  { demo: 'MASTG-DEMO-0120', rules: ['mastg-android-provider-exported-without-permissions'], topic: 'Exported provider' },
  { demo: 'MASTG-DEMO-0122', rules: ['mastg-android-fileprovider-broad-path-scope', 'mastg-android-fileprovider-root-path'], topic: 'FileProvider scope' },
  { demo: 'MASTG-DEMO-0136', rules: ['mastg-android-implicit-intent-internal-communication'], topic: 'Implicit intent IPC' },
  { demo: 'MASTG-DEMO-0138', rules: ['mastg-android-implicit-intent-leaking-extras'], topic: 'Intent extras leak' },
  { demo: 'MASTG-DEMO-0139', rules: ['mastg-android-local-storage-input-validation'], topic: 'Provider path traversal' },
  { demo: 'MASTG-DEMO-0147', rules: ['mastg-android-pendingintent-mutable'], topic: 'PendingIntent' },
  { demo: 'MASTG-DEMO-0151', rules: ['mastg-android-deeplink-autoverify-missing'], topic: 'autoVerify' },
  { demo: 'MASTG-DEMO-0152', rules: ['mastg-android-custom-deeplink-scheme', 'mastg-android-deeplink-unvalidated-parameter'], topic: 'Custom scheme' },
  { demo: 'MASTG-DEMO-0156', rules: ['mastg-android-webview-safebrowsing-disabled-manifest', 'mastg-android-webview-safebrowsing-disabled-code'], topic: 'SafeBrowsing' },
  { demo: 'MASTG-DEMO-0157', rules: ['mastg-android-webviewclient-url-handlers'], topic: 'WebViewClient handlers' },
];

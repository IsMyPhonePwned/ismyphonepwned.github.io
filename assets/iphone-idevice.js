/**
 * Shared WebUSB + idevice-wasm helpers for iphone.html and iphone-advanced.html.
 */
import initIdevice, {
    requestAppleDevice,
    muxLockdownHandshake,
    lockdownQueryType,
    lockdownPair,
    prefetchPairHostKeys,
    pairingIdsFromPlistXml,
    lockdownFetchWithPlistXml,
    lockdownSysdiagnoseList,
    lockdownSysdiagnoseDownload,
    lockdownSysdiagnoseInfo,
    lockdownCrashReportsInfo,
    lockdownBattery,
    lockdownDiagnostics,
    lockdownCrashReports,
    lockdownSyslog,
    lockdownPcap,
    lockdownScreenshot,
} from '../pkg-idevice/idevice_wasm.js';

export const PAIR_STORAGE_KEY = 'idevice-rs.pairRecordXml';

let ideviceReady = false;
/** @type {USBDevice | null} */
let connectedDevice = null;

export function getConnectedDevice() {
    return connectedDevice;
}

export function setConnectedDevice(dev) {
    connectedDevice = dev || null;
}

export function getStoredPairPlist() {
    try {
        const xml = localStorage.getItem(PAIR_STORAGE_KEY);
        if (xml && xml.includes('<plist')) return xml;
    } catch (_) { /* ignore */ }
    return '';
}

export function storePairPlist(xml) {
    try {
        if (xml && xml.includes('<plist')) {
            localStorage.setItem(PAIR_STORAGE_KEY, xml);
        }
    } catch (_) { /* ignore */ }
}

export function clearStoredPairPlist() {
    try {
        localStorage.removeItem(PAIR_STORAGE_KEY);
    } catch (_) { /* ignore */ }
}

/** Parse HostID / SystemBUID from pair-record XML (browser DOMParser). */
export function readPlistRootDictStrings(xmlText) {
    const d = new DOMParser().parseFromString(xmlText, 'application/xml');
    if (d.querySelector('parsererror')) throw new Error('Invalid plist XML');
    const dict = d.querySelector('plist dict');
    if (!dict) throw new Error('No dict found in plist');
    /** @type {Record<string, string>} */
    const out = {};
    let pendingKey = null;
    for (const el of dict.children) {
        if (!(el instanceof Element)) continue;
        if (el.tagName === 'key') pendingKey = (el.textContent ?? '').trim();
        else if (pendingKey !== null) {
            if (el.tagName === 'string') out[pendingKey] = el.textContent ?? '';
            pendingKey = null;
        }
    }
    return out;
}

export function getTlsSettingsFromDom() {
    const authEl = document.getElementById('tls-client-auth');
    const sniEl = document.getElementById('tls-sni');
    return {
        tlsClientAuth: authEl?.value || 'host',
        tlsSni: sniEl?.value || 'device',
    };
}

/**
 * Build lockdown call arguments from stored plist + optional TLS controls in the page.
 * @param {string} [plistXml]
 * @param {{ verbose?: boolean, pairMode?: string, hostId?: string, systemBuid?: string }} [overrides]
 */
export function ideviceCallArgs(plistXml, overrides = {}) {
    const plist = (plistXml ?? getStoredPairPlist() ?? '').trim();
    const tls = getTlsSettingsFromDom();
    const mode = overrides.pairMode || (plist ? 'plist' : 'random');
    let hostId = overrides.hostId ?? '';
    let systemBuid = overrides.systemBuid ?? '';
    if (plist && (!hostId || !systemBuid)) {
        try {
            const ids = readPlistRootDictStrings(plist);
            hostId = hostId || ids.HostID || '';
            systemBuid = systemBuid || ids.SystemBUID || '';
        } catch (_) { /* ignore */ }
    }
    return {
        mode,
        hostId,
        systemBuid,
        plistXml: plist,
        tlsClientAuth: tls.tlsClientAuth,
        tlsSni: tls.tlsSni,
        verbose: !!overrides.verbose,
    };
}

/** Standard positional args for lockdown WASM exports. */
export function toLockdownArgs(device, args) {
    return [
        device,
        args.mode,
        args.hostId,
        args.systemBuid,
        args.plistXml,
        args.verbose,
        args.tlsClientAuth,
        args.tlsSni,
    ];
}

export async function ensureIdeviceWasm() {
    if (!ideviceReady) {
        await initIdevice();
        ideviceReady = true;
    }
}

export function diagnoseWebUsb() {
    if (!navigator.usb) {
        return 'WebUSB is not available. Use Chromium (Chrome/Edge/Brave) over HTTPS or http://127.0.0.1/.';
    }
    if (!window.isSecureContext) {
        return 'WebUSB requires a secure context (localhost or HTTPS).';
    }
    return null;
}

/** Must run in a user-gesture handler (click). */
export async function pickIphoneDevice() {
    await ensureIdeviceWasm();
    const problem = diagnoseWebUsb();
    if (problem) throw new Error(problem);
    const dev = await requestAppleDevice();
    prefetchPairHostKeys();
    connectedDevice = dev;
    return dev;
}

export async function pairIphoneDevice(device, mode = 'random', verbose = false) {
    await ensureIdeviceWasm();
    const xml = await lockdownPair(device, mode, verbose);
    storePairPlist(xml);
    return xml;
}

export async function listSysdiagnoseArchives(device, options = {}) {
    await ensureIdeviceWasm();
    const a = ideviceCallArgs(options.plistXml, options);
    const res = await lockdownSysdiagnoseList(...toLockdownArgs(device, a));
    // WASM returns { entries, debug, matchCount } — same shape as idevice-rs demo app.
    const raw = res && res.entries != null ? res.entries : Array.isArray(res) ? res : null;
    if (!raw || typeof raw.length !== 'number') return [];
    return Array.from({ length: raw.length }, (_, i) => {
        const o = raw[i];
        return {
            path: o.path,
            name: o.name,
            sizeBytes: o.sizeBytes ?? 0,
        };
    });
}

export async function downloadSysdiagnoseArchive(device, devicePath, options = {}) {
    await ensureIdeviceWasm();
    const a = ideviceCallArgs(options.plistXml, options);
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : undefined;
    const res = await lockdownSysdiagnoseDownload(
        ...toLockdownArgs(device, a),
        devicePath,
        onProgress
    );
    if (!res || !(res.data instanceof Uint8Array)) {
        throw new Error('Sysdiagnose download returned no data');
    }
    return {
        name: res.name || 'sysdiagnose.tar.gz',
        path: res.path || devicePath,
        data: res.data,
        byteLength: res.byteLength ?? res.data.byteLength,
    };
}

export function formatBytes(n) {
    if (n == null || Number.isNaN(n)) return '—';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

export function downloadBlob(data, filename, mime = 'application/octet-stream') {
    const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

export {
    muxLockdownHandshake,
    lockdownQueryType,
    pairingIdsFromPlistXml,
    lockdownFetchWithPlistXml,
    lockdownSysdiagnoseInfo,
    lockdownCrashReportsInfo,
    lockdownBattery,
    lockdownDiagnostics,
    lockdownCrashReports,
    lockdownSyslog,
    lockdownPcap,
    lockdownScreenshot,
};

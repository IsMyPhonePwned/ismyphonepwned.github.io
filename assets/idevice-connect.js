/**
 * idevice-rs-style device + pair UI for iphone.html (connect-only workspace).
 */
import {
    ensureIdeviceWasm,
    diagnoseWebUsb,
} from './iphone-idevice.js';
import {
    requestAppleDevice,
    muxLockdownHandshake,
    lockdownQueryType,
    lockdownPair,
    prefetchPairHostKeys,
} from '../pkg-idevice/idevice_wasm.js';

const $ = (id) => document.getElementById(id);

/** @type {USBDevice | null} */
let dev = null;
let plistXmlText = null;
let plistHostShort = null;
let busyBtn = null;

function shortId(s) {
    return s ? String(s).slice(0, 8) + '…' : '—';
}

function readPlistRootDictStrings(xmlText) {
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

function setStatus(id, state, value) {
    const node = $(id);
    if (!node) return;
    node.dataset.state = state;
    node.classList.toggle('ok', state === 'ok');
    node.classList.toggle('warn', state === 'warn');
    const val = $(id + '-val');
    if (val) val.textContent = value;
}

function pairMode() {
    const el = document.querySelector('input[name="pair"]:checked');
    return el ? el.value : 'random';
}

function refreshButtonStates() {
    for (const b of document.querySelectorAll('.idevice-workspace .btn[data-needs]')) {
        const needs = (b.getAttribute('data-needs') || '').split(',').filter(Boolean);
        let reason = '';
        if (needs.includes('dev') && !dev) reason = 'Pick a device first.';
        else if (needs.includes('plist') && !plistXmlText) reason = 'Load or generate a pair record first.';
        else if (needs.includes('auth')) {
            const m = pairMode();
            if (m === 'plist' && !plistXmlText) reason = 'Load a pair-record XML first, or pick Generate.';
        }
        b.disabled = !!reason || !!busyBtn;
        b.title = reason || '';
    }
    const pairBtn = $('btn-pair');
    if (pairBtn) {
        const m = pairMode();
        const canPair = !!dev && !busyBtn && (m === 'random' || m === 'legacy');
        pairBtn.disabled = !canPair;
        pairBtn.title = !dev ? 'Pick a device first' : '';
    }
}

function refreshStatus() {
    if (dev) {
        const name = dev.productName || 'Apple device';
        const sn = dev.serialNumber ? ' · ' + shortId(dev.serialNumber) : '';
        setStatus('st-device', 'ok', name + sn);
    } else {
        setStatus('st-device', 'off', 'Not connected');
    }
    if ($('st-pair')) {
        if (plistXmlText) {
            if (plistHostShort) {
                setStatus('st-pair', 'ok', 'Loaded · HostID ' + plistHostShort);
            } else {
                try {
                    const d = readPlistRootDictStrings(plistXmlText);
                    plistHostShort = d.HostID ? shortId(d.HostID) : null;
                    setStatus('st-pair', 'ok', 'Loaded · HostID ' + (plistHostShort || '?'));
                } catch {
                    setStatus('st-pair', 'warn', 'Loaded (parse error)');
                }
            }
        } else {
            setStatus('st-pair', 'off', 'None');
        }
    }
    refreshButtonStates();
}

/**
 * Load pair XML into memory without UI side-effects (analyzer page).
 * @param {string} xml
 */
function loadPlistQuiet(xml) {
    plistXmlText = xml;
    try {
        const d = readPlistRootDictStrings(xml);
        plistHostShort = d.HostID ? shortId(d.HostID) : null;
    } catch {
        plistHostShort = null;
    }
}

/**
 * @param {string} xml
 * @param {string} sourceLabel
 * @param {{ emit?: boolean, download?: boolean }} [opts]
 */
function setPlist(xml, sourceLabel, opts = {}) {
    const emit = opts.emit !== false;
    const download = opts.download === true;
    plistXmlText = xml;
    try {
        localStorage.setItem('idevice-rs.pairRecordXml', xml);
    } catch (_) { /* ignore */ }
    try {
        const d = readPlistRootDictStrings(xml);
        plistHostShort = d.HostID ? shortId(d.HostID) : null;
        if ($('hostid')) $('hostid').value = d.HostID || '';
        if ($('buid')) $('buid').value = d.SystemBUID || '';
        const ids = $('pair-summary-ids');
        if (ids) {
            ids.innerHTML =
                'HostID = <strong>' + (d.HostID || '?') + '</strong><br>SystemBUID = ' + (d.SystemBUID || '?');
        }
    } catch {
        plistHostShort = null;
        const ids = $('pair-summary-ids');
        if (ids) ids.textContent = '(unparseable XML)';
    }
    const summary = $('pair-summary');
    if (summary) summary.hidden = false;
    setStatus('st-job', 'ok', 'Pair record ' + sourceLabel);
    refreshStatus();
    if (emit) {
        document.dispatchEvent(new CustomEvent('idevice-paired', { detail: { xml } }));
    }
    if (download) {
        queueMicrotask(() => downloadPlist());
    }
}

function clearPlist() {
    plistXmlText = null;
    plistHostShort = null;
    try {
        localStorage.removeItem('idevice-rs.pairRecordXml');
    } catch (_) { /* ignore */ }
    if ($('pair-summary')) $('pair-summary').hidden = true;
    if ($('hostid')) $('hostid').value = '';
    if ($('buid')) $('buid').value = '';
    const fn = $('plist-file-name');
    if (fn) fn.textContent = 'No file chosen';
    setStatus('st-job', 'off', 'Pair record cleared');
    refreshStatus();
    document.dispatchEvent(new CustomEvent('idevice-pair-cleared'));
}

function downloadPlist() {
    if (!plistXmlText) return;
    const blob = new Blob([plistXmlText], { type: 'application/xml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'pair-record.plist';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function copyPlist() {
    if (!plistXmlText) return;
    await navigator.clipboard.writeText(plistXmlText);
}

function setBusy(btn, msg) {
    busyBtn = btn;
    btn.dataset.running = '1';
    setStatus('st-job', 'warn', msg || 'Running…');
    refreshButtonStates();
}

function clearBusy(btn, ok, msg) {
    delete btn.dataset.running;
    busyBtn = null;
    setStatus('st-job', ok ? 'ok' : 'off', msg || (ok ? 'Done' : 'Failed'));
    refreshButtonStates();
}

async function runBusy(btn, label, fn) {
    if (busyBtn) return;
    busyBtn = btn;
    btn.dataset.running = '1';
    const work = fn();
    setStatus('st-job', 'warn', label + '…');
    refreshButtonStates();
    try {
        await work;
        clearBusy(btn, true, label + ' ✓');
    } catch (e) {
        clearBusy(btn, false, label + ' ✗');
        throw e;
    }
}

function maybePrefetchPairKeys() {
    if (!dev) return;
    const m = pairMode();
    if (m === 'random' || m === 'legacy') prefetchPairHostKeys();
}

function refreshPairPanel() {
    const m = pairMode();
    if ($('pair-generate-panel')) $('pair-generate-panel').hidden = m === 'plist';
    if ($('pair-load-panel')) $('pair-load-panel').hidden = m !== 'plist';
    maybePrefetchPairKeys();
    refreshButtonStates();
}

let wired = false;

function wireConnectHandlers(opts = {}) {
    if (wired) return;
    wired = true;
    const notify = (msg) => opts.onStatus?.(msg);

    for (const el of document.querySelectorAll('input[name="pair"]')) {
        el.addEventListener('change', refreshPairPanel);
    }

    $('btn-plist-browse')?.addEventListener('click', () => {
        $('plist-file')?.click();
    });

    $('plist-file')?.addEventListener('change', async (ev) => {
        const input = /** @type {HTMLInputElement} */ (ev.target);
        const file = input.files?.[0];
        if (!file) return;
        try {
            const buf = await file.arrayBuffer();
            const u8 = new Uint8Array(buf);
            const magic = String.fromCharCode(...u8.slice(0, 6));
            if (magic === 'bplist') {
                const st = $('plist-status');
                if (st) st.textContent = 'Binary plist — convert to XML first (plutil -convert xml1).';
                return;
            }
            const text = new TextDecoder('utf-8', { fatal: false }).decode(u8);
            const dict = readPlistRootDictStrings(text);
            if (!dict.HostID || !dict.SystemBUID) {
                const st = $('plist-status');
                if (st) st.textContent = 'Plist has no HostID / SystemBUID at root dict.';
                return;
            }
            setPlist(text, 'loaded from ' + file.name);
            const st = $('plist-status');
            if (st) st.textContent = 'Loaded ' + file.name;
            const fn = $('plist-file-name');
            if (fn) fn.textContent = file.name;
            notify('Pair record loaded');
        } catch (e) {
            const st = $('plist-status');
            if (st) st.textContent = String(e);
        }
        input.value = '';
    });

    $('btn-pair-copy')?.addEventListener('click', () => copyPlist().catch(() => {}));
    $('btn-pair-download')?.addEventListener('click', downloadPlist);
    $('btn-pair-clear')?.addEventListener('click', clearPlist);

    $('btn-pick')?.addEventListener('click', async () => {
        try {
            dev = await requestAppleDevice();
            prefetchPairHostKeys();
            setStatus('st-job', 'off', 'Idle');
            notify('Device: ' + (dev.productName || 'Apple device'));
            document.dispatchEvent(new CustomEvent('idevice-device-picked', { detail: { device: dev } }));
        } catch (e) {
            notify(String(e?.message || e));
        }
        refreshStatus();
    });

    $('btn-mux')?.addEventListener('click', (ev) =>
        runBusy(ev.currentTarget, 'Mux test', async () => {
            await muxLockdownHandshake(dev, false);
            notify('Mux handshake OK');
        }).catch((e) => notify(String(e?.message || e)))
    );

    $('btn-qt')?.addEventListener('click', (ev) =>
        runBusy(ev.currentTarget, 'QueryType', async () => {
            await lockdownQueryType(dev, false);
            notify('QueryType OK');
        }).catch((e) => notify(String(e?.message || e)))
    );

    $('btn-pair')?.addEventListener('click', (ev) => {
        const m = pairMode();
        if (m !== 'random' && m !== 'legacy') return;
        if (busyBtn || !dev) return;
        const btn = ev.currentTarget;
        busyBtn = btn;
        btn.dataset.running = '1';
        const pairWork = lockdownPair(dev, m, false);
        setStatus('st-job', 'warn', `Pair (${m})…`);
        refreshButtonStates();
        pairWork
            .then((xml) => {
                setPlist(xml, 'generated and saved', { download: true });
                notify('Pair record saved');
                clearBusy(btn, true, `Pair (${m}) ✓`);
            })
            .catch((e) => {
                clearBusy(btn, false, `Pair (${m}) ✗`);
                notify(String(e?.message || e));
            });
    });
}

/**
 * @param {{ onStatus?: (msg: string) => void, skipWasm?: boolean, quietRestore?: boolean, restorePair?: boolean }} [opts]
 */
export async function initIdeviceConnect(opts = {}) {
    wireConnectHandlers(opts);
    const notify = (msg) => opts.onStatus?.(msg);

    const problem = diagnoseWebUsb();
    if (problem) {
        notify(problem);
        const pick = $('btn-pick');
        if (pick) pick.disabled = true;
    } else if (!opts.skipWasm) {
        try {
            await ensureIdeviceWasm();
            notify('WebUSB ready — pick device');
        } catch (e) {
            notify('WASM init failed: ' + e);
        }
    }

    const restorePair = opts.restorePair !== false;
    if (restorePair) {
        try {
            const cached = localStorage.getItem('idevice-rs.pairRecordXml');
            if (cached && cached.includes('<plist')) {
                if (opts.quietRestore) {
                    // Analyzer-style silent restore (no "Last action" paint).
                    loadPlistQuiet(cached);
                } else {
                    setPlist(cached, 'restored from cache', { emit: false });
                }
            }
        } catch (_) { /* ignore */ }
    }

    refreshPairPanel();
    refreshStatus();

    return {
        getDevice: () => dev,
        getPlistXml: () => plistXmlText,
        refresh: refreshStatus,
    };
}

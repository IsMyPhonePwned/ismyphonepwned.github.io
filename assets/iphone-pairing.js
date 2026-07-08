/**
 * idevice-rs-style pairing UI — shared by iphone.html and iphone-advanced.html.
 */
import {
    pairIphoneDevice,
    getStoredPairPlist,
    storePairPlist,
    clearStoredPairPlist,
    readPlistRootDictStrings,
    pairingIdsFromPlistXml,
    downloadBlob,
} from './iphone-idevice.js';

function $(id) {
    return document.getElementById(id);
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function shortId(s) {
    return s ? String(s).slice(0, 8) + '…' : '—';
}

function statusPill(el) {
    return el?.closest?.('.iphone-status-pill') || null;
}

function setPillState(valEl, state) {
    const pill = statusPill(valEl);
    if (!pill) return;
    pill.classList.remove('ok', 'warn');
    if (state) pill.classList.add(state);
}

/**
 * @param {{
 *   getDevice: () => USBDevice | null,
 *   onPaired?: (xml: string) => void,
 *   onCleared?: () => void,
 *   onStatus?: (msg: string, kind?: string) => void,
 *   onRefresh?: () => void,
 *   verbose?: () => boolean,
 * }} opts
 */
export function initIphonePairing(opts) {
    const generatePanel = $('pair-generate-panel');
    const loadPanel = $('pair-load-panel');
    const summary = $('pair-summary');
    const summaryIds = $('pair-summary-ids');
    const btnPair = $('btn-pair-generate');
    const btnCopy = $('btn-pair-copy');
    const btnDownload = $('btn-pair-download');
    const btnClear = $('btn-pair-clear');
    const plistFile = $('pair-plist-file');
    const hostIdEl = $('pair-hostid');
    const buidEl = $('pair-buid');
    const stDevice = $('st-device-val');
    const stPair = $('st-pair-val');
    const modeHint = $('pair-mode-hint');
    let pairingBusy = false;

    function status(msg, kind) {
        if (opts.onStatus) opts.onStatus(msg, kind);
    }

    function pairMode() {
        const checked = document.querySelector('input[name="pair-mode"]:checked');
        return checked ? checked.value : 'random';
    }

    function updatePairPanels() {
        const mode = pairMode();
        if (generatePanel) generatePanel.hidden = mode === 'plist';
        if (loadPanel) loadPanel.hidden = mode !== 'plist';
        if (modeHint) {
            if (mode === 'legacy') {
                modeHint.innerHTML =
                    '<em>Legacy</em> → fixed HostID, useful if a device gets stuck on UUID handshakes.';
            } else if (mode === 'random') {
                modeHint.innerHTML =
                    '<em>Random</em> → fresh UUIDs each run (libimobiledevice / pymobiledevice3 style). ' +
                    '<em>Legacy</em> → fixed HostID if the device gets stuck.';
            } else {
                modeHint.textContent = 'Load an XML pair record exported from libimobiledevice, usbmuxd, or a prior Pair + save.';
            }
        }
    }

    function refreshStatusBar() {
        const dev = opts.getDevice();
        if (stDevice) {
            if (dev) {
                const name = dev.productName || 'Apple device';
                const sn = dev.serialNumber ? ' · ' + shortId(dev.serialNumber) : '';
                stDevice.textContent = name + sn;
                setPillState(stDevice, 'ok');
            } else {
                stDevice.textContent = 'Not connected';
                setPillState(stDevice, null);
            }
        }
        const xml = getStoredPairPlist();
        if (stPair) {
            if (xml) {
                try {
                    const d = readPlistRootDictStrings(xml);
                    stPair.textContent = 'Loaded · HostID ' + shortId(d.HostID);
                    setPillState(stPair, 'ok');
                } catch {
                    stPair.textContent = 'Loaded (parse error)';
                    setPillState(stPair, 'warn');
                }
            } else {
                stPair.textContent = 'None';
                setPillState(stPair, null);
            }
        }
        if (summary) summary.hidden = !xml;

        if (btnPair) {
            const mode = pairMode();
            const canPair = !!dev && !pairingBusy && (mode === 'random' || mode === 'legacy');
            btnPair.disabled = !canPair;
            btnPair.title = !dev
                ? 'Pick an iPhone first'
                : mode === 'plist'
                  ? 'Switch to Generate · random or legacy'
                  : '';
        }
    }

    function showSummary(xml) {
        if (!summary || !summaryIds) return;
        try {
            const d = readPlistRootDictStrings(xml);
            if (hostIdEl) hostIdEl.value = d.HostID || '';
            if (buidEl) buidEl.value = d.SystemBUID || '';
            summaryIds.innerHTML =
                'HostID = <strong>' + escapeHtml(d.HostID || '?') + '</strong><br>' +
                'SystemBUID = ' + escapeHtml(d.SystemBUID || '?');
            summary.hidden = false;
        } catch {
            summaryIds.textContent = '(unparseable XML)';
            summary.hidden = false;
        }
    }

    function applyPlist(xml, label) {
        storePairPlist(xml);
        showSummary(xml);
        status('Pair record ' + label, 'success');
        refreshStatusBar();
        if (opts.onPaired) opts.onPaired(xml);
        if (opts.onRefresh) opts.onRefresh();
    }

    document.querySelectorAll('input[name="pair-mode"]').forEach((radio) => {
        radio.addEventListener('change', () => {
            updatePairPanels();
            refreshStatusBar();
        });
    });

    if (btnPair) {
        btnPair.addEventListener('click', async () => {
            const dev = opts.getDevice();
            if (!dev) {
                status('Pick an iPhone first', 'error');
                return;
            }
            const mode = pairMode();
            if (mode !== 'random' && mode !== 'legacy') {
                status('Switch to Generate · random or legacy first', 'error');
                return;
            }
            pairingBusy = true;
            btnPair.disabled = true;
            btnPair.dataset.running = '1';
            status('Pairing… unlock iPhone and accept Trust (may take 10–30 s)', 'warning');
            try {
                const verbose = opts.verbose ? opts.verbose() : false;
                const xml = await pairIphoneDevice(dev, mode, verbose);
                applyPlist(xml, 'generated and saved');
                try {
                    downloadBlob(xml, 'pair-record.plist', 'application/xml');
                } catch (_) { /* optional auto-download */ }
            } catch (e) {
                status(String(e?.message || e), 'error');
            } finally {
                pairingBusy = false;
                delete btnPair.dataset.running;
                refreshStatusBar();
            }
        });
    }

    if (plistFile) {
        plistFile.addEventListener('change', async () => {
            const file = plistFile.files?.[0];
            if (!file) return;
            const text = await file.text();
            if (text.trim().startsWith('bplist')) {
                status('Binary plist not supported — export as XML with plutil -convert xml1', 'error');
                plistFile.value = '';
                return;
            }
            try {
                await pairingIdsFromPlistXml(text);
                applyPlist(text, 'loaded from ' + file.name);
            } catch (e) {
                status('Invalid pair plist: ' + (e?.message || e), 'error');
            }
            plistFile.value = '';
        });
    }

    if (btnCopy) {
        btnCopy.addEventListener('click', async () => {
            const xml = getStoredPairPlist();
            if (!xml) return;
            try {
                await navigator.clipboard.writeText(xml);
                status('Pair record copied to clipboard', 'success');
            } catch (e) {
                status('Clipboard failed: ' + e, 'error');
            }
        });
    }

    if (btnDownload) {
        btnDownload.addEventListener('click', () => {
            const xml = getStoredPairPlist();
            if (!xml) return;
            downloadBlob(xml, 'pair-record.plist', 'application/xml');
            status('pair-record.plist downloaded', 'success');
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            clearStoredPairPlist();
            if (summary) summary.hidden = true;
            if (hostIdEl) hostIdEl.value = '';
            if (buidEl) buidEl.value = '';
            status('Pair record cleared', 'info');
            refreshStatusBar();
            if (opts.onCleared) opts.onCleared();
            if (opts.onRefresh) opts.onRefresh();
        });
    }

    const cached = getStoredPairPlist();
    if (cached) {
        showSummary(cached);
        status('Pair record restored from browser cache', 'info');
    }

    updatePairPanels();
    refreshStatusBar();

    return {
        refresh: refreshStatusBar,
        hasPairRecord: () => !!getStoredPairPlist(),
    };
}

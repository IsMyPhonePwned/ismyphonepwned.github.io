/** fakeMustache options + anonymize UI. Processing stays in the browser. */
import init, { anonymize, describe_policy, explain, restore, version } from '../pkg-fakemustache/fm_wasm.js';

const KINDS = [
    'email',
    'phone_number',
    'imei',
    'imsi',
    'iccid',
    'serial_number',
    'udid',
    'android_id',
    'mac_address',
    'bssid',
    'ssid',
    'bluetooth_name',
    'ipv4_public',
    'ipv4_private',
    'ipv6',
    'domain_name',
    'url',
    'uuid',
    'container_uuid',
    'person_name',
    'user_name',
    'organization_name',
    'gps_coordinate',
    'cell_id',
    'file_path_leaf',
    'package_name',
    'timestamp',
    'carrier',
];

const GROUPS = ['identifiers', 'accounts', 'device', 'network', 'location', 'all'];

let wasmReady = null;
let selectedFile = null;
let selectedKeyB64 = null;

function bytesToB64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

function t(key, fallback) {
    const lang = window.currentLang || 'en';
    const pack =
        (window.ANON_I18N && window.ANON_I18N[lang]) ||
        (window.ANON_I18N && window.ANON_I18N.en) ||
        (window.HUB_I18N && window.HUB_I18N[lang]) ||
        (window.HUB_I18N && window.HUB_I18N.en) ||
        {};
    return pack[key] || fallback;
}

function setWasmPill(state, label) {
    const el = document.getElementById('wasm-status');
    if (!el) return;
    el.dataset.state = state;
    el.className = 'runtime-status is-' + state;
    const labelEl = el.querySelector('.runtime-status__label');
    if (labelEl) labelEl.textContent = label;
}

function val(id) {
    const el = document.getElementById(id);
    return el ? String(el.value || '').trim() : '';
}

function checked(id) {
    const el = document.getElementById(id);
    return !!(el && el.checked);
}

function setStatus(message, kind) {
    const el = document.getElementById('fm-status');
    if (!el) return;
    el.textContent = message || '';
    el.dataset.kind = kind || 'info';
}

function setOutput(text) {
    const el = document.getElementById('fm-output');
    if (!el) return;
    if (!text) {
        el.hidden = true;
        el.textContent = '';
        return;
    }
    el.hidden = false;
    el.textContent = text;
}

function collectOpts() {
    const entities = [];
    document.querySelectorAll('#fm-entities select[data-kind]').forEach(function (sel) {
        if (sel.value) entities.push(sel.getAttribute('data-kind') + '=' + sel.value);
    });
    const mode = val('fm-mode') || 'pseudo';
    return {
        profile: val('fm-profile') || 'balanced',
        passphrase: val('fm-passphrase') || null,
        logarchive: val('fm-logarchive') || 'drop',
        ordinal: checked('fm-ordinal'),
        keep_location: checked('fm-keep-location'),
        keep_cell_ids: checked('fm-keep-cell'),
        generalize_carrier: checked('fm-gen-carrier'),
        drop_carrier: checked('fm-drop-carrier'),
        pseudo_third_party_packages: checked('fm-pseudo-pkg'),
        drop_text_from_packages: val('fm-drop-text') || null,
        only: val('fm-only') || null,
        entities: entities,
        time_shift: val('fm-time-shift') || null,
        reversible: mode === 'reversible',
        restore: mode === 'restore',
        key_b64: selectedKeyB64,
    };
}

function needsKey(opts) {
    return (opts.reversible || opts.restore) && !opts.passphrase && !opts.key_b64;
}

function ensureWasm(opts) {
    opts = opts || {};
    if (!wasmReady) {
        if (!opts.quiet) setStatus(t('hubAnonLoading', 'Loading anonymizer…'), 'info');
        setWasmPill('loading', t('wasmLoading', 'Loading…'));
        wasmReady = init()
            .then(function () {
                const ready = t('hubAnonReady', 'Anonymizer ready') + ' · v' + version();
                if (!opts.quiet) setStatus(ready, 'info');
                setWasmPill('ready', t('wasmReady', 'Ready'));
            })
            .catch(function (err) {
                wasmReady = null;
                setWasmPill('error', t('wasmFailed', 'Failed'));
                throw err;
            });
    }
    return wasmReady;
}

function setFile(file) {
    selectedFile = file || null;
    const label = document.getElementById('fm-file-name');
    if (!label) return;
    if (!file) {
        label.textContent = t('hubAnonNoFile', 'No archive selected.');
        return;
    }
    const mb = (file.size / (1024 * 1024)).toFixed(1);
    label.textContent = file.name + ' · ' + mb + ' MB';
}

function anonName(name) {
    if (/\.tar\.gz$/i.test(name)) return name.replace(/\.tar\.gz$/i, '.anon.tar.gz');
    if (/\.tgz$/i.test(name)) return name.replace(/\.tgz$/i, '.anon.tgz');
    const dot = name.lastIndexOf('.');
    if (dot > 0) return name.slice(0, dot) + '.anon' + name.slice(dot);
    return name + '.anon';
}

function downloadBytes(bytes, name, type) {
    const blob = new Blob([bytes], { type: type || 'application/octet-stream' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () {
        URL.revokeObjectURL(url);
    }, 4000);
}

function yieldFrame() {
    return new Promise(function (resolve) {
        requestAnimationFrame(function () {
            setTimeout(resolve, 0);
        });
    });
}

function buildEntities() {
    const host = document.getElementById('fm-entities');
    if (!host || host.childElementCount) return;
    const profileDefault = t('hubAnonProfileDefault', 'Profile default');
    KINDS.forEach(function (kind) {
        const label = document.createElement('label');
        label.className = 'hub-anon-entity';
        const title = document.createElement('span');
        title.textContent = kind;
        const sel = document.createElement('select');
        sel.setAttribute('data-kind', kind);
        sel.setAttribute('aria-label', kind);
        const def = document.createElement('option');
        def.value = '';
        def.textContent = profileDefault;
        def.setAttribute('data-i18n-option', 'hubAnonProfileDefault');
        sel.appendChild(def);
        ['keep', 'pseudo', 'drop', 'generalize', 'shift'].forEach(function (action) {
            const opt = document.createElement('option');
            opt.value = action;
            opt.textContent = action;
            sel.appendChild(opt);
        });
        label.appendChild(title);
        label.appendChild(sel);
        host.appendChild(label);
    });
}

function refreshDynamicLabels() {
    const profileDefault = t('hubAnonProfileDefault', 'Profile default');
    document.querySelectorAll('#fm-entities option[data-i18n-option]').forEach(function (opt) {
        opt.textContent = profileDefault;
    });
    if (!selectedFile) setFile(null);
    const profile = document.getElementById('fm-profile');
    const warn = document.getElementById('fm-research-warn');
    if (warn) warn.hidden = !profile || profile.value !== 'research';
    const mode = val('fm-mode') || 'pseudo';
    const section = document.getElementById('anonymize');
    if (section) section.classList.toggle('is-restore', mode === 'restore');
    const rev = document.getElementById('fm-reversible-note');
    if (rev) rev.hidden = mode === 'pseudo';
    const runBtn = document.getElementById('fm-run');
    if (runBtn) {
        runBtn.textContent = mode === 'restore'
            ? t('hubAnonRunRestore', 'Restore and download')
            : t('hubAnonRun', 'Anonymize and download');
    }
}

function wire() {
    buildEntities();
    const drop = document.getElementById('fm-drop');
    const input = document.getElementById('fm-file');
    if (drop && input) {
        drop.addEventListener('click', function (e) {
            if (e.target === input) return;
            input.click();
        });
        drop.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                input.click();
            }
        });
        ['dragenter', 'dragover'].forEach(function (name) {
            drop.addEventListener(name, function (e) {
                e.preventDefault();
                drop.classList.add('is-drag');
            });
        });
        ['dragleave', 'drop'].forEach(function (name) {
            drop.addEventListener(name, function (e) {
                e.preventDefault();
                drop.classList.remove('is-drag');
            });
        });
        drop.addEventListener('drop', function (e) {
            const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
            if (file) setFile(file);
        });
        input.addEventListener('change', function () {
            setFile(input.files && input.files[0]);
        });
    }

    const groups = document.getElementById('fm-groups');
    if (groups) {
        GROUPS.forEach(function (group) {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.textContent = group;
            btn.addEventListener('click', function () {
                const only = document.getElementById('fm-only');
                if (only) only.value = group;
            });
            groups.appendChild(btn);
        });
    }

    const profile = document.getElementById('fm-profile');
    if (profile) {
        profile.addEventListener('change', refreshDynamicLabels);
    }
    const mode = document.getElementById('fm-mode');
    if (mode) {
        mode.addEventListener('change', refreshDynamicLabels);
    }
    const keyInput = document.getElementById('fm-key-file');
    if (keyInput) {
        keyInput.addEventListener('change', async function () {
            const file = keyInput.files && keyInput.files[0];
            selectedKeyB64 = null;
            if (!file) return;
            if (file.size > 1024 * 1024) {
                setStatus(t('hubAnonNeedKey', 'Key file is too large.'), 'error');
                keyInput.value = '';
                return;
            }
            selectedKeyB64 = bytesToB64(new Uint8Array(await file.arrayBuffer()));
        });
    }

    document.querySelectorAll('.lang-switcher button').forEach(function (btn) {
        btn.addEventListener('click', function () {
            setTimeout(refreshDynamicLabels, 0);
        });
    });

    const policyBtn = document.getElementById('fm-policy');
    const explainBtn = document.getElementById('fm-explain');
    const runBtn = document.getElementById('fm-run');
    const resetBtn = document.getElementById('fm-reset-entities');

    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            document.querySelectorAll('#fm-entities select').forEach(function (sel) {
                sel.value = '';
            });
        });
    }

    if (policyBtn) {
        policyBtn.addEventListener('click', async function () {
            try {
                await ensureWasm();
                setOutput(describe_policy(collectOpts()));
                setStatus(t('hubAnonPolicyDone', 'Policy for the current options.'), 'info');
            } catch (err) {
                setStatus(String(err && err.message ? err.message : err), 'error');
            }
        });
    }

    if (explainBtn) {
        explainBtn.addEventListener('click', async function () {
            if (!selectedFile) {
                setStatus(t('hubAnonNeedFile', 'Choose a bugreport (.zip) or sysdiagnose (.tar.gz) first.'), 'error');
                return;
            }
            try {
                await ensureWasm();
                setStatus(t('hubAnonExplainBusy', 'Explaining… this can take a while on large archives.'), 'info');
                await yieldFrame();
                const buf = new Uint8Array(await selectedFile.arrayBuffer());
                setOutput(explain(buf, collectOpts()));
                setStatus(t('hubAnonExplainDone', 'Dry run complete. Nothing was written.'), 'info');
            } catch (err) {
                setStatus(String(err && err.message ? err.message : err), 'error');
            }
        });
    }

    if (runBtn) {
        runBtn.addEventListener('click', async function () {
            if (!selectedFile) {
                setStatus(t('hubAnonNeedFile', 'Choose a bugreport (.zip) or sysdiagnose (.tar.gz) first.'), 'error');
                return;
            }
            try {
                await ensureWasm();
                const opts = collectOpts();
                if (needsKey(opts)) {
                    setStatus(t('hubAnonNeedKey', 'Reversible and restore need a passphrase or a key file.'), 'error');
                    return;
                }
                if (opts.restore) {
                    setStatus(t('hubAnonBusy', 'Restoring in this browser… keep the tab open.'), 'info');
                } else if (opts.profile === 'research') {
                    setStatus(t('hubAnonResearchBusy', 'Research profile is not safe for public release. Anonymizing…'), 'info');
                } else if (opts.reversible) {
                    setStatus(t('hubAnonReversibleNote', 'Reversible anonymize… keep the passphrase. Do not send it with the archive.'), 'info');
                } else {
                    setStatus(t('hubAnonBusy', 'Anonymizing in this browser… keep the tab open.'), 'info');
                }
                await yieldFrame();
                const buf = new Uint8Array(await selectedFile.arrayBuffer());
                const result = opts.restore ? restore(buf, opts) : anonymize(buf, opts);
                const outName = opts.restore
                    ? selectedFile.name.replace(/(\.[^.]+)?$/, '.restored$1')
                    : anonName(selectedFile.name);
                const bytes = result.output;
                const report = result.report_json || '';
                if (typeof result.free === 'function') result.free();
                downloadBytes(bytes, outName, 'application/octet-stream');
                if (!opts.restore) {
                    downloadBytes(report, selectedFile.name + '.fakemustache-report.json', 'application/json');
                }
                let summary = t('hubAnonDone', 'Download started: anonymized archive and audit report.');
                if (opts.restore) {
                    let opened = '';
                    try {
                        opened = String(JSON.parse(report).opened);
                    } catch (e) {
                        opened = '?';
                    }
                    summary = t('hubAnonRestored', 'Restored {n} token(s). Download started.').replace('{n}', opened);
                } else {
                    try {
                        const parsed = JSON.parse(report);
                        const residual = parsed && parsed.residual_scan && parsed.residual_scan.status;
                        if (residual) summary += ' residual=' + residual;
                    } catch (e) {
                        /* report still downloaded */
                    }
                }
                setOutput(report);
                setStatus(summary, 'info');
            } catch (err) {
                setStatus(String(err && err.message ? err.message : err), 'error');
            }
        });
    }

    setFile(null);
    refreshDynamicLabels();
    ensureWasm({ quiet: true }).catch(function (err) {
        setStatus(String(err && err.message ? err.message : err), 'error');
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
} else {
    wire();
}

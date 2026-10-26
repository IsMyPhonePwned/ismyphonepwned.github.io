/**
 * Mobipwn-parity curated panels for the iPhone dashboard (Overview identity,
 * Network leftovers, External devices, Authentication, Battery).
 * Expects page helpers via window.IphoneDashApi (set by iphone.html).
 */
(function (global) {
    'use strict';

    function api() {
        return global.IphoneDashApi || {};
    }

    function A() {
        return api();
    }

    function field(ev) {
        var a = A();
        return a.iosLooseField.apply(null, arguments);
    }

    function events(out, name) {
        return A().iosParserEvents(out, name) || [];
    }

    function plain(x) {
        var a = A();
        return (a.mapPlainTop && a.mapPlainTop(x)) || x || {};
    }

    function asArr(x) {
        return A().asArr ? A().asArr(x) : Array.isArray(x) ? x : [];
    }

    function tr(key) {
        return A().trIphone ? A().trIphone(key) : key;
    }

    function setCard(cardId, visible) {
        if (A().setIphoneNetworkCardVisible) A().setIphoneNetworkCardVisible(cardId, visible);
        else {
            var el = document.getElementById(cardId);
            if (el) el.classList.toggle('hidden', !visible);
        }
    }

    function fillTable(cardId, mountId, headers, rows, opts) {
        var mount = document.getElementById(mountId);
        if (!mount) return 0;
        setCard(cardId, !!rows.length);
        if (!rows.length) {
            mount.textContent = '';
            return 0;
        }
        A().mountDashFilterableTable(mount, headers, rows, opts || { monoCols: { 0: true } });
        return rows.length;
    }

    function formatBytes(raw) {
        var n = Number.parseInt(String(raw || ''), 10);
        if (!Number.isFinite(n) || n <= 0) return raw || '—';
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
        return (n / (1024 * 1024)).toFixed(1) + ' MB';
    }

    function parseCapacityPercent(cap, capacityPercent) {
        var fromField = Number(capacityPercent);
        if (Number.isFinite(fromField) && fromField > 0) return Math.min(100, fromField);
        var n = Number(String(cap || '').replace('%', '').trim());
        return Number.isFinite(n) && n > 0 ? Math.min(100, n) : 0;
    }

    /* ---------- Overview identity ---------- */

    function collectAccounts(out) {
        var list = [];
        var seen = {};
        function push(email, type, detail) {
            if (!email) return;
            var key = String(type || 'account') + ':' + String(email).toLowerCase();
            if (seen[key]) return;
            seen[key] = true;
            list.push({
                email: String(email),
                type: String(type || 'account'),
                when: detail ? String(detail) : '—'
            });
        }

        var acc = A().getAnalyserPayload ? A().getAnalyserPayload(out, 'accounts') : null;
        if (acc && typeof acc === 'object') {
            asArr(acc.owner_emails).forEach(function (row) {
                var r = plain(row);
                push(r.email, 'owner_email', r.source || r.path || '');
            });
            asArr(acc.organization_emails).forEach(function (row) {
                var r = plain(row);
                push(
                    r.email,
                    r.account_type || 'organization_email',
                    r.organization_name || r.source || ''
                );
            });
            asArr(acc.activation_lock_usernames).forEach(function (row) {
                var r = plain(row);
                push(r.email, r.account_type || 'activation_lock', r.source || '');
            });
            asArr(acc.contacts).forEach(function (row) {
                var r = plain(row);
                push(r.email || r.phone || r.uri, r.kind || 'contact', r.source || '');
            });
            asArr(acc.apple_accounts).forEach(function (row) {
                var r = plain(row);
                push(r.account_id || r.email, r.account_type || 'apple_account', r.source || '');
            });
            asArr(acc.linked_devices).forEach(function (row) {
                var r = plain(row);
                var label = r.name || r.serial || r.model;
                var detail = [r.serial, r.model, r.os_version].filter(Boolean).join(' · ');
                push(label, 'linked_device', detail);
            });
            if (acc.lockdown_mode === true || acc.lockdown_mode === false) {
                push(
                    tr('dashLockdownMode'),
                    acc.lockdown_mode ? tr('dashEnabled') : tr('dashDisabled'),
                    'EffectiveUserSettings'
                );
            }
            if (list.length) return list.slice(0, 80);
        }

        // Legacy fallback if an accounts event stream ever reappears.
        var rows = events(out, 'accounts');
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var email =
                field(ev, 'email', 'account_name', 'account name', 'owner_name', 'owner name') ||
                field(ev, 'user');
            var type =
                field(ev, 'account_type', 'account type', 'event_type', 'data_type') || 'account';
            if (!email) continue;
            push(email, type, field(ev, 'datetime', 'timestamp') || '—');
        }
        return list;
    }

    function collectMountIntegrity(out) {
        var data = A().getParserPayload ? A().getParserPayload(out, 'mount') : null;
        if (!data || typeof data !== 'object' || data.error) return null;
        var sum = plain(data.summary) || {};
        var sealed = sum.root_sealed === true;
        var readOnly = sum.root_read_only === true;
        var hint = sum.integrity_hint ? String(sum.integrity_hint) : '';
        var rows = [];
        asArr(data.events).forEach(function (ev) {
            if (rows.length >= 40) return;
            var e = plain(ev);
            var d = plain(e.data) || e;
            var mp = d.mountpoint || '';
            var device = d.device || '';
            if (!mp && e.message) {
                rows.push({ mount: e.message, device: '—', flags: '—' });
                return;
            }
            if (!mp) return;
            var opts = asArr(d.opts);
            rows.push({
                mount: String(mp),
                device: String(device || '—'),
                flags: opts.length ? opts.join(', ') : '—'
            });
        });
        if (!rows.length && !hint && sealed !== true && readOnly !== true) return null;
        return { sealed: sealed, readOnly: readOnly, hint: hint, mounts: rows };
    }

    function collectCollectionMeta(out) {
        var data = A().getParserPayload ? A().getParserPayload(out, 'collection_meta') : null;
        if (!data || typeof data !== 'object' || data.error) return null;
        var meta = plain(data.meta) || {};
        var errKeys =
            data.errors && typeof data.errors === 'object' && !Array.isArray(data.errors)
                ? Object.keys(data.errors)
                : [];
        var taskCount = asArr(data.task_summary).length;
        var summaryCount =
            meta.summary_returned != null
                ? Number(meta.summary_returned)
                : data.summaries && typeof data.summaries === 'object'
                  ? Object.keys(data.summaries).length
                  : 0;
        var errorCount =
            meta.error_file_count != null ? Number(meta.error_file_count) : errKeys.length;
        if (!taskCount && !summaryCount && !errorCount && !data.sysdiagnose_log) return null;
        return {
            taskCount: taskCount,
            summaryCount: summaryCount,
            errorCount: errorCount,
            errorPaths: errKeys.slice(0, 24),
            hasLog: !!(
                data.sysdiagnose_log &&
                (data.sysdiagnose_log.preview || data.sysdiagnose_log.len)
            )
        };
    }

    function collectFileInventory(out, parserName, maxRows) {
        var data = A().getParserPayload ? A().getParserPayload(out, parserName) : null;
        if (!data || typeof data !== 'object' || data.error) return [];
        var files = data.files;
        if (!files || typeof files !== 'object' || Array.isArray(files)) return [];
        var keys = Object.keys(files).sort();
        var list = [];
        var cap = maxRows || 40;
        for (var i = 0; i < keys.length && list.length < cap; i++) {
            var path = keys[i];
            var val = files[path];
            var preview = '—';
            var size = '—';
            if (typeof val === 'string') {
                size = String(val.length);
                var line = val.trim().split('\n')[0] || '';
                preview = line.length > 96 ? line.slice(0, 93) + '…' : line || '(empty)';
            } else if (val && typeof val === 'object') {
                if (val.skipped_oversized) {
                    preview = 'oversized';
                    size = val.size != null ? String(val.size) : '—';
                } else if (typeof val.raw === 'string') {
                    size = String(val.raw.length);
                    preview = val.raw.trim().split('\n')[0].slice(0, 96) || 'raw';
                } else if (val.empty) {
                    preview = '(empty)';
                } else {
                    preview = 'structured';
                }
            }
            var base = path.split('/').pop() || path;
            list.push({ path: path, name: base, preview: preview, size: size });
        }
        return list;
    }

    function collectRunningboard(out) {
        var data = A().getParserPayload ? A().getParserPayload(out, 'runningboard') : null;
        if (!data || typeof data !== 'object' || data.error) return null;
        var meta = plain(data.meta) || {};
        var domains = asArr(meta.domain_hints).map(String).filter(Boolean);
        var jetsam = asArr(meta.jetsam_bands_seen).map(String).filter(Boolean);
        if (!domains.length && !jetsam.length) return null;
        return { domains: domains.slice(0, 80), jetsam: jetsam };
    }

    function collectCkks(out) {
        return collectFileInventory(out, 'ckks_pcs', 24);
    }

    function collectStorage(out) {
        var rows = events(out, 'disks');
        var byMount = {};
        var MOUNT_LABELS = {
            '/': 'System root',
            '/private/var': 'Variable data',
            '/private/var/mobile': 'Mobile user data',
            '/private/preboot': 'Preboot'
        };
        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var mount = field(ev, 'mounted_on', 'mounted on', 'mount');
            if (!mount || byMount[mount]) continue;
            var sizeBytes = Number(field(ev, 'size_bytes', 'size bytes')) || 0;
            var usedBytes = Number(field(ev, 'used_bytes', 'used bytes')) || 0;
            if (mount === '/dev') continue;
            if (sizeBytes > 0 && sizeBytes < 512 * 1024) continue;
            var pct = parseCapacityPercent(field(ev, 'capacity'), field(ev, 'capacity_percent', 'capacity percent'));
            byMount[mount] = {
                mount: mount,
                label: MOUNT_LABELS[mount] || mount.replace(/^\/private\//, ''),
                fs: field(ev, 'filesystem') || '—',
                size: field(ev, 'size') || formatBytes(sizeBytes),
                used: field(ev, 'used') || formatBytes(usedBytes),
                avail: field(ev, 'avail') || formatBytes(Number(field(ev, 'avail_bytes')) || 0),
                capacity: pct ? pct + '%' : field(ev, 'capacity') || '—'
            };
        }
        return Object.keys(byMount)
            .map(function (k) {
                return byMount[k];
            })
            .sort(function (a, b) {
                return a.mount.length - b.mount.length || a.mount.localeCompare(b.mount);
            });
    }

    function collectActivation(out) {
        var rows = events(out, 'mobileactivation');
        var startup = null;
        var state = '';
        var dcrtReq = 0;
        var dcrtResp = 0;
        var dcrtOther = 0;
        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var msg = field(ev, 'message');
            var et = (
                field(ev, 'event_type', 'event type', 'kind', 'data_type') || ''
            ).toLowerCase();
            if (et.indexOf('dcrt_baa_request') >= 0) dcrtReq += 1;
            else if (et.indexOf('dcrt_baa_response') >= 0) dcrtResp += 1;
            else if (et.indexOf('dcrt_baa') >= 0) dcrtOther += 1;
            if (!startup && field(ev, 'hardware_model', 'hardware model')) startup = ev;
            if (!state && /activation state:/i.test(msg)) {
                state = msg.replace(/.*activation state:\s*/i, '').trim();
            }
        }
        if (!startup && !state && !dcrtReq && !dcrtResp && !dcrtOther) return null;
        var hasBb = field(startup || {}, 'has_baseband', 'has baseband');
        return {
            state: state || '—',
            soc: field(startup || {}, 'soc_generation', 'soc generation') || '—',
            baseband: hasBb === 'true' ? 'Yes' : hasBb === 'false' ? 'No' : '—',
            build: field(startup || {}, 'build_version', 'build version') || '—',
            dcrtReq: dcrtReq,
            dcrtResp: dcrtResp,
            dcrtOther: dcrtOther
        };
    }

    function collectPaired(out) {
        var rows = events(out, 'security_sysdiagnose');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var section = field(ev, 'section') || 'keychain';
            var name =
                field(ev, 'labl', 'label', 'name') ||
                (function () {
                    var attrs = ev.attributes || (ev.data && ev.data.attributes);
                    if (attrs && typeof attrs === 'object') {
                        return String(attrs.labl || attrs.label || '').trim();
                    }
                    return '';
                })();
            if (!name) {
                var msg = field(ev, 'message');
                if (msg && msg.length < 80) name = msg;
            }
            if (!name) continue;
            var service = field(ev, 'svce', 'service', 'agrp') || '—';
            var key = section + ':' + name + ':' + service;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                name: name,
                section: section,
                service: service,
                added: field(ev, 'cdat', 'added', 'created') || '—'
            });
        }
        return list;
    }

    function collectIoservice(out) {
        var LABELS = {
            ioplatformserialnumber: 'Platform serial',
            model: 'Model',
            'board-id': 'Board ID',
            'product-name': 'Product',
            'chip-id': 'Chip ID',
            uniquechipid: 'Unique chip ID',
            'die-id': 'Die ID'
        };
        var props = [];
        var nodeCount = '';

        var data = A().getParserPayload ? A().getParserPayload(out, 'ioservice') : null;
        if (data && typeof data === 'object' && !data.error) {
            var sum = plain(data.summary) || {};
            if (sum.node_count != null) nodeCount = String(sum.node_count);
            var dp = data.device_properties;
            if (dp && typeof dp === 'object' && !Array.isArray(dp)) {
                Object.keys(dp)
                    .sort()
                    .forEach(function (k) {
                        if (props.length >= 24) return;
                        var raw = dp[k];
                        var s =
                            typeof raw === 'string'
                                ? raw
                                : raw != null && typeof raw !== 'object'
                                  ? String(raw)
                                  : '';
                        if (!s.trim()) return;
                        var leaf = k.split('.').pop() || k;
                        props.push({
                            label: LABELS[leaf.toLowerCase()] || leaf.replace(/_/g, ' '),
                            value: s.trim()
                        });
                    });
            }
            if (nodeCount || props.length) {
                return { nodeCount: nodeCount, properties: props.slice(0, 24) };
            }
        }

        // Legacy flattened events fallback
        var rows = events(out, 'ioservice');
        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var et = field(ev, 'event_type', 'event type');
            if (et === 'ioservice_summary' || field(ev, 'node_count', 'node count')) {
                nodeCount = field(ev, 'node_count', 'node count') || nodeCount;
            }
            if (et === 'device_properties' || et === 'ioservice_summary') {
                var skip = { event_type: 1, parser: 1, message: 1, datetime: 1, data_type: 1 };
                Object.keys(ev).forEach(function (k) {
                    if (skip[k]) return;
                    var v = ev[k];
                    if (typeof v !== 'string' || !v.trim()) return;
                    if (k === 'node_count' || k === 'property_count' || k === 'tree_truncated') return;
                    props.push({
                        label: LABELS[k.toLowerCase()] || k.replace(/_/g, ' '),
                        value: v.trim()
                    });
                });
            }
        }
        if (!nodeCount && !props.length) return null;
        return { nodeCount: nodeCount, properties: props.slice(0, 24) };
    }

    function ensurePanelEmpty(panelId, emptyKey, hasContent) {
        var panel = document.getElementById(panelId);
        if (!panel) return;
        var existing = panel.querySelector('.iphone-dash-panel-empty');
        if (existing) existing.remove();
        if (hasContent) return;
        var el;
        if (A().dashEmptyEl) {
            el = A().dashEmptyEl(emptyKey);
        } else {
            el = document.createElement('p');
            el.className = 'iphone-dash-empty';
            el.textContent = tr(emptyKey);
        }
        el.classList.add('iphone-dash-panel-empty');
        panel.appendChild(el);
    }

    function fillKvGrid(mount, pairs) {
        if (!mount) return;
        mount.textContent = '';
        var grid = document.createElement('div');
        grid.className = 'result-grid';
        pairs.forEach(function (pair) {
            var item = document.createElement('div');
            item.className = 'result-item';
            item.innerHTML =
                '<div class="result-item-label">' +
                (A().escapeHtmlIphone ? A().escapeHtmlIphone(pair[0]) : pair[0]) +
                '</div><div class="result-item-value mono">' +
                (A().escapeHtmlIphone ? A().escapeHtmlIphone(String(pair[1])) : String(pair[1])) +
                '</div>';
            grid.appendChild(item);
        });
        mount.appendChild(grid);
    }

    function renderOverviewIdentity(out) {
        var accounts = collectAccounts(out);
        fillTable(
            'iphone-accounts-card',
            'iphone-accounts-mount',
            [tr('dashColAccount'), tr('dashColKind'), tr('dashColDetail')],
            accounts.map(function (a) {
                return {
                    cells: [a.email, a.type, a.when],
                    haystack: [a.email, a.type, a.when].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var storage = collectStorage(out);
        fillTable(
            'iphone-storage-card',
            'iphone-storage-mount',
            [
                tr('dashColMount'),
                tr('dashColLabel'),
                tr('dashColFs'),
                tr('dashColSize'),
                tr('dashColUsed'),
                tr('dashColAvail'),
                tr('dashColCapacity')
            ],
            storage.map(function (v) {
                return {
                    cells: [v.mount, v.label, v.fs || '—', v.size, v.used, v.avail, v.capacity],
                    haystack: [v.mount, v.label, v.fs].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 2: true } }
        );

        var integrity = collectMountIntegrity(out);
        var intCard = document.getElementById('iphone-integrity-card');
        var intMount = document.getElementById('iphone-integrity-mount');
        if (intCard && intMount) {
            intMount.textContent = '';
            if (!integrity) {
                intCard.classList.add('hidden');
            } else {
                intCard.classList.remove('hidden');
                fillKvGrid(intMount, [
                    [tr('dashColRootSealed'), integrity.sealed ? tr('dashYes') : tr('dashNo')],
                    [tr('dashColRootReadonly'), integrity.readOnly ? tr('dashYes') : tr('dashNo')],
                    [tr('dashColIntegrityHint'), integrity.hint || '—']
                ]);
                if (integrity.mounts && integrity.mounts.length) {
                    var mountRows = integrity.mounts.map(function (m) {
                        return {
                            cells: [m.mount, m.device, m.flags],
                            haystack: [m.mount, m.device, m.flags].join('\n').toLowerCase()
                        };
                    });
                    var tableHost = document.createElement('div');
                    tableHost.style.marginTop = '0.75rem';
                    intMount.appendChild(tableHost);
                    A().mountDashFilterableTable(
                        tableHost,
                        [tr('dashColMount'), tr('dashColDevice'), tr('dashColFlags')],
                        mountRows,
                        { monoCols: { 0: true, 1: true } }
                    );
                }
            }
        }

        var collMeta = collectCollectionMeta(out);
        var cmCard = document.getElementById('iphone-collection-meta-card');
        var cmMount = document.getElementById('iphone-collection-meta-mount');
        if (cmCard && cmMount) {
            cmMount.textContent = '';
            if (!collMeta) {
                cmCard.classList.add('hidden');
            } else {
                cmCard.classList.remove('hidden');
                fillKvGrid(cmMount, [
                    [tr('dashColTaskSummary'), String(collMeta.taskCount)],
                    [tr('dashColCollectionErrors'), String(collMeta.errorCount)],
                    [tr('dashColCollectionSummaries'), String(collMeta.summaryCount)],
                    [tr('dashColSysdiagnoseLog'), collMeta.hasLog ? tr('dashYes') : tr('dashNo')]
                ]);
                if (collMeta.errorPaths && collMeta.errorPaths.length) {
                    var errHost = document.createElement('div');
                    errHost.style.marginTop = '0.75rem';
                    cmMount.appendChild(errHost);
                    A().mountDashFilterableTable(
                        errHost,
                        [tr('dashColPath')],
                        collMeta.errorPaths.map(function (p) {
                            return { cells: [p], haystack: String(p).toLowerCase() };
                        }),
                        { monoCols: { 0: true } }
                    );
                }
            }
        }

        var act = collectActivation(out);
        var actMount = document.getElementById('iphone-activation-mount');
        var actCard = document.getElementById('iphone-activation-card');
        if (actMount && actCard) {
            actMount.textContent = '';
            if (!act) {
                actCard.classList.add('hidden');
            } else {
                actCard.classList.remove('hidden');
                var actPairs = [
                    [tr('dashColState'), act.state],
                    [tr('dashColSoc'), act.soc],
                    [tr('dashColBaseband'), act.baseband],
                    [tr('dashDeviceBuild'), act.build]
                ];
                if (act.dcrtReq || act.dcrtResp || act.dcrtOther) {
                    actPairs.push([
                        tr('dashColDcrtBaa'),
                        tr('dashDcrtBaaCounts')
                            .replace('{req}', String(act.dcrtReq || 0))
                            .replace('{resp}', String(act.dcrtResp || 0))
                            .replace('{other}', String(act.dcrtOther || 0))
                    ]);
                }
                fillKvGrid(actMount, actPairs);
            }
        }

        fillTable(
            'iphone-ckks-card',
            'iphone-ckks-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            collectCkks(out).map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        fillTable(
            'iphone-ota-card',
            'iphone-ota-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            collectFileInventory(out, 'ota_update', 32).map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        fillTable(
            'iphone-usermgmt-card',
            'iphone-usermgmt-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            collectFileInventory(out, 'usermanagement', 24).map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        fillTable(
            'iphone-preferences-card',
            'iphone-preferences-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            collectFileInventory(out, 'preferences', 32).map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var paired = collectPaired(out);
        fillTable(
            'iphone-paired-card',
            'iphone-paired-mount',
            [tr('dashColName'), tr('dashColSection'), tr('dashColService'), tr('dashColWhen')],
            paired.map(function (d) {
                return {
                    cells: [d.name, d.section, d.service, d.added],
                    haystack: [d.name, d.section, d.service].join('\n').toLowerCase()
                };
            })
        );

        var iosvc = collectIoservice(out);
        var iosProps = iosvc
            ? iosvc.properties.map(function (p) {
                  return {
                      cells: [p.label, p.value],
                      haystack: [p.label, p.value].join('\n').toLowerCase()
                  };
              })
            : [];
        if (iosvc && iosvc.nodeCount && !iosProps.length) {
            iosProps.push({
                cells: [tr('dashIoserviceNodes'), String(iosvc.nodeCount)],
                haystack: 'ioservice nodes'
            });
        }
        fillTable(
            'iphone-ioservice-card',
            'iphone-ioservice-mount',
            [tr('dashColLabel'), tr('dashColValue')],
            iosProps,
            {
                monoCols: { 1: true },
                note:
                    iosvc && iosvc.nodeCount
                        ? tr('dashIoserviceNodeNote').replace('{n}', String(iosvc.nodeCount))
                        : ''
            }
        );

        var mdm = collectMdm(out);
        fillTable(
            'iphone-mdm-card',
            'iphone-mdm-mount',
            [tr('dashColPath'), tr('dashColPreview'), tr('dashColChars')],
            mdm.map(function (r) {
                return {
                    cells: [r.path, r.preview, r.chars],
                    haystack: [r.path, r.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var visible =
            accounts.length +
            storage.length +
            (integrity ? 1 : 0) +
            (collMeta ? 1 : 0) +
            (act ? 1 : 0) +
            paired.length +
            iosProps.length +
            mdm.length;
        ensurePanelEmpty('iphone-dash-overview', 'dashEmptyOverview', true);
        return {
            accounts: accounts.length,
            storage: storage.length,
            paired: paired.length,
            visible: visible
        };
    }

    function collectMdm(out) {
        var list = [];
        var ana = A().getAnalyserPayload ? A().getAnalyserPayload(out, 'mcstateshared') : null;
        if (ana && Array.isArray(ana.rows)) {
            asArr(ana.rows).forEach(function (row) {
                if (list.length >= 40) return;
                var r = plain(row);
                var path = String(r.path || '—');
                var preview = String(r.preview || r.value || '').slice(0, 120);
                list.push({
                    path: path,
                    preview: preview || '—',
                    chars: r.char_count != null ? String(r.char_count) : '—'
                });
            });
            if (list.length) return list;
        }
        ['mcstate_shared_profile', 'mcsettingsevents'].forEach(function (name) {
            var rows = events(out, name);
            for (var i = 0; i < rows.length && list.length < 40; i++) {
                var ev = plain(rows[i]);
                var path =
                    field(ev, 'path', 'source_path', 'profile') ||
                    field(ev, 'message').slice(0, 80) ||
                    name;
                var preview =
                    field(ev, 'preview', 'value', 'payload') ||
                    field(ev, 'message') ||
                    '—';
                list.push({
                    path: path,
                    preview: String(preview).slice(0, 120),
                    chars: '—'
                });
            }
        });
        return list;
    }

    /* ---------- Network leftovers ---------- */

    function collectInteractionUrls(out) {
        var rows = events(out, 'interactionc');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var url = field(ev, 'content url', 'content_url', 'url');
            var domain = field(ev, 'domain identifier', 'domain_identifier', 'domain');
            if (!url && !domain) continue;
            if (url && url.indexOf('://') < 0 && url.indexOf('.') < 0 && !domain) continue;
            var when = field(ev, 'timestamp', 'start', 'datetime') || '—';
            var key = url + ':' + domain + ':' + when;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                url: url || '—',
                domain: domain || '—',
                context: field(ev, 'context text', 'context_text', 'content text') || '—',
                when: when
            });
        }
        return list;
    }

    function collectPlistUrls(out) {
        var rows = events(out, 'plists');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var url = field(ev, 'url', 'destination_domain') || field(ev, 'message');
            if (!url || (url.indexOf('://') < 0 && url.indexOf('.') < 0)) continue;
            var path = field(ev, 'plist_path', 'plist path') || '—';
            var key = path + ':' + field(ev, 'plist_key', 'plist key') + ':' + url;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                url: url,
                path: path,
                key: field(ev, 'plist_key', 'plist key') || '—'
            });
        }
        return list;
    }

    function collectPowerlogUsage(out) {
        var rows = events(out, 'powerlogs');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var mod = field(ev, 'apollo_module', 'module');
            var msg = field(ev, 'message');
            if (mod !== 'powerlog_process_data_usage' && !/process data usage/i.test(msg)) continue;
            var bundle = field(ev, 'bundle id', 'bundleid', 'bundle_id') || '—';
            var proc = field(ev, 'process name', 'processname', 'process_name') || '—';
            var wifiIn = formatBytes(field(ev, 'wifi in', 'wifiin'));
            var wifiOut = formatBytes(field(ev, 'wifi out', 'wifiout'));
            var cellIn = formatBytes(field(ev, 'cell in', 'cellin'));
            var cellOut = formatBytes(field(ev, 'cell out', 'cellout'));
            if (wifiIn === '—' && wifiOut === '—' && cellIn === '—' && cellOut === '—') continue;
            var key = bundle + ':' + proc + ':' + wifiIn + ':' + cellIn;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({ bundle: bundle, proc: proc, wifiIn: wifiIn, wifiOut: wifiOut, cellIn: cellIn, cellOut: cellOut });
        }
        return list;
    }

    function collectTransparency(out) {
        var rows = events(out, 'transparency_json');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var uri = field(ev, 'contact_uri', 'contact uri');
            if (!uri) {
                var m = field(ev, 'message').match(/im:\/\/(?:mailto|tel):[^\s]+/);
                uri = m ? m[0] : '';
            }
            if (!uri || uri.indexOf('im://') !== 0) continue;
            if (seen[uri]) continue;
            seen[uri] = true;
            var kind = uri.indexOf('mailto:') >= 0 ? 'mailto' : uri.indexOf('tel:') >= 0 ? 'tel' : 'other';
            list.push({
                uri: uri,
                kind: kind,
                label: uri.replace(/^im:\/\/(mailto|tel):/, '')
            });
        }
        return list.sort(function (a, b) {
            return a.label.localeCompare(b.label);
        });
    }

    function renderNetworkExtras(out) {
        var interaction = collectInteractionUrls(out);
        fillTable(
            'iphone-network-interaction-card',
            'iphone-network-interaction-mount',
            [tr('dashColDomain'), tr('dashColValue'), tr('dashColContext'), tr('dashColWhen')],
            interaction.map(function (v) {
                return {
                    cells: [v.domain, v.url, v.context, v.when],
                    haystack: [v.domain, v.url, v.context].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true } }
        );

        var plists = collectPlistUrls(out);
        fillTable(
            'iphone-network-plist-card',
            'iphone-network-plist-mount',
            [tr('dashColValue'), tr('dashColPath'), tr('dashColKey')],
            plists.map(function (v) {
                return {
                    cells: [v.url, v.path, v.key],
                    haystack: [v.url, v.path, v.key].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true } }
        );

        var usage = collectPowerlogUsage(out);
        fillTable(
            'iphone-network-powerlog-card',
            'iphone-network-powerlog-mount',
            [
                tr('dashColBundle'),
                tr('dashColProcess'),
                tr('dashColWifiIn'),
                tr('dashColWifiOut'),
                tr('dashColCellIn'),
                tr('dashColCellOut')
            ],
            usage.map(function (v) {
                return {
                    cells: [v.bundle, v.proc, v.wifiIn, v.wifiOut, v.cellIn, v.cellOut],
                    haystack: [v.bundle, v.proc].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true } }
        );

        var contacts = collectTransparency(out);
        fillTable(
            'iphone-network-transparency-card',
            'iphone-network-transparency-mount',
            [tr('dashColKind'), tr('dashColLabel'), tr('dashColValue')],
            contacts.map(function (v) {
                return {
                    cells: [v.kind, v.label, v.uri],
                    haystack: [v.kind, v.label, v.uri].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 1: true, 2: true } }
        );

        return interaction.length + plists.length + usage.length + contacts.length;
    }

    /* ---------- External devices ---------- */

    function wifiSecurityKind(security) {
        var s = String(security || '')
            .trim()
            .toLowerCase();
        if (!s || s === '—' || s === '-') return 'unknown';
        if (/\b(none|open|os)\b/.test(s) || s === '0') return 'open';
        if (/\bwep\b/.test(s)) return 'wep';
        if (/\b(eap|enterprise|802\.1x)\b/.test(s)) return 'enterprise';
        if (/\b(wpa|rsn|sae|owe|psk)\b/.test(s)) return 'wpa';
        return 'unknown';
    }

    function collectWifiScan(out) {
        var rows = events(out, 'wifiscan');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 60; i++) {
            var ev = plain(rows[i]);
            var msg = field(ev, 'message');
            if (!field(ev, 'ssid') && (/^Wifi scan:\s*total=/i.test(msg) || msg.indexOf('total=') === 0)) continue;
            var ssid = field(ev, 'ssid') || (msg.match(/^(\S+)/) || [])[1] || '';
            if (!ssid && !field(ev, 'channel') && !field(ev, 'rssi')) continue;
            var bssid = field(ev, 'bssid', 'BSSID') || '';
            var channel = field(ev, 'channel', 'ch') || '—';
            var rssi = field(ev, 'rssi', 'RSSI') || '—';
            var security = field(ev, 'security') || '—';
            var key = ssid + ':' + bssid + ':' + channel + ':' + rssi;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                ssid: ssid || '<unknown>',
                bssid: bssid || '—',
                channel: channel,
                rssi: rssi === '—' ? '—' : /dBm/i.test(rssi) ? rssi : rssi + ' dBm',
                security: security,
                kind: wifiSecurityKind(security)
            });
        }
        return list;
    }

    function collectWifiSaved(out) {
        var rows = events(out, 'wifinetworks');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 60; i++) {
            var ev = plain(rows[i]);
            var msg = field(ev, 'message');
            if (/BSS location/i.test(msg)) continue;
            if (field(ev, 'latitude') || field(ev, 'longitude')) continue;
            var ssid = field(ev, 'ssid');
            if (!ssid) continue;
            var file = field(ev, 'file') || '';
            var key = ssid + ':' + file + ':' + field(ev, 'network_key', 'network key');
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                ssid: ssid,
                bssid: field(ev, 'bssid') || '—',
                channel: field(ev, 'channel') || '—',
                added: field(ev, 'timestamp_raw', 'added_at', 'AddedAt') || field(ev, 'datetime') || '—'
            });
        }
        return list;
    }

    function collectWifiKnown(out) {
        var rows = events(out, 'wifi_known_networks');
        var geo = A().getAnalyserPayload ? A().getAnalyserPayload(out, 'wifi_geolocation') : null;
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 60; i++) {
            var ev = plain(rows[i]);
            var lat = field(ev, 'latitude');
            var lon = field(ev, 'longitude');
            if (!lat || !lon) continue;
            var ssid = field(ev, 'ssid') || '—';
            var bssid = field(ev, 'bssid') || '';
            var key = ssid + ':' + bssid + ':' + lat + ':' + lon;
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                ssid: ssid,
                bssid: bssid || '—',
                lat: lat,
                lon: lon,
                channel: field(ev, 'channel') || '—',
                when: field(ev, 'timestamp_raw', 'datetime') || '—'
            });
        }
        if (!list.length && geo && typeof geo.xml === 'string' && geo.xml) {
            try {
                var doc = new DOMParser().parseFromString(geo.xml, 'text/xml');
                if (!doc.querySelector('parsererror')) {
                    var wpts = doc.querySelectorAll('wpt');
                    for (var wi = 0; wi < wpts.length && list.length < 60; wi++) {
                        var pt = wpts[wi];
                        var nmEl = pt.querySelector('name');
                        var tmEl = pt.querySelector('time');
                        list.push({
                            ssid: nmEl && nmEl.textContent ? nmEl.textContent : '—',
                            bssid: '—',
                            lat: pt.getAttribute('lat') || '—',
                            lon: pt.getAttribute('lon') || '—',
                            channel: '—',
                            when: tmEl && tmEl.textContent ? tmEl.textContent : '—'
                        });
                    }
                }
            } catch (e) {
                /* ignore malformed GPX */
            }
        }
        return list;
    }

    function collectWifiSecurity(out) {
        var rows = events(out, 'wifisecurity');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var label = field(ev, 'labl', 'label') || field(ev, 'acct', 'account');
            if (!label) continue;
            var account = field(ev, 'acct', 'account') || '—';
            var key = label + ':' + account + ':' + field(ev, 'cdat');
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                label: label,
                account: account,
                desc: field(ev, 'desc', 'description') || '—',
                created: field(ev, 'cdat', 'created') || '—'
            });
        }
        return list;
    }

    function pickUsbField(obj, names) {
        if (!obj || typeof obj !== 'object') return '';
        for (var i = 0; i < names.length; i++) {
            var n = names[i];
            if (obj[n] != null && typeof obj[n] !== 'object') return String(obj[n]).trim();
            var lower = n.toLowerCase();
            var keys = Object.keys(obj);
            for (var k = 0; k < keys.length; k++) {
                if (keys[k].toLowerCase() === lower && typeof obj[keys[k]] !== 'object') {
                    return String(obj[keys[k]]).trim();
                }
            }
        }
        return '';
    }

    function walkIousbTree(node, devices, seen, depth) {
        if (!node || devices.length >= 40 || depth > 14) return;
        if (Array.isArray(node)) {
            for (var ai = 0; ai < node.length; ai++) walkIousbTree(node[ai], devices, seen, depth + 1);
            return;
        }
        if (typeof node !== 'object') return;

        var product = pickUsbField(node, [
            'USB Product Name',
            'USBProductName',
            'usb product name',
            'kUSBProductString',
            'Product Name'
        ]);
        var vendor = pickUsbField(node, [
            'USB Vendor Name',
            'USBVendorName',
            'usb vendor name',
            'kUSBVendorString',
            'Vendor Name'
        ]);
        var idVendor = pickUsbField(node, ['idVendor', 'id vendor', 'VendorID']);
        var idProduct = pickUsbField(node, ['idProduct', 'id product', 'ProductID']);
        var serial = pickUsbField(node, [
            'USB Serial Number',
            'USBSerialNumber',
            'usb serial number',
            'kUSBSerialNumberString',
            'Serial Number'
        ]);
        if (product || (idVendor && idProduct) || serial) {
            var key =
                product + '|' + vendor + '|' + idVendor + '|' + idProduct + '|' + serial;
            if (!seen[key]) {
                seen[key] = true;
                devices.push({
                    product: product || tr('dashUsbDeviceFallback'),
                    vendor: vendor || '—',
                    ids: (idVendor || '—') + ':' + (idProduct || '—'),
                    serial: serial || '—',
                    when: '—'
                });
            }
        }

        var keys = Object.keys(node);
        for (var i = 0; i < keys.length; i++) {
            var child = node[keys[i]];
            if (child && typeof child === 'object') walkIousbTree(child, devices, seen, depth + 1);
        }
    }

    function collectUsb(out) {
        var devices = [];
        var seen = {};

        var data = A().getParserPayload ? A().getParserPayload(out, 'iousb') : null;
        if (data && typeof data === 'object') {
            if (data.tree) walkIousbTree(data.tree, devices, seen, 0);
            else walkIousbTree(data, devices, seen, 0);
        }

        if (!devices.length) {
            var rows = events(out, 'iousb');
            for (var i = 0; i < rows.length && devices.length < 40; i++) {
                var ev = plain(rows[i]);
                var kind = field(ev, 'usb_kind', 'event_type').toLowerCase();
                if (kind.indexOf('summary') >= 0 || field(ev, 'action') === 'iousb_summary') continue;
                var product =
                    field(ev, 'usb_product', 'usb product') ||
                    field(ev, 'node_name', 'node name') ||
                    field(ev, 'action') ||
                    '';
                var vendor = field(ev, 'usb_vendor', 'usb vendor') || field(ev, 'app_name') || '—';
                var idVendor = field(ev, 'id_vendor', 'id vendor') || '—';
                var idProduct = field(ev, 'id_product', 'id product') || '—';
                var serial = field(ev, 'usb_serial', 'usb serial') || '—';
                if (!product && idVendor === '—' && idProduct === '—' && serial === '—') continue;
                var key = product + '|' + vendor + '|' + idVendor + '|' + idProduct + '|' + serial;
                if (seen[key]) continue;
                seen[key] = true;
                devices.push({
                    product: product || tr('dashUsbDeviceFallback'),
                    vendor: vendor,
                    ids: idVendor + ':' + idProduct,
                    serial: serial,
                    when: field(ev, 'datetime', 'timestamp') || '—'
                });
            }
        }

        var lockdownRows = events(out, 'lockdownd');
        var lockdown = [];
        var lseen = {};
        for (var j = 0; j < lockdownRows.length && lockdown.length < 40; j++) {
            var lev = plain(lockdownRows[j]);
            var message = field(lev, 'message');
            if (!message) continue;
            var low = message.toLowerCase();
            if (
                !(
                    low.indexOf('usb') >= 0 ||
                    low.indexOf('usbmux') >= 0 ||
                    low.indexOf('pair') >= 0 ||
                    low.indexOf('trust') >= 0
                )
            ) {
                continue;
            }
            if (low.indexOf('hostmaypairwithoptions') >= 0) continue;
            if (low.indexOf('allowing pairing from connection') >= 0) continue;
            var title = message.length > 100 ? message.slice(0, 97) + '…' : message;
            var lk = title + ':' + field(lev, 'datetime');
            if (lseen[lk]) continue;
            lseen[lk] = true;
            lockdown.push({
                title: title,
                when: field(lev, 'datetime', 'timestamp') || '—'
            });
        }
        return { devices: devices, lockdown: lockdown };
    }

    function renderExternalPanel(out) {
        var scan = collectWifiScan(out);
        fillTable(
            'iphone-wifi-scan-card',
            'iphone-wifi-scan-mount',
            [tr('dashColSsid'), tr('dashColBssid'), tr('dashColChannel'), tr('dashColRssi'), tr('dashColSecurity')],
            scan.map(function (v) {
                return {
                    cells: [v.ssid, v.bssid, v.channel, v.rssi, v.security],
                    haystack: [v.ssid, v.bssid, v.security].join('\n').toLowerCase(),
                    kind: v.kind
                };
            }),
            { monoCols: { 0: true, 1: true }, kindChips: true }
        );

        var saved = collectWifiSaved(out);
        fillTable(
            'iphone-wifi-saved-card',
            'iphone-wifi-saved-mount',
            [tr('dashColSsid'), tr('dashColBssid'), tr('dashColChannel'), tr('dashColWhen')],
            saved.map(function (v) {
                return {
                    cells: [v.ssid, v.bssid, v.channel, v.added],
                    haystack: [v.ssid, v.bssid].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true } }
        );

        var known = collectWifiKnown(out);
        var geo = A().getAnalyserPayload ? A().getAnalyserPayload(out, 'wifi_geolocation') : null;
        var hasGeoXml = !!(geo && typeof geo.xml === 'string' && geo.xml);
        fillTable(
            'iphone-wifi-known-card',
            'iphone-wifi-known-mount',
            [
                tr('dashColSsid'),
                tr('dashColBssid'),
                tr('dashColLat'),
                tr('dashColLon'),
                tr('dashColChannel'),
                tr('dashColWhen')
            ],
            known.map(function (v) {
                return {
                    cells: [v.ssid, v.bssid, v.lat, v.lon, v.channel || '—', v.when],
                    haystack: [v.ssid, v.bssid, v.lat, v.lon, v.channel].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true, 2: true, 3: true } }
        );
        if (hasGeoXml) {
            setCard('iphone-wifi-known-card', true);
            var geoMount = document.getElementById('iphone-wifi-known-mount');
            if (geoMount) {
                if (!known.length) {
                    var note = document.createElement('p');
                    note.className = 'iphone-dash-card__lead';
                    note.textContent = tr('dashWifiKnownBlurb');
                    geoMount.appendChild(note);
                }
                var dl = document.createElement('a');
                dl.className = 'iphone-dash-download';
                dl.style.cssText =
                    'display:inline-block;margin:0.5rem 0 0;padding:0.35rem 0.75rem;background:var(--accent);color:#fff;border-radius:6px;text-decoration:none;font-size:0.8125rem;';
                dl.href = URL.createObjectURL(new Blob([geo.xml], { type: 'application/gpx+xml' }));
                dl.download = 'wifi-geolocation.gpx';
                dl.textContent = tr('dashDownloadGpx');
                geoMount.appendChild(dl);
            }
        }

        var sec = collectWifiSecurity(out);
        fillTable(
            'iphone-wifi-security-card',
            'iphone-wifi-security-mount',
            [tr('dashColLabel'), tr('dashColAccount'), tr('dashColDesc'), tr('dashColWhen')],
            sec.map(function (v) {
                return {
                    cells: [v.label, v.account, v.desc, v.created],
                    haystack: [v.label, v.account, v.desc].join('\n').toLowerCase()
                };
            })
        );

        var usb = collectUsb(out);
        fillTable(
            'iphone-usb-devices-card',
            'iphone-usb-devices-mount',
            [tr('dashColProduct'), tr('dashColVendor'), tr('dashColIds'), tr('dashColSerial'), tr('dashColWhen')],
            usb.devices.map(function (v) {
                return {
                    cells: [v.product, v.vendor, v.ids, v.serial, v.when],
                    haystack: [v.product, v.vendor, v.serial].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 2: true, 3: true } }
        );
        fillTable(
            'iphone-usb-lockdown-card',
            'iphone-usb-lockdown-mount',
            [tr('dashColEvent'), tr('dashColWhen')],
            usb.lockdown.map(function (v) {
                return {
                    cells: [v.title, v.when],
                    haystack: v.title.toLowerCase()
                };
            })
        );

        var bt = collectFileInventory(out, 'bluetooth', 40);
        fillTable(
            'iphone-bluetooth-card',
            'iphone-bluetooth-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            bt.map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var wifiDiag = collectFileInventory(out, 'wifi_diagnostics', 40);
        fillTable(
            'iphone-wifi-diag-card',
            'iphone-wifi-diag-mount',
            [tr('dashColFile'), tr('dashColPreview'), tr('dashColChars')],
            wifiDiag.map(function (f) {
                return {
                    cells: [f.name, f.preview, f.size],
                    haystack: [f.path, f.preview].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var total =
            scan.length +
            saved.length +
            known.length +
            sec.length +
            usb.devices.length +
            usb.lockdown.length +
            bt.length +
            wifiDiag.length;
        ensurePanelEmpty('iphone-dash-external', 'dashEmptyExternal', total > 0);
        return total;
    }

    function renderProcessesExtras(out) {
        var rb = collectRunningboard(out);
        var card = document.getElementById('iphone-runningboard-card');
        var mount = document.getElementById('iphone-runningboard-mount');
        if (!card || !mount) return 0;
        mount.textContent = '';
        if (!rb) {
            card.classList.add('hidden');
            return 0;
        }
        card.classList.remove('hidden');
        fillKvGrid(mount, [
            [tr('dashColJetsamBands'), rb.jetsam.length ? rb.jetsam.join(', ') : '—'],
            [tr('dashColDomainHints'), String(rb.domains.length)]
        ]);
        if (rb.domains.length) {
            var host = document.createElement('div');
            host.style.marginTop = '0.75rem';
            mount.appendChild(host);
            A().mountDashFilterableTable(
                host,
                [tr('dashColDomain')],
                rb.domains.map(function (d) {
                    return { cells: [d], haystack: String(d).toLowerCase() };
                }),
                { monoCols: { 0: true } }
            );
        }
        return rb.domains.length || 1;
    }

    /* ---------- Authentication (aligned with mobipwn iosLockState) ---------- */

    function scrapeMessageValue(message, key) {
        var lowerMsg = String(message || '').toLowerCase();
        var lowerKey = String(key || '').toLowerCase();
        var needles = [', ' + lowerKey + '=', ': ' + lowerKey + '=', ':' + lowerKey + '='];
        for (var i = 0; i < needles.length; i++) {
            var idx = lowerMsg.indexOf(needles[i]);
            if (idx < 0) continue;
            var rest = String(message).slice(idx + needles[i].length);
            var token = (rest.split(',')[0] || '').trim();
            if (token) return token;
        }
        return '';
    }

    function normalizeLockKind(raw) {
        var v = String(raw || '')
            .trim()
            .toLowerCase()
            .replace(/_/g, ' ');
        if (!v) return 'unknown';
        // Activity titles alone are not a lock/unlock state.
        if (v === 'lock state' || v === 'device lock status' || v === 'screen unlock state') {
            return 'unknown';
        }
        if (/fail|denied|lockout|incorrect|invalid/.test(v)) return 'failed';
        if (v.indexOf('unlock') !== -1 || v === '0' || v === 'false' || v === 'no' || v === 'device unlocked') {
            return 'unlocked';
        }
        if ((v.indexOf('lock') !== -1 && v.indexOf('unlock') === -1) || v === '1' || v === 'true' || v === 'yes' || v === 'device locked') {
            return 'locked';
        }
        if (/autolock|auto lock/.test(v)) return 'autolock';
        return 'unknown';
    }

    function parseAuthSuccessField(ev) {
        // Prefer stamped auth_success; avoid generic parser "success" wrappers when event_type is absent.
        var raw = field(ev, 'auth_success');
        if (!raw) {
            var eventType = field(ev, 'event_type');
            if (eventType === 'authentication_event') raw = field(ev, 'success');
        }
        if (raw === 'true' || raw === '1') return true;
        if (raw === 'false' || raw === '0') return false;
        return null;
    }

    /** Classify one parser row into a lock/auth event, or null. */
    function parseIosLockEvent(ev, parserName) {
        ev = plain(ev);
        var msg = field(ev, 'message');
        var desc = field(ev, 'timestamp_desc', 'timestamp desc', 'activity');
        var apollo = field(ev, 'apollo_module', 'module');
        var eventType = field(ev, 'event_type');
        var authType = field(ev, 'auth_type') || 'passcode';
        var authSuccess = parseAuthSuccessField(ev);

        if (
            /before first unlock/i.test(msg) ||
            /companions not supported/i.test(msg) ||
            /Code=-1000/i.test(msg)
        ) {
            return null;
        }

        var looksFail =
            authSuccess === false ||
            /processed authentication request \(success\s*=\s*no\)/i.test(msg) ||
            /unlock attempt succeeded:\s*no/i.test(msg) ||
            /identity match failed/i.test(msg) ||
            /processMatchFailReason/i.test(msg) ||
            /passcode authentication failed/i.test(msg) ||
            /biometry is locked/i.test(msg) ||
            /needs passcode bio lockout/i.test(msg) ||
            (/code=-8/i.test(msg) && /biom/i.test(msg) && /locked out/i.test(msg)) ||
            /device authentication is (now )?locked out/i.test(msg);

        var looksOk =
            authSuccess === true ||
            /processed authentication request \(success\s*=\s*yes\)/i.test(msg) ||
            /unlock attempt succeeded:\s*yes/i.test(msg) ||
            /passcode authentication succeeded/i.test(msg) ||
            /bio unlocked/i.test(msg);

        var isAuthEvent =
            eventType === 'authentication_event' ||
            looksFail ||
            looksOk ||
            /^Authentication (Failed|Succeeded)$/i.test(desc);

        var isLockActivity =
            isAuthEvent ||
            /^Lock State$/i.test(desc) ||
            /^Device Lock Status$/i.test(desc) ||
            /^Keybag Lock Status$/i.test(desc) ||
            /^Screen Unlock State$/i.test(desc) ||
            /^Lock State:/i.test(msg) ||
            /^Device Lock Status:/i.test(msg) ||
            /^Keybag Lock Status:/i.test(msg) ||
            /^Screen Unlock State:/i.test(msg) ||
            /DEVICE (UN)?LOCKED/i.test(msg) ||
            Boolean(field(ev, 'lock_status', 'is_locked', 'auto_lock_type')) ||
            apollo === 'powerlog_device_lock_state' ||
            apollo === 'powerlog_device_screen_autolock' ||
            apollo === 'knowledge_device_locked' ||
            apollo === 'knowledge_device_locked_imputed' ||
            apollo === 'knowledge_device_keybag_locked' ||
            apollo === 'coreduetd_device_lock_state';

        if (!isLockActivity) return null;

        if (looksFail) {
            return {
                kind: 'failed',
                when: field(ev, 'datetime', 'timestamp') || '—',
                source: parserName === 'logarchive' ? 'Unified log' : parserName === 'lockdownd' ? 'Lockdown' : parserName,
                detail:
                    authType === 'biometric'
                        ? 'Biometric authentication failed'
                        : 'Passcode / unlock failed',
                message: (msg || desc || '—').slice(0, 180)
            };
        }

        var statusRaw =
            field(ev, 'lock_status', 'is_locked', 'auto_lock_type', 'lock status', 'is locked') ||
            scrapeMessageValue(msg, 'LOCK STATUS') ||
            scrapeMessageValue(msg, 'lock status') ||
            scrapeMessageValue(msg, 'IS LOCKED') ||
            scrapeMessageValue(msg, 'AUTO LOCK TYPE') ||
            '';

        var kind = normalizeLockKind(statusRaw);
        if (kind === 'unknown' && looksOk) kind = 'unlocked';
        if (kind === 'unknown' && /^Screen Unlock State/i.test(desc || msg)) kind = 'autolock';
        if (kind === 'unknown') {
            if (/DEVICE UNLOCKED/i.test(msg) || /\bunlocked\b/i.test(msg)) kind = 'unlocked';
            else if (/DEVICE LOCKED/i.test(msg) || /\blocked\b/i.test(msg)) kind = 'locked';
        }
        if (kind === 'unknown' && isAuthEvent && looksOk) kind = 'unlocked';
        if (kind === 'unknown') return null;

        var source =
            parserName === 'knowledgec'
                ? 'KnowledgeC'
                : parserName === 'logarchive'
                  ? 'Unified log'
                  : parserName === 'lockdownd'
                    ? 'Lockdown'
                    : apollo.indexOf('autolock') !== -1 || /^Screen Unlock State/i.test(desc || msg)
                      ? 'Powerlog auto-lock'
                      : parserName === 'powerlogs'
                        ? 'Powerlog'
                        : parserName;

        var detail =
            kind === 'unlocked'
                ? 'Device unlocked'
                : kind === 'locked'
                  ? 'Device locked'
                  : kind === 'autolock'
                    ? statusRaw || 'Auto-lock'
                    : statusRaw || desc || 'Lock state';

        return {
            kind: kind,
            when: field(ev, 'datetime', 'timestamp') || '—',
            source: source,
            detail: detail,
            message: (msg || desc || '—').slice(0, 180)
        };
    }

    function collectLockEvents(out) {
        var parsers = [
            { name: 'powerlogs', cap: 8000 },
            { name: 'knowledgec', cap: 8000 },
            { name: 'lockdownd', cap: 4000 },
            { name: 'logarchive', cap: 50000 }
        ];
        var list = [];
        var seen = {};
        for (var pi = 0; pi < parsers.length; pi++) {
            var rows = events(out, parsers[pi].name);
            var limit = Math.min(rows.length, parsers[pi].cap);
            for (var i = 0; i < limit && list.length < 250; i++) {
                var parsed = parseIosLockEvent(rows[i], parsers[pi].name);
                if (!parsed) continue;
                var key = parsed.kind + ':' + parsed.when + ':' + parsed.detail + ':' + parsed.source + ':' + parsed.message;
                if (seen[key]) continue;
                seen[key] = true;
                list.push(parsed);
            }
        }
        return list;
    }

    function renderAuthPanel(out) {
        var eventsList = collectLockEvents(out);
        var summary = { unlocked: 0, locked: 0, autolock: 0, failed: 0 };
        eventsList.forEach(function (e) {
            if (summary[e.kind] != null) summary[e.kind] += 1;
        });
        var sumMount = document.getElementById('iphone-auth-summary-mount');
        var sumCard = document.getElementById('iphone-auth-summary-card');
        if (sumMount && sumCard) {
            sumMount.textContent = '';
            if (!eventsList.length) {
                sumCard.classList.add('hidden');
            } else {
                sumCard.classList.remove('hidden');
                var grid = document.createElement('div');
                grid.className = 'result-grid';
                [
                    [tr('dashAuthUnlocked'), summary.unlocked],
                    [tr('dashAuthLocked'), summary.locked],
                    [tr('dashAuthAutolock'), summary.autolock],
                    [tr('dashAuthFailed'), summary.failed]
                ].forEach(function (pair) {
                    var item = document.createElement('div');
                    item.className = 'result-item';
                    item.innerHTML =
                        '<div class="result-item-label">' +
                        (A().escapeHtmlIphone ? A().escapeHtmlIphone(pair[0]) : pair[0]) +
                        '</div><div class="result-item-value">' +
                        pair[1] +
                        '</div>';
                    grid.appendChild(item);
                });
                sumMount.appendChild(grid);
            }
        }
        fillTable(
            'iphone-auth-events-card',
            'iphone-auth-events-mount',
            [tr('dashColKind'), tr('dashColWhen'), tr('dashColSource'), tr('dashColDetail'), tr('dashColMessage')],
            eventsList.map(function (v) {
                return {
                    kind: v.kind,
                    cells: [v.kind, v.when, v.source, v.detail, v.message],
                    haystack: [v.kind, v.source, v.detail, v.message].join('\n').toLowerCase()
                };
            }),
            { kindChips: true, monoCols: { 2: true } }
        );
        ensurePanelEmpty('iphone-dash-auth', 'dashEmptyAuth', eventsList.length > 0);
        return eventsList.length;
    }

    /* ---------- Battery ---------- */

    function parseBatteryTimeMs(raw) {
        if (raw == null || raw === '' || raw === '—') return null;
        if (typeof raw === 'number' && Number.isFinite(raw)) {
            return raw < 1e12 ? Math.round(raw * 1000) : Math.round(raw);
        }
        var s = String(raw).trim();
        if (!s) return null;
        if (/^\d+(\.\d+)?$/.test(s)) {
            var n = Number(s);
            if (!Number.isFinite(n)) return null;
            return n < 1e12 ? Math.round(n * 1000) : Math.round(n);
        }
        var ms = Date.parse(s);
        if (!Number.isFinite(ms)) {
            // "YYYY-MM-DD HH:MM:SS" without TZ → treat as UTC
            ms = Date.parse(s.replace(' ', 'T') + 'Z');
        }
        return Number.isFinite(ms) ? ms : null;
    }

    function parseBatterySoc(raw) {
        if (raw == null || raw === '' || raw === '—') return null;
        var n = Number(String(raw).replace('%', '').trim());
        if (!Number.isFinite(n)) return null;
        if (n > 0 && n <= 1) n = n * 100;
        return Math.max(0, Math.min(100, n));
    }

    function isTruthyBatteryFlag(v) {
        var s = String(v == null ? '' : v).trim().toLowerCase();
        return s === '1' || s === 'true' || s === 'yes' || s === 'charging';
    }

    function downsampleSeries(points, maxPts) {
        if (!points || points.length <= maxPts) return points || [];
        var out = [];
        var step = (points.length - 1) / (maxPts - 1);
        for (var i = 0; i < maxPts; i++) {
            var idx = Math.round(i * step);
            out.push(points[idx]);
        }
        // Always keep last point exact
        out[out.length - 1] = points[points.length - 1];
        return out;
    }

    function formatChartSpan(ms) {
        if (ms < 3600000) return Math.max(1, Math.round(ms / 60000)) + ' min';
        if (ms < 86400000) return (ms / 3600000).toFixed(1) + ' h';
        return (ms / 86400000).toFixed(1) + ' d';
    }

    function formatChartTick(ms) {
        try {
            var d = new Date(ms);
            if (!Number.isFinite(d.getTime())) return '—';
            return d.toISOString().replace('T', ' ').slice(0, 16);
        } catch (e) {
            return '—';
        }
    }

    function collectBattery(out) {
        var rows = events(out, 'battery_bdc');
        var byType = {};
        var seriesRaw = [];
        var seenT = {};

        function pushSeriesPoint(whenRaw, type, socRaw, chargingRaw, externalRaw) {
            var level = parseBatterySoc(socRaw);
            if (level == null) return;
            var t = parseBatteryTimeMs(whenRaw);
            var charging = isTruthyBatteryFlag(chargingRaw);
            var external = isTruthyBatteryFlag(externalRaw);
            var when = whenRaw ? String(whenRaw) : t != null ? formatChartTick(t) : '—';
            // Prefer timed points for the graph; still keep table rows without time.
            if (t != null) {
                var key = t + ':' + Math.round(level) + ':' + (charging ? 1 : 0);
                if (!seenT[key]) {
                    seenT[key] = true;
                    seriesRaw.push({
                        t: t,
                        level: level,
                        charging: charging,
                        external: external,
                        when: when,
                        type: type || 'BDC'
                    });
                }
            }
        }

        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var type = field(ev, 'type') || 'BDC';
            if (!byType[type]) byType[type] = {};
            [
                'StateOfCharge',
                'IsCharging',
                'ExternalConnected',
                'AppleRawExternalConnected',
                'Temperature',
                'Voltage',
                'InstantAmperage',
                'DesignCapacity',
                'MaxCapacity',
                'FullyCharged',
                'AtCriticalLevel',
                'AtWarnLevel'
            ].forEach(function (k) {
                var v = field(ev, k);
                if (v && !byType[type][k]) byType[type][k] = v;
            });
            pushSeriesPoint(
                field(ev, 'datetime', 'timestamp', 'TimeStamp'),
                type,
                field(ev, 'StateOfCharge'),
                field(ev, 'IsCharging'),
                field(ev, 'ExternalConnected', 'AppleRawExternalConnected')
            );
        }

        var sbc = byType.BDC_SBC || byType.BDC || {};
        var once = byType.BDC_Once || {};
        var obc = byType.BDC_OBC || {};
        var soc = sbc.StateOfCharge || once.StateOfCharge || '';
        var charging = isTruthyBatteryFlag(sbc.IsCharging);
        var external =
            isTruthyBatteryFlag(obc.ExternalConnected) ||
            isTruthyBatteryFlag(obc.AppleRawExternalConnected);
        var badges = [];
        if (charging) badges.push(tr('dashBattCharging'));
        if (external) badges.push(tr('dashBattExternal'));
        if (isTruthyBatteryFlag(sbc.FullyCharged)) badges.push(tr('dashBattFullyCharged'));
        if (isTruthyBatteryFlag(sbc.AtCriticalLevel)) badges.push(tr('dashBattCritical'));
        if (isTruthyBatteryFlag(sbc.AtWarnLevel)) badges.push(tr('dashBattLow'));

        var fields = [];
        function pushField(label, value) {
            if (value) fields.push({ label: label, value: value });
        }
        pushField(tr('dashBattSoc'), soc ? soc + '%' : '');
        pushField(tr('dashBattTemp'), sbc.Temperature || once.Temperature);
        pushField(tr('dashBattVoltage'), sbc.Voltage || once.Voltage);
        pushField(tr('dashBattAmperage'), sbc.InstantAmperage);
        pushField(tr('dashBattDesign'), once.DesignCapacity);
        pushField(tr('dashBattMax'), once.MaxCapacity);
        var designN = Number(once.DesignCapacity);
        var maxN = Number(once.MaxCapacity);
        if (Number.isFinite(designN) && designN > 0 && Number.isFinite(maxN) && maxN > 0) {
            pushField(tr('dashBattHealth'), Math.round((maxN / designN) * 100) + '%');
        }

        // Powerlogs battery level — primary timeline when BDC is sparse
        var pl = events(out, 'powerlogs');
        var plCap = Math.min(pl.length, 12000);
        for (var j = 0; j < plCap; j++) {
            var pev = plain(pl[j]);
            var mod = field(pev, 'apollo_module', 'module');
            var pmsg = field(pev, 'message');
            if (mod !== 'powerlog_battery_level' && !/battery level/i.test(pmsg)) continue;
            pushSeriesPoint(
                field(pev, 'datetime', 'timestamp'),
                'Battery Level',
                field(pev, 'level', 'battery level', 'raw_level', 'StateOfCharge'),
                field(pev, 'is charging', 'is_charging', 'IsCharging'),
                field(pev, 'ExternalConnected')
            );
        }

        seriesRaw.sort(function (a, b) {
            return a.t - b.t;
        });
        if (!soc && seriesRaw.length) {
            soc = String(Math.round(seriesRaw[seriesRaw.length - 1].level));
        }

        var series = downsampleSeries(seriesRaw, 360);
        var samples = seriesRaw.slice(-40).reverse().map(function (p) {
            return {
                when: p.when,
                type: p.type,
                soc: String(Math.round(p.level)),
                charging: p.charging ? '1' : '0',
                external: p.external ? '1' : '0'
            };
        });

        if (!soc && !fields.length && !series.length && !samples.length) return null;
        return {
            soc: soc,
            badges: badges,
            fields: fields,
            samples: samples,
            series: series,
            seriesCount: seriesRaw.length
        };
    }

    function renderBatterySocChart(series, totalCount) {
        var mount = document.getElementById('iphone-battery-chart-mount');
        var card = document.getElementById('iphone-battery-chart-card');
        var caption = document.getElementById('iphone-battery-chart-caption');
        if (!mount || !card) return 0;
        mount.textContent = '';
        if (caption) caption.textContent = '';

        if (!series || series.length < 2) {
            card.classList.add('hidden');
            return 0;
        }
        card.classList.remove('hidden');

        var legend = document.createElement('div');
        legend.className = 'iphone-battery-chart-legend';
        legend.innerHTML =
            '<span><i class="soc" aria-hidden="true"></i>' +
            (A().escapeHtmlIphone ? A().escapeHtmlIphone(tr('dashBattSoc')) : tr('dashBattSoc')) +
            '</span><span><i class="charge" aria-hidden="true"></i>' +
            (A().escapeHtmlIphone ? A().escapeHtmlIphone(tr('dashBattCharging')) : tr('dashBattCharging')) +
            '</span><span><i class="low" aria-hidden="true"></i>20%</span>';
        mount.appendChild(legend);

        var w = 720;
        var h = 200;
        var padL = 36;
        var padR = 14;
        var padT = 14;
        var padB = 28;
        var t0 = series[0].t;
        var t1 = series[series.length - 1].t;
        var span = Math.max(1, t1 - t0);
        function xAt(t) {
            return padL + ((t - t0) / span) * (w - padL - padR);
        }
        function yAt(level) {
            return padT + (1 - level / 100) * (h - padT - padB);
        }

        var poly = series
            .map(function (p) {
                return xAt(p.t).toFixed(1) + ',' + yAt(p.level).toFixed(1);
            })
            .join(' ');
        var area =
            xAt(t0).toFixed(1) +
            ',' +
            yAt(0).toFixed(1) +
            ' ' +
            poly +
            ' ' +
            xAt(t1).toFixed(1) +
            ',' +
            yAt(0).toFixed(1);

        var bands = '';
        var bandStart = null;
        for (var i = 0; i < series.length; i++) {
            var p = series[i];
            if (p.charging && bandStart == null) bandStart = p.t;
            if ((!p.charging || i === series.length - 1) && bandStart != null) {
                var endT = p.t;
                var x1 = xAt(bandStart);
                var x2 = xAt(Math.max(bandStart, endT));
                bands +=
                    '<rect class="iphone-batt-charge-band" x="' +
                    x1.toFixed(1) +
                    '" y="' +
                    padT +
                    '" width="' +
                    Math.max(1.5, x2 - x1).toFixed(1) +
                    '" height="' +
                    (h - padT - padB) +
                    '" fill="rgba(76,175,80,0.14)"></rect>';
                bandStart = null;
            }
        }

        var yTicks = [0, 20, 50, 100];
        var yGrid = '';
        var yLabels = '';
        for (var yi = 0; yi < yTicks.length; yi++) {
            var yy = yAt(yTicks[yi]);
            var isWarn = yTicks[yi] === 20;
            yGrid +=
                '<line x1="' +
                padL +
                '" y1="' +
                yy.toFixed(1) +
                '" x2="' +
                (w - padR) +
                '" y2="' +
                yy.toFixed(1) +
                '" stroke="' +
                (isWarn ? 'rgba(244,67,54,0.4)' : 'rgba(128,128,128,0.18)') +
                '" stroke-dasharray="' +
                (isWarn ? '4 3' : '2 4') +
                '" stroke-width="1"></line>';
            yLabels +=
                '<text x="' +
                (padL - 6) +
                '" y="' +
                (yy + 3).toFixed(1) +
                '" text-anchor="end" font-size="10" fill="var(--text-secondary)">' +
                yTicks[yi] +
                '</text>';
        }

        var xLabels =
            '<text x="' +
            padL +
            '" y="' +
            (h - 8) +
            '" text-anchor="start" font-size="10" fill="var(--text-secondary)">' +
            formatChartTick(t0) +
            '</text>' +
            '<text x="' +
            (w - padR) +
            '" y="' +
            (h - 8) +
            '" text-anchor="end" font-size="10" fill="var(--text-secondary)">' +
            formatChartTick(t1) +
            '</text>';
        if (span > 3600000) {
            var mid = t0 + span / 2;
            xLabels +=
                '<text x="' +
                xAt(mid).toFixed(1) +
                '" y="' +
                (h - 8) +
                '" text-anchor="middle" font-size="10" fill="var(--text-secondary)">' +
                formatChartTick(mid) +
                '</text>';
        }

        var last = series[series.length - 1];
        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('aria-hidden', 'true');
        svg.innerHTML =
            bands +
            yGrid +
            '<polygon points="' +
            area +
            '" fill="color-mix(in srgb, var(--accent) 18%, transparent)"></polygon>' +
            '<polyline fill="none" stroke="var(--accent)" stroke-width="2.25" stroke-linejoin="round" stroke-linecap="round" points="' +
            poly +
            '"></polyline>' +
            '<circle cx="' +
            xAt(last.t).toFixed(1) +
            '" cy="' +
            yAt(last.level).toFixed(1) +
            '" r="3.5" fill="var(--accent)"></circle>' +
            yLabels +
            xLabels;

        var chartHost = document.createElement('div');
        chartHost.style.cssText = 'position:relative;width:100%;height:180px;';
        chartHost.appendChild(svg);

        var tip = document.createElement('div');
        tip.className = 'iphone-battery-chart-tip';
        tip.setAttribute('aria-hidden', 'true');
        chartHost.appendChild(tip);

        var hoverLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        hoverLine.setAttribute('y1', String(padT));
        hoverLine.setAttribute('y2', String(h - padB));
        hoverLine.setAttribute('stroke', 'var(--text-secondary)');
        hoverLine.setAttribute('stroke-width', '1');
        hoverLine.setAttribute('stroke-dasharray', '3 3');
        hoverLine.setAttribute('opacity', '0');
        svg.appendChild(hoverLine);

        var hoverDot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        hoverDot.setAttribute('r', '4');
        hoverDot.setAttribute('fill', 'var(--accent)');
        hoverDot.setAttribute('opacity', '0');
        svg.appendChild(hoverDot);

        function nearestPoint(clientX) {
            var rect = chartHost.getBoundingClientRect();
            var ratio = rect.width > 0 ? (clientX - rect.left) / rect.width : 0;
            var xSvg = ratio * w;
            var best = series[0];
            var bestDist = Infinity;
            for (var si = 0; si < series.length; si++) {
                var dx = Math.abs(xAt(series[si].t) - xSvg);
                if (dx < bestDist) {
                    bestDist = dx;
                    best = series[si];
                }
            }
            return best;
        }

        chartHost.addEventListener('mousemove', function (ev) {
            var pt = nearestPoint(ev.clientX);
            var x = xAt(pt.t);
            var y = yAt(pt.level);
            hoverLine.setAttribute('x1', x.toFixed(1));
            hoverLine.setAttribute('x2', x.toFixed(1));
            hoverLine.setAttribute('opacity', '0.7');
            hoverDot.setAttribute('cx', x.toFixed(1));
            hoverDot.setAttribute('cy', y.toFixed(1));
            hoverDot.setAttribute('opacity', '1');
            tip.innerHTML =
                '<div class="iphone-battery-chart-tip__soc">' +
                Math.round(pt.level) +
                '%</div><div class="iphone-battery-chart-tip__meta">' +
                (A().escapeHtmlIphone ? A().escapeHtmlIphone(pt.when) : pt.when) +
                '</div><div class="iphone-battery-chart-tip__meta">' +
                (pt.charging ? tr('dashBattCharging') : tr('dashBattSoc')) +
                '</div>';
            var rect = chartHost.getBoundingClientRect();
            var leftPct = (x / w) * 100;
            tip.style.left = leftPct + '%';
            tip.style.top = (y / h) * 100 + '%';
            tip.classList.add('is-visible');
        });
        chartHost.addEventListener('mouseleave', function () {
            tip.classList.remove('is-visible');
            hoverLine.setAttribute('opacity', '0');
            hoverDot.setAttribute('opacity', '0');
        });

        mount.appendChild(chartHost);

        if (caption) {
            caption.textContent = tr('dashBatteryChartCaption')
                .replace('{n}', String(totalCount != null ? totalCount : series.length))
                .replace('{span}', formatChartSpan(span))
                .replace('{min}', String(Math.round(Math.min.apply(null, series.map(function (p) { return p.level; })))))
                .replace('{max}', String(Math.round(Math.max.apply(null, series.map(function (p) { return p.level; })))));
        }
        return series.length;
    }

    function renderBatteryPanel(out) {
        var view = collectBattery(out);
        var hero = document.getElementById('iphone-battery-hero-mount');
        var heroCard = document.getElementById('iphone-battery-hero-card');
        if (hero && heroCard) {
            hero.textContent = '';
            if (!view) {
                heroCard.classList.add('hidden');
            } else {
                heroCard.classList.remove('hidden');
                var title = document.createElement('div');
                title.className = 'iphone-battery-soc';
                title.textContent = view.soc ? view.soc + '%' : '—';
                hero.appendChild(title);

                var socN = parseBatterySoc(view.soc);
                if (socN != null) {
                    var gauge = document.createElement('div');
                    gauge.className = 'iphone-battery-gauge';
                    var track = document.createElement('div');
                    track.className = 'iphone-battery-gauge__track';
                    var fill = document.createElement('div');
                    fill.className = 'iphone-battery-gauge__fill';
                    if (socN <= 20) fill.classList.add('is-low');
                    else if (socN <= 50) fill.classList.add('is-mid');
                    fill.style.width = socN + '%';
                    track.appendChild(fill);
                    gauge.appendChild(track);
                    hero.appendChild(gauge);
                }

                if (view.badges.length) {
                    var chips = document.createElement('div');
                    chips.className = 'iphone-filter-chips';
                    view.badges.forEach(function (b) {
                        var span = document.createElement('span');
                        span.className = 'iphone-kind-chip';
                        span.textContent = b;
                        chips.appendChild(span);
                    });
                    hero.appendChild(chips);
                }
                if (view.fields.length) {
                    var grid = document.createElement('div');
                    grid.className = 'result-grid';
                    grid.style.marginTop = '0.75rem';
                    view.fields.forEach(function (f) {
                        var item = document.createElement('div');
                        item.className = 'result-item';
                        item.innerHTML =
                            '<div class="result-item-label">' +
                            (A().escapeHtmlIphone ? A().escapeHtmlIphone(f.label) : f.label) +
                            '</div><div class="result-item-value mono">' +
                            (A().escapeHtmlIphone ? A().escapeHtmlIphone(f.value) : f.value) +
                            '</div>';
                        grid.appendChild(item);
                    });
                    hero.appendChild(grid);
                }
            }
        }

        var chartN = view ? renderBatterySocChart(view.series, view.seriesCount) : 0;

        var n = 0;
        if (view && view.samples.length) {
            n = fillTable(
                'iphone-battery-samples-card',
                'iphone-battery-samples-mount',
                [tr('dashColWhen'), tr('dashColKind'), tr('dashColSoc'), tr('dashColCharging'), tr('dashColExternal')],
                view.samples.map(function (v) {
                    return {
                        cells: [v.when, v.type, v.soc, v.charging, v.external],
                        haystack: [v.type, v.soc].join('\n').toLowerCase()
                    };
                })
            );
        } else {
            setCard('iphone-battery-samples-card', false);
        }
        var total = view ? Math.max(1, n, chartN) : 0;
        ensurePanelEmpty('iphone-dash-battery', 'dashEmptyBattery', total > 0);
        return total;
    }

    function parserEventCount(out, name) {
        return events(out, name).length;
    }

    function countExternal(out) {
        // Prefer curated row counts so the tab badge matches visible cards.
        var usb = collectUsb(out);
        return Math.min(
            99,
            collectWifiScan(out).length +
                collectWifiSaved(out).length +
                collectWifiKnown(out).length +
                collectWifiSecurity(out).length +
                usb.devices.length +
                usb.lockdown.length +
                collectFileInventory(out, 'bluetooth', 99).length +
                collectFileInventory(out, 'wifi_diagnostics', 99).length
        );
    }

    function countAuth(out) {
        return Math.min(99, collectLockEvents(out).length);
    }

    function countBattery(out) {
        var view = collectBattery(out);
        if (!view) return 0;
        return Math.min(99, Math.max(1, view.samples.length || 1));
    }

    global.IphoneMobipwnPanels = {
        renderOverviewIdentity: renderOverviewIdentity,
        renderNetworkExtras: renderNetworkExtras,
        renderExternalPanel: renderExternalPanel,
        renderProcessesExtras: renderProcessesExtras,
        renderAuthPanel: renderAuthPanel,
        renderBatteryPanel: renderBatteryPanel,
        countExternal: countExternal,
        countAuth: countAuth,
        countBattery: countBattery
    };
})(typeof window !== 'undefined' ? window : globalThis);

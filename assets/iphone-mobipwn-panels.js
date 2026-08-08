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
        var rows = events(out, 'accounts');
        var list = [];
        var seen = {};
        for (var i = 0; i < rows.length && list.length < 40; i++) {
            var ev = plain(rows[i]);
            var email =
                field(ev, 'email', 'account_name', 'account name', 'owner_name', 'owner name') ||
                field(ev, 'user');
            var type =
                field(ev, 'account_type', 'account type', 'event_type', 'data_type') || 'account';
            if (!email) continue;
            var key = type + ':' + email.toLowerCase();
            if (seen[key]) continue;
            seen[key] = true;
            list.push({
                email: email,
                type: type,
                when: field(ev, 'datetime', 'timestamp') || '—'
            });
        }
        return list;
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
        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var msg = field(ev, 'message');
            if (!startup && field(ev, 'hardware_model', 'hardware model')) startup = ev;
            if (!state && /activation state:/i.test(msg)) {
                state = msg.replace(/.*activation state:\s*/i, '').trim();
            }
        }
        if (!startup && !state) return null;
        var hasBb = field(startup || {}, 'has_baseband', 'has baseband');
        return {
            state: state || '—',
            soc: field(startup || {}, 'soc_generation', 'soc generation') || '—',
            baseband: hasBb === 'true' ? 'Yes' : hasBb === 'false' ? 'No' : '—',
            build: field(startup || {}, 'build_version', 'build version') || '—'
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
        var rows = events(out, 'ioservice');
        if (!rows.length) return null;
        var props = [];
        var nodeCount = '';
        var LABELS = {
            ioplatformserialnumber: 'Platform serial',
            model: 'Model',
            'board-id': 'Board ID',
            'product-name': 'Product',
            'chip-id': 'Chip ID',
            uniquechipid: 'Unique chip ID'
        };
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
        return { nodeCount: nodeCount, properties: props.slice(0, 16) };
    }

    function renderOverviewIdentity(out) {
        var accounts = collectAccounts(out);
        fillTable(
            'iphone-accounts-card',
            'iphone-accounts-mount',
            [tr('dashColAccount'), tr('dashColKind'), tr('dashColWhen')],
            accounts.map(function (a) {
                return {
                    cells: [a.email, a.type, a.when],
                    haystack: [a.email, a.type].join('\n').toLowerCase()
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
                tr('dashColSize'),
                tr('dashColUsed'),
                tr('dashColAvail'),
                tr('dashColCapacity')
            ],
            storage.map(function (v) {
                return {
                    cells: [v.mount, v.label, v.size, v.used, v.avail, v.capacity],
                    haystack: [v.mount, v.label, v.fs].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true } }
        );

        var act = collectActivation(out);
        var actMount = document.getElementById('iphone-activation-mount');
        var actCard = document.getElementById('iphone-activation-card');
        if (actMount && actCard) {
            actMount.textContent = '';
            if (!act) {
                actCard.classList.add('hidden');
            } else {
                actCard.classList.remove('hidden');
                var grid = document.createElement('div');
                grid.className = 'result-grid';
                [
                    [tr('dashColState'), act.state],
                    [tr('dashColSoc'), act.soc],
                    [tr('dashColBaseband'), act.baseband],
                    [tr('dashDeviceBuild'), act.build]
                ].forEach(function (pair) {
                    var item = document.createElement('div');
                    item.className = 'result-item';
                    item.innerHTML =
                        '<div class="result-item-label">' +
                        (A().escapeHtmlIphone ? A().escapeHtmlIphone(pair[0]) : pair[0]) +
                        '</div><div class="result-item-value mono">' +
                        (A().escapeHtmlIphone ? A().escapeHtmlIphone(pair[1]) : pair[1]) +
                        '</div>';
                    grid.appendChild(item);
                });
                actMount.appendChild(grid);
            }
        }

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
                cells: ['IOService nodes', String(iosvc.nodeCount)],
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
                note: iosvc && iosvc.nodeCount ? iosvc.nodeCount + ' IOService nodes' : ''
            }
        );

        return {
            accounts: accounts.length,
            storage: storage.length,
            paired: paired.length
        };
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
        if (!list.length && geo && geo.point_count) {
            list.push({
                ssid: '(geolocation analyser)',
                bssid: '—',
                lat: String(geo.point_count) + ' points',
                lon: geo.format || 'gpx',
                channel: '—',
                when: '—'
            });
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

    function collectUsb(out) {
        var rows = events(out, 'iousb');
        var devices = [];
        var seen = {};
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
                product: product || 'USB device',
                vendor: vendor,
                ids: idVendor + ':' + idProduct,
                serial: serial,
                when: field(ev, 'datetime', 'timestamp') || '—'
            });
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
        fillTable(
            'iphone-wifi-known-card',
            'iphone-wifi-known-mount',
            [tr('dashColSsid'), tr('dashColBssid'), tr('dashColLat'), tr('dashColLon'), tr('dashColWhen')],
            known.map(function (v) {
                return {
                    cells: [v.ssid, v.bssid, v.lat, v.lon, v.when],
                    haystack: [v.ssid, v.bssid, v.lat, v.lon].join('\n').toLowerCase()
                };
            }),
            { monoCols: { 0: true, 1: true, 2: true, 3: true } }
        );

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

        return (
            scan.length +
            saved.length +
            known.length +
            sec.length +
            usb.devices.length +
            usb.lockdown.length
        );
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
        return eventsList.length;
    }

    /* ---------- Battery ---------- */

    function collectBattery(out) {
        var rows = events(out, 'battery_bdc');
        var byType = {};
        var samples = [];
        for (var i = 0; i < rows.length; i++) {
            var ev = plain(rows[i]);
            var type = field(ev, 'type') || 'BDC';
            if (!byType[type]) byType[type] = {};
            ['StateOfCharge', 'IsCharging', 'ExternalConnected', 'AppleRawExternalConnected', 'Temperature', 'Voltage', 'InstantAmperage', 'DesignCapacity', 'MaxCapacity', 'FullyCharged', 'AtCriticalLevel', 'AtWarnLevel'].forEach(
                function (k) {
                    var v = field(ev, k);
                    if (v && !byType[type][k]) byType[type][k] = v;
                }
            );
            if (samples.length < 20) {
                samples.push({
                    when: field(ev, 'datetime', 'timestamp') || '—',
                    type: type,
                    soc: field(ev, 'StateOfCharge') || '—',
                    charging: field(ev, 'IsCharging') || '—',
                    external: field(ev, 'ExternalConnected', 'AppleRawExternalConnected') || '—'
                });
            }
        }

        var sbc = byType.BDC_SBC || byType.BDC || {};
        var once = byType.BDC_Once || {};
        var obc = byType.BDC_OBC || {};
        var soc = sbc.StateOfCharge || once.StateOfCharge || '';
        var charging = sbc.IsCharging === '1' || sbc.IsCharging === 'true';
        var external =
            obc.ExternalConnected === '1' ||
            obc.ExternalConnected === 'true' ||
            obc.AppleRawExternalConnected === '1' ||
            obc.AppleRawExternalConnected === 'true';
        var badges = [];
        if (charging) badges.push('Charging');
        if (external) badges.push('External power');
        if (sbc.FullyCharged === '1' || sbc.FullyCharged === 'true') badges.push('Fully charged');
        if (sbc.AtCriticalLevel === '1' || sbc.AtCriticalLevel === 'true') badges.push('Critical');
        if (sbc.AtWarnLevel === '1' || sbc.AtWarnLevel === 'true') badges.push('Low');

        var fields = [];
        function pushField(label, value) {
            if (value) fields.push({ label: label, value: value });
        }
        pushField('State of charge', soc ? soc + '%' : '');
        pushField('Temperature', sbc.Temperature || once.Temperature);
        pushField('Voltage', sbc.Voltage || once.Voltage);
        pushField('Amperage', sbc.InstantAmperage);
        pushField('Design capacity', once.DesignCapacity);
        pushField('Max capacity', once.MaxCapacity);

        // Powerlogs battery level fallback samples
        if (!samples.length) {
            var pl = events(out, 'powerlogs');
            for (var j = 0; j < pl.length && samples.length < 20; j++) {
                var pev = plain(pl[j]);
                var mod = field(pev, 'apollo_module', 'module');
                var pmsg = field(pev, 'message');
                if (mod !== 'powerlog_battery_level' && !/battery level/i.test(pmsg)) continue;
                samples.push({
                    when: field(pev, 'datetime', 'timestamp') || '—',
                    type: 'Battery Level',
                    soc: field(pev, 'level', 'battery level', 'raw_level') || '—',
                    charging: field(pev, 'is charging', 'is_charging') || '—',
                    external: '—'
                });
            }
        }

        if (!soc && !fields.length && !samples.length) return null;
        return { soc: soc, badges: badges, fields: fields, samples: samples };
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
        return view ? Math.max(1, n) : 0;
    }

    function parserEventCount(out, name) {
        return events(out, name).length;
    }

    function countExternal(out) {
        return (
            Math.min(parserEventCount(out, 'wifiscan'), 99) +
            Math.min(parserEventCount(out, 'wifinetworks'), 99) +
            Math.min(parserEventCount(out, 'wifi_known_networks'), 99) +
            Math.min(parserEventCount(out, 'wifisecurity'), 99) +
            Math.min(parserEventCount(out, 'iousb'), 99)
        );
    }

    function countAuth(out) {
        // Same classifier as the panel so the badge matches visible rows.
        var n = 0;
        var parsers = [
            { name: 'powerlogs', cap: 4000 },
            { name: 'knowledgec', cap: 4000 },
            { name: 'lockdownd', cap: 2000 },
            { name: 'logarchive', cap: 20000 }
        ];
        for (var pi = 0; pi < parsers.length; pi++) {
            var rows = events(out, parsers[pi].name);
            var limit = Math.min(rows.length, parsers[pi].cap);
            for (var i = 0; i < limit; i++) {
                if (parseIosLockEvent(rows[i], parsers[pi].name)) {
                    n += 1;
                    if (n >= 99) return n;
                }
            }
        }
        return n;
    }

    function countBattery(out) {
        if (parserEventCount(out, 'battery_bdc') > 0) return 1;
        var pl = events(out, 'powerlogs');
        var limit = Math.min(pl.length, 80);
        for (var i = 0; i < limit; i++) {
            var ev = plain(pl[i]);
            var mod = field(ev, 'apollo_module', 'module');
            var msg = field(ev, 'message');
            if (mod === 'powerlog_battery_level' || /battery level/i.test(msg)) return 1;
        }
        return 0;
    }

    global.IphoneMobipwnPanels = {
        renderOverviewIdentity: renderOverviewIdentity,
        renderNetworkExtras: renderNetworkExtras,
        renderExternalPanel: renderExternalPanel,
        renderAuthPanel: renderAuthPanel,
        renderBatteryPanel: renderBatteryPanel,
        countExternal: countExternal,
        countAuth: countAuth,
        countBattery: countBattery
    };
})(typeof window !== 'undefined' ? window : globalThis);

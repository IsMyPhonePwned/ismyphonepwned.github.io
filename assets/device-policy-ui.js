/* Readable dumpsys device_policy: owners, admins, restrictions, app lists, caches. */
(function () {
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function labelize(key) {
        return String(key || '')
            .replace(/_/g, ' ')
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function cleanScalar(v) {
        if (typeof v === 'boolean' || typeof v === 'number' || v == null) return v;
        if (typeof v === 'object') return v;
        var s = String(v).trim().replace(/\s*\}+\s*$/, '').trim();
        if (s === 'true') return true;
        if (s === 'false') return false;
        if (s === 'null' || s === '[null]' || s === '{}' || s === '[]' || s === '') return null;
        return s;
    }

    function restrictionName(key) {
        return String(key || '')
            .replace(/^userRestriction_/, '')
            .replace(/_/g, ' ');
    }

    function listName(key) {
        return String(key || '').replace(/_/g, ' ');
    }

    function pill(on, yes, no) {
        if (on === true) return '<span class="dp-pill dp-pill--on">' + esc(yes || 'Yes') + '</span>';
        if (on === false) return '<span class="dp-pill dp-pill--off">' + esc(no || 'No') + '</span>';
        return '<span class="dp-muted">Not set</span>';
    }

    function adminNames(per) {
        if (!Array.isArray(per)) return [];
        var names = [];
        per.forEach(function (raw) {
            if (!raw || typeof raw !== 'object') return;
            var pkg = raw.package_name || raw.package || raw.mPackageName;
            if (pkg && names.indexOf(String(pkg)) < 0) names.push(String(pkg));
        });
        return names;
    }

    function formatValue(v) {
        v = cleanScalar(v);
        if (v == null) return '<span class="dp-muted">None</span>';
        if (v === true || v === false) return pill(v);
        if (typeof v === 'number') return '<code>' + esc(String(v)) + '</code>';
        if (Array.isArray(v)) {
            if (!v.length) return '<span class="dp-muted">None</span>';
            return '<span class="dp-chips">' + v.map(function (item) {
                return '<span class="dp-chip">' + esc(typeof item === 'object' ? JSON.stringify(item) : String(item)) + '</span>';
            }).join('') + '</span>';
        }
        if (typeof v === 'object') {
            var keys = Object.keys(v);
            if (!keys.length) return '<span class="dp-muted">None</span>';
            return '<span class="dp-chips">' + keys.map(function (k) {
                var inner = cleanScalar(v[k]);
                var text = (inner === true || inner === false) ? (inner ? 'Yes' : 'No') : (inner == null ? '—' : String(inner));
                return '<span class="dp-chip">' + esc(labelize(k)) + ': ' + esc(text) + '</span>';
            }).join('') + '</span>';
        }
        var s = String(v).trim();
        var mapish = s.replace(/^\{/, '').replace(/\}$/, '').trim();
        if (/^\d+\s*=/.test(mapish)) {
            return '<span class="dp-chips">' + mapish.split(',').map(function (part) {
                var bits = part.split('=');
                if (bits.length < 2) return '<span class="dp-chip">' + esc(part.trim()) + '</span>';
                return '<span class="dp-chip">User ' + esc(bits[0].trim()) + ': ' + esc(bits.slice(1).join('=').trim()) + '</span>';
            }).join('') + '</span>';
        }
        return '<code class="dp-code">' + esc(s) + '</code>';
    }

    function item(hay, html) {
        return '<div class="dp-item" data-dp-item="' + esc(String(hay || '').toLowerCase()) + '">' + html + '</div>';
    }

    function heading(key, t) {
        t = t || {};
        if (key === 'profile_owner') return t.devicePolicyTitleProfileOwner || 'Profile owner';
        var um = /^device_admins_user_(\d+)$/.exec(key);
        if (um) return (t.devicePolicyTitleDeviceAdminsUser || 'Device admins (user {u})').replace('{u}', um[1]);
        if (key === 'device_admins') return t.devicePolicyTitleDeviceAdmins || 'Device admins';
        if (key === 'local_policies') return t.devicePolicyTitleLocalPol || 'Local policies';
        if (key === 'global_policies') return t.devicePolicyTitleGlobalPol || 'Global policies';
        if (key === 'personal_apps_suspension') return t.devicePolicyTitlePersonalSusp || 'Personal apps suspension';
        if (key === 'overlay_packages') return t.devicePolicyTitleOverlay || 'Overlay packages';
        if (key === 'device_policy_cache') return t.devicePolicyTitlePolCache || 'Device policy cache';
        if (key === 'device_state_cache') return t.devicePolicyTitleStateCache || 'Device state cache';
        return labelize(key);
    }

    function profileOwner(v) {
        var pkg = v.package || v.Package || '';
        var receiver = v.receiver || v.Receiver || '';
        var user = v.user != null ? v.user : v.User;
        var owned = cleanScalar(v.isOrganizationOwnedDevice);
        var html = '<div class="dp-identity">';
        if (pkg) html += '<div class="dp-identity__pkg">' + esc(pkg) + '</div>';
        if (receiver) html += '<code class="dp-code">' + esc(receiver) + '</code>';
        html += '<div class="dp-chips">';
        if (user != null && user !== '') html += '<span class="dp-chip">User ' + esc(user) + '</span>';
        if (owned === true) html += '<span class="dp-pill dp-pill--on">Organization-owned</span>';
        else if (owned === false) html += '<span class="dp-pill">Not organization-owned</span>';
        html += '</div></div>';
        var skip = { package: 1, Package: 1, receiver: 1, Receiver: 1, user: 1, User: 1, isOrganizationOwnedDevice: 1 };
        var rows = '';
        Object.keys(v).forEach(function (k) {
            if (skip[k]) return;
            var val = v[k];
            if (val == null || val === '') return;
            rows += item(k + ' ' + (typeof val === 'object' ? JSON.stringify(val) : val),
                '<div class="dp-row"><span>' + esc(labelize(k)) + '</span>' + formatValue(val) + '</div>');
        });
        if (rows) html += '<div class="dp-rows">' + rows + '</div>';
        return html;
    }

    function adminCard(a, t) {
        var pkg = a.package != null ? String(a.package) : '';
        var receiver = a.receiver != null ? String(a.receiver) : '';
        var uid = a.uid != null ? String(a.uid) : '';
        var pol = Array.isArray(a.policies) ? a.policies : [];
        var hay = [pkg, receiver, uid].concat(pol).join(' ');
        var html = '<article class="dp-admin">';
        html += '<div class="dp-admin__pkg">' + esc(pkg || 'Unknown admin') + '</div>';
        if (receiver) html += '<code class="dp-code">' + esc(receiver) + '</code>';
        html += '<div class="dp-chips">';
        if (uid) html += '<span class="dp-chip">uid ' + esc(uid) + '</span>';
        html += '<span class="dp-chip">' + esc((t.devicePolicyPoliciesCount || '{n} policies').replace('{n}', String(pol.length))) + '</span>';
        html += '</div>';
        if (pol.length) {
            var open = pol.length <= 6 ? ' open' : '';
            html += '<details class="dp-fold"' + open + ' data-dp-default-open="' + (pol.length <= 6 ? '1' : '0') + '"><summary>' +
                esc(t.devicePolicyThPolicies || 'Policies') + '</summary><div class="dp-chips">';
            pol.forEach(function (p) {
                html += '<span class="dp-chip">' + esc(String(p)) + '</span>';
            });
            html += '</div></details>';
        }
        var skip = { package: 1, receiver: 1, uid: 1, policies: 1, component: 1 };
        var extra = '';
        Object.keys(a).forEach(function (k) {
            if (skip[k] || a[k] == null || a[k] === '') return;
            extra += '<div class="dp-row"><span>' + esc(labelize(k)) + '</span>' + formatValue(a[k]) + '</div>';
            hay += ' ' + k;
        });
        if (extra) {
            html += '<details class="dp-fold" data-dp-default-open="0"><summary>' +
                esc(t.devicePolicyMoreFields || 'More fields') + '</summary><div class="dp-rows">' + extra + '</div></details>';
        }
        html += '</article>';
        return item(hay, html);
    }

    function admins(list, t) {
        if (!Array.isArray(list) || !list.length) return '<p class="dp-muted">None</p>';
        return '<div class="dp-admins">' + list.map(function (raw) {
            return adminCard(raw && typeof raw === 'object' ? raw : { package: String(raw) }, t);
        }).join('') + '</div>';
    }

    function restrictionChip(p) {
        var key = p.key != null ? String(p.key) : '';
        var name = restrictionName(key);
        var resolved = cleanScalar(p.resolved_policy);
        var names = adminNames(p.per_admin_policy);
        var cls = resolved === true ? ' dp-chip--on' : (resolved === false ? ' dp-chip--off' : '');
        var title = names.length ? ' title="' + esc(names.join(', ')) + '"' : '';
        var mark = resolved === true ? 'On' : (resolved === false ? 'Off' : 'Not set');
        return item(key + ' ' + name + ' ' + names.join(' '),
            '<span class="dp-chip' + cls + '"' + title + '>' + esc(name) + ' <em>' + esc(mark) + '</em></span>');
    }

    function restrictions(root, t) {
        if (!root || typeof root !== 'object' || Array.isArray(root)) return formatValue(root);
        var userKeys = Object.keys(root).filter(function (k) { return /^user_\d+$/.test(k); })
            .sort(function (a, b) { return parseInt(a.slice(5), 10) - parseInt(b.slice(5), 10); });
        if (!userKeys.length) {
            return '<div class="dp-rows">' + Object.keys(root).map(function (k) {
                return item(k, '<div class="dp-row"><span>' + esc(labelize(k)) + '</span>' + formatValue(root[k]) + '</div>');
            }).join('') + '</div>';
        }
        return userKeys.map(function (uk) {
            var arr = Array.isArray(root[uk]) ? root[uk] : [];
            var uid = uk.replace(/^user_/, '');
            var on = [];
            var off = [];
            var unset = [];
            arr.forEach(function (raw) {
                var p = raw && typeof raw === 'object' ? raw : { key: String(raw) };
                var resolved = cleanScalar(p.resolved_policy);
                if (resolved === true) on.push(p);
                else if (resolved === false) off.push(p);
                else unset.push(p);
            });
            var head = (t.devicePolicyUserRestrictions || 'User {u} ({n} restrictions)')
                .replace('{u}', uid).replace('{n}', String(arr.length));
            var html = '<details class="dp-fold dp-user" open data-dp-default-open="1"><summary>' + esc(head) +
                ' <span class="dp-cnt">' + on.length + ' on</span></summary>';
            if (on.length) html += '<div class="dp-chips">' + on.map(restrictionChip).join('') + '</div>';
            else html += '<p class="dp-muted">No restrictions enforced.</p>';
            if (off.length) {
                html += '<details class="dp-fold" data-dp-default-open="0"><summary>Allowed (' + off.length + ')</summary><div class="dp-chips">' +
                    off.map(restrictionChip).join('') + '</div></details>';
            }
            if (unset.length) {
                html += '<details class="dp-fold" data-dp-default-open="0"><summary>Not set (' + unset.length + ')</summary><div class="dp-chips">' +
                    unset.map(restrictionChip).join('') + '</div></details>';
            }
            html += '</details>';
            return html;
        }).join('');
    }

    function appLists(obj) {
        var keys = Object.keys(obj || {});
        if (!keys.length) return '<p class="dp-muted">None</p>';
        return keys.sort().map(function (name) {
            var apps = obj[name];
            var title = /^\d+$/.test(name) ? 'User ' + name : listName(name);
            if (!Array.isArray(apps)) {
                return item(name, '<div class="dp-row"><span>' + esc(listName(name)) + '</span>' + formatValue(apps) + '</div>');
            }
            var open = apps.length > 0 && apps.length <= 8;
            var html = '<details class="dp-fold" ' + (open ? 'open ' : '') + 'data-dp-default-open="' + (open ? '1' : '0') + '"><summary>' +
                esc(title) + ' <span class="dp-cnt">(' + apps.length + ')</span></summary>';
            if (!apps.length) html += '<p class="dp-muted">None</p>';
            else {
                html += '<div class="dp-chips">';
                apps.forEach(function (pkg) {
                    html += item(name + ' ' + pkg, '<code class="dp-pkg">' + esc(String(pkg)) + '</code>');
                });
                html += '</div>';
            }
            html += '</details>';
            return html;
        }).join('');
    }

    function kvBlock(obj) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return formatValue(obj);
        var keys = Object.keys(obj);
        if (!keys.length) return '<p class="dp-muted">None</p>';
        return '<div class="dp-rows">' + keys.map(function (k) {
            return item(k + ' ' + (typeof obj[k] === 'object' ? JSON.stringify(obj[k]) : obj[k]),
                '<div class="dp-row"><span>' + esc(labelize(k)) + '</span>' + formatValue(obj[k]) + '</div>');
        }).join('') + '</div>';
    }

    function sectionBody(key, v, t) {
        if (key === 'profile_owner' && v && typeof v === 'object' && !Array.isArray(v)) return profileOwner(v);
        if ((key === 'device_admins' || /^device_admins_user_\d+$/.test(key)) && Array.isArray(v)) return admins(v, t);
        if ((key === 'local_policies' || key === 'global_policies') && v && typeof v === 'object' && !Array.isArray(v)) return restrictions(v, t);
        if ((key === 'personal_apps_suspension' || key === 'overlay_packages') && v && typeof v === 'object' && !Array.isArray(v)) return appLists(v);
        if (v && typeof v === 'object' && !Array.isArray(v)) return kvBlock(v);
        return formatValue(v);
    }

    window.renderDevicePolicyHtml = function (data, t) {
        t = t || {};
        var keys = Object.keys(data || {});
        var adminKeys = keys.filter(function (k) {
            return k === 'device_admins' || /^device_admins_user_\d+$/.test(k);
        }).sort(function (a, b) {
            if (a === 'device_admins') return -1;
            if (b === 'device_admins') return 1;
            return parseInt((/^device_admins_user_(\d+)$/.exec(a) || [, '0'])[1], 10) -
                parseInt((/^device_admins_user_(\d+)$/.exec(b) || [, '0'])[1], 10);
        });
        var preferred = ['profile_owner'].concat(adminKeys).concat([
            'local_policies', 'global_policies', 'personal_apps_suspension', 'overlay_packages',
            'device_policy_cache', 'device_state_cache'
        ]);
        var ordered = [];
        preferred.forEach(function (k) {
            if (keys.indexOf(k) >= 0 && ordered.indexOf(k) < 0) ordered.push(k);
        });
        keys.slice().sort().forEach(function (k) {
            if (ordered.indexOf(k) < 0) ordered.push(k);
        });
        var intro = t.devicePolicyIntro || '';
        var ph = t.devicePolicyFilterPlaceholder || 'Filter sections (package, restriction, keyword)…';
        var blocks = ordered.map(function (key) {
            return '<article class="parser-dp-block"><h4 class="parser-dp-block-title">' + esc(heading(key, t)) +
                '</h4><div class="parser-dp-block-body">' + sectionBody(key, data[key], t) + '</div></article>';
        }).join('');
        return (intro ? '<p class="parser-dp-intro">' + esc(intro) + '</p>' : '') +
            '<div class="search-box parser-dp-search-wrap"><span class="search-icon" aria-hidden="true">🔍</span>' +
            '<input type="search" class="parser-dp-filter" placeholder="' + esc(ph) + '" autocomplete="off"></div>' +
            '<div class="parser-dp-blocks">' + blocks + '</div>';
    };

    window.bindDevicePolicyFilter = function (root) {
        if (!root) return;
        var input = root.querySelector('.parser-dp-filter');
        if (!input || input.dataset.dpBound) return;
        input.dataset.dpBound = '1';
        input.addEventListener('input', function () {
            var q = input.value.trim().toLowerCase();
            var first = null;
            root.querySelectorAll('.parser-dp-block').forEach(function (blk) {
                var title = ((blk.querySelector('.parser-dp-block-title') || {}).textContent || '').toLowerCase();
                var titleHit = !q || title.indexOf(q) >= 0;
                var any = false;
                blk.querySelectorAll('[data-dp-item]').forEach(function (node) {
                    var hay = node.getAttribute('data-dp-item') || '';
                    var hit = !q || titleHit || hay.indexOf(q) >= 0;
                    node.hidden = q ? !hit : false;
                    if (hit) {
                        any = true;
                        if (q && !first) first = node;
                        if (q) {
                            var det = node.parentElement;
                            while (det && det !== blk) {
                                if (det.tagName === 'DETAILS') det.open = true;
                                det = det.parentElement;
                            }
                        }
                    }
                });
                if (!q) {
                    blk.hidden = false;
                    blk.querySelectorAll('details[data-dp-default-open]').forEach(function (d) {
                        d.open = d.getAttribute('data-dp-default-open') === '1';
                    });
                    return;
                }
                var show = titleHit || any;
                blk.hidden = !show;
                if (show && !first) first = blk;
            });
            if (q && first && first.scrollIntoView) {
                first.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }
        });
    };
})();

/* Readable fused-location provider cards (source + listeners). */
(function () {
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function clean(s) {
        return String(s == null ? '' : s).replace(/\uFFFD/g, '').replace(/[\u0000-\u001F\u007F]/g, '').trim();
    }

    function typeLabel(t) {
        var s = clean(t);
        if (!s) return '';
        if (s === 'fused_location_provider') return 'Fused location';
        return s.replace(/_/g, ' ');
    }

    function humanDuration(s) {
        var t = clean(s);
        if (/^106751991167d/.test(t)) return 'No expiry';
        return t;
    }

    function humanQuality(q) {
        var map = {
            BALANCED_POWER_ACCURACY: 'Balanced',
            HIGH_ACCURACY: 'High accuracy',
            LOW_POWER: 'Low power',
            NO_POWER: 'No power'
        };
        var t = clean(q);
        return map[t] || t.replace(/_/g, ' ');
    }

    function humanFlag(f) {
        var t = clean(f);
        if (t === 'THROTTLE_NEVER') return 'Never throttle';
        if (t.toLowerCase() === 'bypass') return 'Bypass';
        return t.replace(/_/g, ' ');
    }

    function distanceLabel(v) {
        var t = clean(v);
        if (!t) return '';
        if (/m$/i.test(t)) return t;
        var n = Number(t);
        if (Number.isFinite(n)) return (n >= 1000 ? (n / 1000) + ' km' : n + ' m');
        return t;
    }

    function workSource(ws) {
        if (!ws || typeof ws !== 'object') return '';
        var pkg = clean(ws.package || ws.packageName || '');
        var uid = ws.uid != null && ws.uid !== '' ? clean(ws.uid) : '';
        if (pkg && uid) return pkg + ' · uid ' + uid;
        return pkg || (uid ? 'uid ' + uid : '');
    }

    function chip(text) {
        var t = clean(text);
        if (!t) return '';
        return '<span class="loc-chip">' + esc(t) + '</span>';
    }

    function requestChips(req) {
        if (!req || typeof req !== 'object' || Array.isArray(req)) {
            var raw = clean(req);
            return raw ? chip(raw) : '';
        }
        var html = '';
        if (req.mode) html += chip(clean(req.mode) === 'PASSIVE' ? 'Passive' : clean(req.mode));
        if (req.interval) html += chip('Every ' + clean(req.interval));
        if (req.quality) html += chip(humanQuality(req.quality));
        if (req.minUpdateInterval) html += chip('Min interval ' + humanDuration(req.minUpdateInterval));
        if (req.minUpdateDistance != null && req.minUpdateDistance !== '') html += chip('Min distance ' + distanceLabel(req.minUpdateDistance));
        if (req.maxUpdateAge) html += chip('Max age ' + humanDuration(req.maxUpdateAge));
        if (req.duration) html += chip(humanDuration(req.duration) === 'No expiry' ? 'No expiry' : 'Duration ' + humanDuration(req.duration));
        if (req.flags) html += chip(humanFlag(req.flags));
        var known = {
            mode: 1, interval: 1, quality: 1, minUpdateInterval: 1, minUpdateDistance: 1,
            maxUpdateAge: 1, duration: 1, flags: 1, work_source: 1
        };
        Object.keys(req).forEach(function (k) {
            if (known[k]) return;
            var v = req[k];
            if (v && typeof v === 'object') return;
            html += chip(k.replace(/_/g, ' ') + ' ' + clean(v));
        });
        return html;
    }

    function requestBlock(title, req) {
        var chips = requestChips(req);
        var ws = req && typeof req === 'object' ? workSource(req.work_source) : '';
        if (!chips && !ws) return '';
        var html = '<div class="loc-block"><h5>' + esc(title) + '</h5>';
        if (chips) html += '<div class="loc-chips">' + chips + '</div>';
        if (ws) html += '<p class="loc-ws">Work source · ' + esc(ws) + '</p>';
        html += '</div>';
        return html;
    }

    function listenerCard(row) {
        var pkg = clean(row.package || row.packageName || '');
        var comp = clean(row.component || '');
        if (comp === '—' || comp === '-') comp = '';
        var acc = clean(row.accuracy || row.permission || '');
        var uid = row.uid != null && row.uid !== '' ? clean(row.uid) : '';
        var id = clean(row.listener_id || '');
        var req = row.request;
        var hay = [pkg, comp, acc, uid, id].join(' ').toLowerCase();
        var accClass = acc.toUpperCase() === 'FINE' ? ' is-fine' : (acc.toUpperCase() === 'COARSE' ? ' is-coarse' : '');
        var html = '<article class="loc-listener" data-hay="' + esc(hay) + '">';
        html += '<div class="loc-listener__head">';
        if (acc) html += '<span class="loc-acc' + accClass + '">' + esc(acc.toUpperCase()) + '</span>';
        html += '<span class="loc-listener__pkg">' + esc(pkg || 'Unknown package') + '</span>';
        if (comp) html += '<span class="loc-listener__comp">' + esc(comp) + '</span>';
        html += '</div>';
        var meta = [];
        if (uid) meta.push('uid ' + uid);
        if (id) meta.push(id);
        if (meta.length) html += '<p class="loc-listener__meta">' + esc(meta.join(' · ')) + '</p>';
        var chips = requestChips(req);
        if (chips) html += '<div class="loc-chips">' + chips + '</div>';
        var ws = req && typeof req === 'object' ? workSource(req.work_source) : '';
        if (ws) html += '<p class="loc-ws">Work source · ' + esc(ws) + '</p>';
        html += '</article>';
        return html;
    }

    window.renderLocationProviderHtml = function (prov, index, extraHtml) {
        prov = prov || {};
        var html = '<section class="loc-prov">';
        html += '<div class="loc-prov__head"><h4>Location provider ' + (index + 1) + '</h4>';
        var kind = typeLabel(prov.type);
        if (kind) html += '<span class="loc-prov__kind">' + esc(kind) + '</span>';
        if (Object.prototype.hasOwnProperty.call(prov, 'last_availability')) {
            html += '<span class="loc-prov__avail' + (prov.last_availability ? ' is-on' : ' is-off') + '">' +
                (prov.last_availability ? 'Available' : 'Unavailable') + '</span>';
        }
        html += '</div>';
        if (extraHtml) html += extraHtml;
        if (prov.source && typeof prov.source === 'object') {
            html += requestBlock('Source', prov.source);
        }
        var listeners = Array.isArray(prov.listeners) ? prov.listeners : [];
        if (listeners.length) {
            html += '<div class="loc-block"><h5>Listeners <span class="loc-count">' + listeners.length + '</span></h5>';
            if (listeners.length > 3) {
                html += '<input type="search" class="loc-prov__search" placeholder="Filter package, component, or uid" autocomplete="off">';
            }
            html += '<div class="loc-listeners">';
            listeners.forEach(function (row) {
                html += listenerCard(row && typeof row === 'object' ? row : { package: String(row) });
            });
            html += '</div></div>';
        }
        html += '</section>';
        return html;
    };

    document.addEventListener('input', function (ev) {
        var input = ev.target && ev.target.classList && ev.target.classList.contains('loc-prov__search') ? ev.target : null;
        if (!input) return;
        var q = input.value.trim().toLowerCase();
        var root = input.closest('.loc-prov');
        if (!root) return;
        var cards = root.querySelectorAll('.loc-listener');
        var shown = 0;
        for (var i = 0; i < cards.length; i++) {
            var hay = cards[i].getAttribute('data-hay') || '';
            var hide = !!(q && hay.indexOf(q) < 0);
            cards[i].hidden = hide;
            if (!hide) shown += 1;
        }
        var empty = root.querySelector('.loc-filter-empty');
        if (!empty && q) {
            empty = document.createElement('p');
            empty.className = 'loc-filter-empty';
            empty.textContent = 'No listeners match that filter.';
            var list = root.querySelector('.loc-listeners');
            if (list) list.appendChild(empty);
        }
        if (empty) empty.hidden = !q || shown > 0;
    });
})();

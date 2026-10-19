/* Readable ADB debugging-manager block (authorized keys + keystore hints). */
(function () {
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function cleanText(s) {
        return String(s == null ? '' : s)
            .replace(/\uFFFD/g, '')
            .replace(/[\u0000-\u001F\u007F]/g, '')
            .trim();
    }

    function labelize(key) {
        return String(key || '')
            .replace(/_/g, ' ')
            .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function copyButton(text, label) {
        return '<button type="button" class="adb-debug__copy" data-copy="' + esc(text) + '">' + esc(label || 'Copy') + '</button>';
    }

    function flag(on, label) {
        return '<span class="adb-debug__flag' + (on ? ' is-yes' : ' is-no') + '">' + esc(label) + '</span>';
    }

    function renderKeyCard(entry) {
        var id = cleanText(entry.identifier || entry.name || '');
        var key = cleanText(entry.key || '');
        var raw = cleanText(entry.raw || '');
        var material = key || raw;
        var html = '<article class="adb-key">';
        html += '<div class="adb-key__head"><span class="adb-key__id">' + esc(id || 'Authorized key') + '</span>';
        if (material) html += copyButton(material, 'Copy key');
        html += '</div>';
        if (material) {
            var preview = material.length > 72 ? material.slice(0, 72) + '…' : material;
            html += '<code class="adb-key__preview">' + esc(preview) + '</code>';
            if (material.length > 72) {
                html += '<details class="adb-key__full"><summary>Show full key</summary><code>' + esc(material) + '</code></details>';
            }
        } else {
            html += '<p class="adb-key__empty">No key material parsed.</p>';
        }
        html += '</article>';
        return html;
    }

    function renderKeystore(ks) {
        var html = '<div class="adb-debug__block"><h5>Keystore</h5>';
        html += '<div class="adb-debug__flags">';
        html += flag(ks.has_adb_key === true, 'ADB key');
        html += flag(ks.has_last_connection === true, 'Last connection');
        html += flag(ks.has_version === true, 'Version');
        html += '</div>';
        var rows = '';
        var id = cleanText(ks.key_identifier || '');
        if (id) {
            rows += '<div class="adb-debug__row"><span>Identifier</span><code>' + esc(id) + '</code></div>';
        }
        if (ks.raw_length != null && ks.raw_length !== '') {
            rows += '<div class="adb-debug__row"><span>Keystore size</span><code>' + esc(String(ks.raw_length)) + ' bytes</code></div>';
        }
        Object.keys(ks).forEach(function (k) {
            if (k === 'has_adb_key' || k === 'has_last_connection' || k === 'has_version' || k === 'key_identifier' || k === 'raw_length') return;
            var v = ks[k];
            if (v && typeof v === 'object') return;
            rows += '<div class="adb-debug__row"><span>' + esc(labelize(k)) + '</span><code>' + esc(cleanText(v)) + '</code></div>';
        });
        if (rows) html += '<div class="adb-debug__rows">' + rows + '</div>';
        html += '</div>';
        return html;
    }

    window.renderDebuggingManagerHtml = function (dm) {
        if (!dm || typeof dm !== 'object') return '';
        var html = '<section class="adb-debug"><h4 class="adb-debug__title">Debugging manager</h4>';
        html += '<div class="adb-debug__status">';
        if (typeof dm.connected_to_adb === 'boolean') {
            html += '<span class="adb-debug__pill' + (dm.connected_to_adb ? ' is-on' : ' is-off') + '">' +
                (dm.connected_to_adb ? 'Connected to ADB' : 'Not connected to ADB') + '</span>';
        }
        var last = cleanText(dm.last_key_received || '');
        if (last) {
            html += '<div class="adb-debug__fingerprint"><span>Last key received</span><code>' + esc(last) + '</code>' +
                copyButton(last, 'Copy') + '</div>';
        }
        html += '</div>';

        var keys = Array.isArray(dm.user_keys_parsed) ? dm.user_keys_parsed : [];
        if (keys.length) {
            html += '<div class="adb-debug__block"><h5>Authorized keys <span class="adb-debug__count">' + keys.length + '</span></h5>';
            keys.forEach(function (entry) {
                var row = entry && typeof entry === 'object' ? entry : { raw: String(entry) };
                html += renderKeyCard(row);
            });
            html += '</div>';
        }

        if (dm.keystore_parsed && typeof dm.keystore_parsed === 'object' && !Array.isArray(dm.keystore_parsed)) {
            html += renderKeystore(dm.keystore_parsed);
        }

        var skip = {
            user_keys: true,
            keystore: true,
            user_keys_parsed: true,
            keystore_parsed: true,
            connected_to_adb: true,
            last_key_received: true
        };
        var extra = '';
        Object.keys(dm).forEach(function (k) {
            if (skip[k]) return;
            var v = dm[k];
            if (v && typeof v === 'object') return;
            extra += '<div class="adb-debug__row"><span>' + esc(labelize(k)) + '</span><code>' + esc(cleanText(v)) + '</code></div>';
        });
        if (extra) html += '<div class="adb-debug__block"><h5>Other fields</h5><div class="adb-debug__rows">' + extra + '</div></div>';

        html += '</section>';
        return html;
    };

    document.addEventListener('click', function (ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest('.adb-debug__copy') : null;
        if (!btn) return;
        var text = btn.getAttribute('data-copy') || '';
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
            var prev = btn.textContent;
            btn.textContent = 'Copied';
            btn.classList.add('is-copied');
            window.setTimeout(function () {
                btn.textContent = prev;
                btn.classList.remove('is-copied');
            }, 1200);
        }).catch(function () {});
    });
})();

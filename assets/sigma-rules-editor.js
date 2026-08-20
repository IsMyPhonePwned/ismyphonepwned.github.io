/**
 * Session Sigma rules pack: edit / add / delete after a scan, then rescan.
 * Shared by android.html and iphone.html.
 */
(function () {
    'use strict';

    var BLANK_RULE = [
        'title: Custom rule',
        'id: custom-rule',
        'status: experimental',
        'description: |',
        '  Describe what this rule detects.',
        'logsource:',
        '  product: android',
        'detection:',
        '  selection:',
        '    # field: value',
        '  condition: selection',
        'level: medium',
        '',
    ].join('\n');

    var session = [];
    var lastOpts = null;

    function escapeHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function mapPlainTop(x) {
        if (x && typeof x === 'object' && typeof Map !== 'undefined' && x instanceof Map) {
            return Object.fromEntries(x);
        }
        return x;
    }

    function asArray(v) {
        if (v == null) return [];
        if (Array.isArray(v)) return v;
        if (typeof v === 'object' && typeof v.length === 'number') return Array.from(v);
        return [];
    }

    function parseMeta(yamlText) {
        var o = { title: null, id: null, description: null, status: null, level: null };
        if (!yamlText || typeof yamlText !== 'string') return o;
        function m(name, pat) {
            var r = yamlText.match(pat);
            if (r) o[name] = r[1].trim();
        }
        m('title', /^title:\s*(.+)$/m);
        m('id', /^id:\s*(.+)$/m);
        m('status', /^status:\s*(.+)$/m);
        m('level', /^level:\s*(.+)$/m);
        var desc = yamlText.match(/^description:\s*(.+)$/m);
        if (desc) o.description = desc[1].replace(/\s+/g, ' ').trim();
        return o;
    }

    function cloneEntry(raw) {
        var r = mapPlainTop(raw) || {};
        var content = typeof r.content === 'string' ? r.content : r.content == null ? '' : String(r.content);
        return {
            url: r.url || '',
            success: !!r.success || !!(content && content.trim()),
            fetchError: r.fetchError || null,
            title: r.title != null ? r.title : null,
            id: r.id != null ? r.id : null,
            description: r.description != null ? r.description : null,
            status: r.status != null ? r.status : null,
            level: r.level != null ? r.level : null,
            content: content,
            custom: !!r.custom,
        };
    }

    function cloneRulesInfo(info) {
        return asArray(info).map(cloneEntry);
    }

    function applyMetaFromContent(entry) {
        var meta = parseMeta(entry.content || '');
        entry.title = meta.title;
        entry.id = meta.id;
        entry.description = meta.description;
        entry.status = meta.status;
        entry.level = meta.level;
        entry.success = !!(entry.content && String(entry.content).trim());
        if (entry.success) entry.fetchError = null;
        return entry;
    }

    function rebuildRulesString(info) {
        return asArray(info)
            .map(function (r) {
                return typeof r.content === 'string' ? r.content.trim() : '';
            })
            .filter(Boolean)
            .join('\n---\n');
    }

    function setSession(rulesInfo) {
        session = cloneRulesInfo(rulesInfo);
        return session;
    }

    function clearSession() {
        session = [];
        lastOpts = null;
    }

    function getSession() {
        return session;
    }

    function getPack() {
        return {
            rules: rebuildRulesString(session),
            rulesInfo: cloneRulesInfo(session),
        };
    }

    function packLabel(pack, key, fallback) {
        return (pack && pack[key]) || fallback;
    }

    function syncFromDom(container) {
        if (!container) return session;
        var cards = container.querySelectorAll('[data-sigma-rule-idx]');
        cards.forEach(function (card) {
            var idx = Number(card.getAttribute('data-sigma-rule-idx'));
            if (!Number.isFinite(idx) || idx < 0 || idx >= session.length) return;
            var ta = card.querySelector('textarea.sigma-rule-editor');
            if (!ta) return;
            session[idx].content = ta.value;
            applyMetaFromContent(session[idx]);
        });
        return session;
    }

    function renderToolbar(pack, canRescan) {
        var rescanDisabled = canRescan ? '' : ' disabled';
        var rescanTitle = canRescan
            ? ''
            : ' title="' + escapeHtml(packLabel(pack, 'sigmaRescanUnavailable', 'Re-analyze after a successful scan that kept the dump in memory.')) + '"';
        return (
            '<div class="sigma-session-toolbar" role="toolbar" aria-label="' +
            escapeHtml(packLabel(pack, 'sigmaRulesToolbar', 'Rules session')) +
            '">' +
            '<button type="button" class="sigma-session-btn sigma-session-btn--primary" data-sigma-action="rescan"' +
            rescanDisabled +
            rescanTitle +
            '>' +
            escapeHtml(packLabel(pack, 'sigmaRescan', 'Rescan with current rules')) +
            '</button>' +
            '<button type="button" class="sigma-session-btn" data-sigma-action="add">' +
            escapeHtml(packLabel(pack, 'sigmaAddRule', 'Add rule')) +
            '</button>' +
            '<button type="button" class="sigma-session-btn" data-sigma-action="reset">' +
            escapeHtml(packLabel(pack, 'sigmaResetRules', 'Reset to bundled')) +
            '</button>' +
            '<p class="sigma-session-hint">' +
            escapeHtml(
                packLabel(
                    pack,
                    'sigmaRulesEditHint',
                    'Edit YAML below, add or delete rules, then rescan the same dump.'
                )
            ) +
            '</p>' +
            '</div>'
        );
    }

    function renderCard(r, idx, pack) {
        var sourceBadge = r.custom
            ? '<span class="sigma-fetch-ok">' + escapeHtml(packLabel(pack, 'sigmaRuleCustom', 'Custom')) + '</span>'
            : r.success
              ? '<span class="sigma-fetch-ok">' + escapeHtml(packLabel(pack, 'sigmaRuleLoaded', 'Loaded')) + '</span>'
              : '<span class="sigma-fetch-err">✗ ' + escapeHtml(r.fetchError || packLabel(pack, 'sigmaRuleFailed', 'Failed')) + '</span>';
        var sourceLabel = r.custom
            ? packLabel(pack, 'sigmaRuleSourceCustom', 'Session')
            : r.url
              ? escapeHtml(r.url)
              : packLabel(pack, 'sigmaRuleSourceCustom', 'Session');
        var rows = [
            [packLabel(pack, 'sigmaRuleFieldSource', 'Source'), sourceLabel],
            [packLabel(pack, 'sigmaRuleFieldStatus', 'Load'), sourceBadge],
            [packLabel(pack, 'sigmaRuleFieldTitle', 'Title'), r.title ? escapeHtml(r.title) : '—'],
            [packLabel(pack, 'sigmaRuleFieldId', 'ID'), r.id ? escapeHtml(r.id) : '—'],
            [packLabel(pack, 'sigmaRuleFieldLevel', 'Level'), r.level ? escapeHtml(r.level) : '—'],
        ];
        var body = rows
            .map(function (row) {
                return (
                    '<div class="sigma-rule-row"><span class="sigma-rule-label">' +
                    escapeHtml(row[0]) +
                    '</span><span class="sigma-rule-value">' +
                    row[1] +
                    '</span></div>'
                );
            })
            .join('');
        var openAttr = r.custom || !(r.content && String(r.content).trim()) ? ' open' : '';
        return (
            '<div class="sigma-rule-card sigma-rule-card--editable" data-sigma-rule-idx="' +
            idx +
            '">' +
            body +
            '<div class="sigma-rule-card-actions">' +
            '<button type="button" class="sigma-session-btn sigma-session-btn--danger" data-sigma-action="delete" data-sigma-rule-idx="' +
            idx +
            '">' +
            escapeHtml(packLabel(pack, 'sigmaDeleteRule', 'Delete')) +
            '</button>' +
            '</div>' +
            '<details class="sigma-rule-content"' +
            openAttr +
            '>' +
            '<summary class="sigma-rule-content__summary">' +
            escapeHtml(packLabel(pack, 'sigmaEditContent', 'Edit rule YAML')) +
            '</summary>' +
            '<textarea class="sigma-rule-editor" spellcheck="false" rows="14" aria-label="' +
            escapeHtml(packLabel(pack, 'sigmaEditContent', 'Edit rule YAML')) +
            '">' +
            escapeHtml(r.content || '') +
            '</textarea>' +
            '</details>' +
            '</div>'
        );
    }

    function renderInto(container, opts) {
        opts = opts || {};
        lastOpts = opts;
        var pack = opts.i18nPack || {};
        var canRescan = !!opts.canRescan;
        if (!container) return;

        if (!session.length) {
            container.innerHTML =
                renderToolbar(pack, canRescan) +
                '<p class="detection-empty">' +
                escapeHtml(packLabel(pack, 'sigmaNoRules', 'No rules loaded.')) +
                '</p>';
        } else {
            container.innerHTML =
                renderToolbar(pack, canRescan) + session.map(function (r, i) {
                    return renderCard(r, i, pack);
                }).join('');
        }
        wire(container, opts);
    }

    function wire(container, opts) {
        if (!container) return;
        container.querySelectorAll('textarea.sigma-rule-editor').forEach(function (ta) {
            ta.addEventListener('change', function () {
                syncFromDom(container);
                var card = ta.closest('[data-sigma-rule-idx]');
                if (!card) return;
                var idx = Number(card.getAttribute('data-sigma-rule-idx'));
                if (!session[idx]) return;
                var titleEl = card.querySelectorAll('.sigma-rule-value')[2];
                var idEl = card.querySelectorAll('.sigma-rule-value')[3];
                var levelEl = card.querySelectorAll('.sigma-rule-value')[4];
                if (titleEl) titleEl.textContent = session[idx].title || '—';
                if (idEl) idEl.textContent = session[idx].id || '—';
                if (levelEl) levelEl.textContent = session[idx].level || '—';
            });
        });
        container.querySelectorAll('[data-sigma-action]').forEach(function (btn) {
            btn.addEventListener('click', function (ev) {
                ev.preventDefault();
                var action = btn.getAttribute('data-sigma-action');
                if (action === 'rescan') {
                    syncFromDom(container);
                    if (typeof opts.onRescan === 'function') opts.onRescan(getPack());
                    return;
                }
                if (action === 'add') {
                    syncFromDom(container);
                    var n = session.filter(function (r) {
                        return r.custom;
                    }).length;
                    var template = (opts && opts.blankRuleYaml) || BLANK_RULE;
                    var yaml = String(template).replace(/id:\s*custom-rule\b/, 'id: custom-rule-' + (n + 1));
                    var entry = applyMetaFromContent({
                        url: '',
                        success: true,
                        fetchError: null,
                        content: yaml,
                        custom: true,
                    });
                    session.push(entry);
                    renderInto(container, opts);
                    try {
                        var rulesContent =
                            document.getElementById('sigma-rules-content') ||
                            document.getElementById('iphone-sigma-rules-content');
                        if (rulesContent && rulesContent.classList.contains('collapsed')) {
                            rulesContent.classList.remove('collapsed');
                            var toggle =
                                rulesContent.previousElementSibling &&
                                rulesContent.previousElementSibling.querySelector('.section-toggle');
                            if (toggle) toggle.classList.remove('collapsed');
                        }
                    } catch (e) {
                        /* ignore */
                    }
                    var lastTa = container.querySelector(
                        '.sigma-rule-card--editable:last-of-type textarea.sigma-rule-editor'
                    );
                    if (lastTa) {
                        lastTa.focus();
                        lastTa.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    }
                    return;
                }
                if (action === 'reset') {
                    if (typeof opts.onReset === 'function') opts.onReset();
                    return;
                }
                if (action === 'delete') {
                    syncFromDom(container);
                    var idx = Number(btn.getAttribute('data-sigma-rule-idx'));
                    if (!Number.isFinite(idx) || idx < 0 || idx >= session.length) return;
                    session.splice(idx, 1);
                    renderInto(container, opts);
                }
            });
        });
    }

    function refresh(container) {
        if (!lastOpts) return;
        renderInto(container || lastOpts.container, lastOpts);
    }

    window.SigmaRulesEditor = {
        BLANK_RULE: BLANK_RULE,
        parseMeta: parseMeta,
        cloneRulesInfo: cloneRulesInfo,
        rebuildRulesString: rebuildRulesString,
        setSession: setSession,
        clearSession: clearSession,
        getSession: getSession,
        getPack: getPack,
        syncFromDom: syncFromDom,
        renderInto: renderInto,
        refresh: refresh,
    };
})();

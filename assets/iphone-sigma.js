/** Sigma rules fetch + results UI for iphone.html (shared patterns with android.html). */
(function () {
    'use strict';

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function i18nPack() {
        return (
            (window.IPHONE_I18N && window.IPHONE_I18N[window.currentLang || 'en']) ||
            (window.IPHONE_I18N && window.IPHONE_I18N.en) ||
            {}
        );
    }

    function i18nFmt(key, vars) {
        var s = i18nPack()[key] || key;
        if (vars) {
            Object.keys(vars).forEach(function (k) {
                s = s.replace('{' + k + '}', String(vars[k]));
            });
        }
        return s;
    }

    function mapPlainTop(x) {
        if (x && typeof x === 'object' && typeof Map !== 'undefined' && x instanceof Map) {
            return Object.fromEntries(x);
        }
        return x;
    }

    function asWasmArray(v) {
        if (v == null) return [];
        if (Array.isArray(v)) return v;
        if (typeof v === 'object' && typeof v.length === 'number') {
            return Array.from(v);
        }
        return [];
    }

    function parseSigmaRuleMeta(yamlText) {
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

    async function fetchSigmaRules() {
        var urls = window.SIGMA_RULE_URLS || [];
        console.log('[fetchSigmaRules] Fetching Sigma rules:', urls.join(', '));
        try {
            var fetchOne = async function (url) {
                try {
                    var res = await fetch(url);
                    var text = res.ok ? await res.text() : '';
                    var success = !!(res.ok && (text || '').length > 0);
                    if (success) {
                        console.log('[fetchSigmaRules] ✓ ' + url + ': ' + res.status + ', ' + (text || '').length + ' chars');
                    } else {
                        console.warn('[fetchSigmaRules] ✗ ' + url + ': ' + res.status + ' ' + res.statusText);
                    }
                    return {
                        text: text,
                        success: success,
                        httpStatus: res.status,
                        fetchError: success ? null : res.status + ' ' + (res.statusText || ''),
                        url: url,
                    };
                } catch (e) {
                    console.warn('[fetchSigmaRules] ✗ ' + url + ':', e);
                    return {
                        text: '',
                        success: false,
                        httpStatus: null,
                        fetchError: 'Network error: ' + (e.message || String(e)),
                        url: url,
                    };
                }
            };
            var results = await Promise.all(urls.map(fetchOne));
            var combined = results
                .filter(function (r) {
                    return (r.text || '').length > 0;
                })
                .map(function (r) {
                    return r.text;
                })
                .join('\n---\n');
            var rulesInfo = results.map(function (r) {
                var meta = r.success ? parseSigmaRuleMeta(r.text) : {};
                return {
                    url: r.url,
                    success: r.success,
                    fetchError: r.fetchError || null,
                    title: meta.title != null ? meta.title : null,
                    id: meta.id != null ? meta.id : null,
                    description: meta.description != null ? meta.description : null,
                    status: meta.status != null ? meta.status : null,
                    level: meta.level != null ? meta.level : null,
                };
            });
            var count = rulesInfo.filter(function (r) {
                return r.success;
            }).length;
            if (count > 0) {
                console.log('[fetchSigmaRules] Loaded ' + count + ' rule file(s), ' + combined.length + ' chars total');
            } else {
                console.warn('[fetchSigmaRules] No rules loaded (all fetches failed or empty)');
            }
            return { rules: combined, rulesInfo: rulesInfo };
        } catch (e) {
            console.warn('[fetchSigmaRules] Could not fetch Sigma rules:', e);
            return { rules: '', rulesInfo: [] };
        }
    }

    var SIGMA_LEVEL_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

    function sigmaLevelClass(level) {
        var l = (level || '').toLowerCase();
        if (l === 'critical') return 'critical';
        if (l === 'high') return 'high';
        if (l === 'medium') return 'medium';
        if (l === 'low') return 'low';
        return 'unknown';
    }

    function extractSigmaMatchLog(m) {
        var ml = m.log_entry != null ? m.log_entry : m.matched_log;
        if (ml && typeof ml === 'object' && ml instanceof Map) {
            ml = Object.fromEntries(ml);
        }
        if (ml && typeof ml === 'object' && !Array.isArray(ml)) return ml;
        return null;
    }

    function sigmaMatchLogPreview(ml) {
        if (!ml || typeof ml !== 'object') return '';
        var ts = ml.timestamp || ml.time || ml.datetime || ml['@timestamp'];
        var entry = ml.log_entry || ml.message || ml.subject || ml.pkg || ml.package;
        var parts = [];
        if (ts) parts.push(String(ts));
        if (entry) {
            var s = String(entry);
            parts.push(s.length > 90 ? s.slice(0, 87) + '…' : s);
        }
        if (parts.length) return parts.join(' — ');
        var keys = Object.keys(ml);
        if (keys.length) {
            var k = keys[0];
            var v = String(ml[k] != null ? ml[k] : '');
            return k + ': ' + (v.length > 60 ? v.slice(0, 57) + '…' : v);
        }
        return '';
    }

    function renderSigmaLogBodyHtml(ml) {
        if (!ml || typeof ml !== 'object' || Array.isArray(ml) || Object.keys(ml).length === 0) {
            return '';
        }
        function fmt(v) {
            return typeof v === 'object' && v !== null ? escapeHtml(JSON.stringify(v)) : escapeHtml(String(v != null ? v : ''));
        }
        return Object.entries(ml)
            .map(function (kv) {
                return (
                    '<div style="margin-bottom: 0.2rem;"><span style="color: var(--text-secondary);">' +
                    escapeHtml(kv[0]) +
                    ':</span> ' +
                    fmt(kv[1]) +
                    '</div>'
                );
            })
            .join('');
    }

    function sigmaMatchGroupKey(m) {
        var id = (m.rule_id || '').trim();
        if (id) return id;
        var title = (m.rule_title || '').trim();
        if (title) return 'title:' + title;
        return 'unknown';
    }

    function groupSigmaMatches(rawMatches) {
        var matches = rawMatches.map(function (raw) {
            return mapPlainTop(raw) || raw;
        });
        var groups = new Map();
        matches.forEach(function (m) {
            var key = sigmaMatchGroupKey(m);
            if (!groups.has(key)) {
                groups.set(key, {
                    rule_id: (m.rule_id || '').trim(),
                    rule_title: (m.rule_title || '').trim(),
                    level: (m.level || '').trim(),
                    items: [],
                });
            }
            var g = groups.get(key);
            g.items.push(m);
            if (!g.rule_title && m.rule_title) g.rule_title = String(m.rule_title).trim();
            if (!g.rule_id && m.rule_id) g.rule_id = String(m.rule_id).trim();
            var cur = SIGMA_LEVEL_ORDER[sigmaLevelClass(g.level)] != null ? SIGMA_LEVEL_ORDER[sigmaLevelClass(g.level)] : 4;
            var next = SIGMA_LEVEL_ORDER[sigmaLevelClass(m.level)] != null ? SIGMA_LEVEL_ORDER[sigmaLevelClass(m.level)] : 4;
            if (next < cur) g.level = String(m.level).trim();
        });
        return Array.from(groups.values()).sort(function (a, b) {
            var la = SIGMA_LEVEL_ORDER[sigmaLevelClass(a.level)] != null ? SIGMA_LEVEL_ORDER[sigmaLevelClass(a.level)] : 4;
            var lb = SIGMA_LEVEL_ORDER[sigmaLevelClass(b.level)] != null ? SIGMA_LEVEL_ORDER[sigmaLevelClass(b.level)] : 4;
            if (la !== lb) return la - lb;
            return b.items.length - a.items.length;
        });
    }

    function renderSigmaMatchesGroupedHtml(rawMatches) {
        var pack = i18nPack();
        var groups = groupSigmaMatches(rawMatches);
        if (!groups.length) {
            return '<p class="detection-empty">' + escapeHtml(pack.sigmaNoMatches || 'No matches.') + '</p>';
        }
        return groups
            .map(function (g) {
                var id = g.rule_id ? escapeHtml(g.rule_id) : '-';
                var title = g.rule_title ? escapeHtml(g.rule_title) : '-';
                var level = g.level ? escapeHtml(g.level) : '-';
                var lvlCls = sigmaLevelClass(g.level);
                var n = g.items.length;
                var countLabel =
                    n === 1
                        ? escapeHtml(pack.sigmaMatchCountOne || '1 occurrence')
                        : escapeHtml(i18nFmt('sigmaMatchCount', { n: n }));

                var bodyHtml = '';
                if (n === 1) {
                    var ml = extractSigmaMatchLog(g.items[0]);
                    var logBody = renderSigmaLogBodyHtml(ml);
                    if (logBody) {
                        bodyHtml =
                            '<details class="sigma-matched-log" open><summary>' +
                            escapeHtml(pack.sigmaMatchedLog || 'Matched log') +
                            '</summary><div class="sigma-matched-log-body">' +
                            logBody +
                            '</div></details>';
                    }
                } else {
                    var occHtml = g.items
                        .map(function (m, i) {
                            var mlOcc = extractSigmaMatchLog(m);
                            var preview = sigmaMatchLogPreview(mlOcc);
                            var occTitle = i18nFmt('sigmaMatchOccurrence', { n: i + 1 });
                            var occLabel = escapeHtml(preview ? occTitle + ' — ' + preview : occTitle);
                            var logBodyOcc = renderSigmaLogBodyHtml(mlOcc);
                            if (!logBodyOcc) {
                                return (
                                    '<div class="sigma-match-occurrence sigma-match-occurrence--empty">' +
                                    '<span class="sigma-match-occurrence-label">' +
                                    occLabel +
                                    '</span></div>'
                                );
                            }
                            return (
                                '<details class="sigma-matched-log sigma-match-occurrence"><summary>' +
                                occLabel +
                                '</summary><div class="sigma-matched-log-body">' +
                                logBodyOcc +
                                '</div></details>'
                            );
                        })
                        .join('');
                    bodyHtml =
                        '<details class="sigma-match-occurrences"><summary class="sigma-match-occurrences-summary">' +
                        escapeHtml(i18nFmt('sigmaMatchShowLogs', { n: n })) +
                        '</summary><div class="sigma-match-occurrence-list">' +
                        occHtml +
                        '</div></details>';
                }

                return (
                    '<div class="sigma-match-card sigma-match-card--' +
                    lvlCls +
                    '"><div class="sigma-match-title">' +
                    title +
                    '</div><div class="sigma-match-meta"><span>ID: ' +
                    id +
                    '</span><span class="sigma-level-badge sigma-level-badge--' +
                    lvlCls +
                    '">' +
                    level +
                    '</span><span class="sigma-match-count">' +
                    countLabel +
                    '</span></div>' +
                    bodyHtml +
                    '</div>'
                );
            })
            .join('');
    }

    function updateSigmaSummaryBar(data) {
        var bar = document.getElementById('iphone-sigma-summary-bar');
        if (!bar) return;
        var pack = i18nPack();
        var rules = asWasmArray(data.sigma_rules_info);
        var matches = asWasmArray(data.sigma_matches);
        var chips = [];
        if (rules.length > 0) {
            chips.push(
                '<span class="sigma-summary-chip sigma-summary-chip--rules">' +
                    escapeHtml(i18nFmt('sigmaChipRules', { n: rules.length })) +
                    '</span>'
            );
        }
        if (matches.length > 0) {
            var groups = groupSigmaMatches(matches);
            chips.push(
                '<span class="sigma-summary-chip sigma-summary-chip--matches">' +
                    escapeHtml(
                        groups.length < matches.length
                            ? i18nFmt('sigmaChipMatchDetail', { hits: matches.length, rules: groups.length })
                            : i18nFmt('sigmaChipMatches', { n: matches.length })
                    ) +
                    '</span>'
            );
        } else {
            chips.push(
                '<span class="sigma-summary-chip sigma-summary-chip--clean">' +
                    escapeHtml(pack.sigmaChipClean || 'No matches') +
                    '</span>'
            );
        }
        bar.innerHTML = chips.join('');
    }

    function renderSigmaRulesContainerHtml(data) {
        var pack = i18nPack();
        var info = asWasmArray(data.sigma_rules_info);
        if (!info.length) {
            return '<p class="detection-empty">' + escapeHtml(pack.sigmaNoRules || 'No rules loaded.') + '</p>';
        }
        return info
            .map(function (rawR) {
                var r = mapPlainTop(rawR) || rawR;
                var fetchBadge = r.success
                    ? '<span class="sigma-fetch-ok">✓ Fetched</span>'
                    : '<span class="sigma-fetch-err">✗ ' + escapeHtml(r.fetchError || 'Failed') + '</span>';
                var rows = [
                    ['URL', escapeHtml(r.url)],
                    ['Server', fetchBadge],
                    ['Title', r.title ? escapeHtml(r.title) : '-'],
                    ['ID', r.id ? escapeHtml(r.id) : '-'],
                    ['Description', r.description ? escapeHtml(r.description) : '-'],
                    ['Status', r.status ? escapeHtml(r.status) : '-'],
                    ['Level', r.level ? escapeHtml(r.level) : '-'],
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
                return '<div class="sigma-rule-card">' + body + '</div>';
            })
            .join('');
    }

    var sigmaDetailsData = null;
    var sigmaDetailsBuilt = false;

    function ensureSysdiagnoseSigmaDetails() {
        if (sigmaDetailsBuilt || !sigmaDetailsData) return;
        sigmaDetailsBuilt = true;
        var pack = i18nPack();
        var sigmaEl = document.getElementById('iphone-sigma-rules-container');
        var matchesEl = document.getElementById('iphone-sigma-matches-container');
        if (sigmaEl) {
            sigmaEl.innerHTML = renderSigmaRulesContainerHtml(sigmaDetailsData);
        }
        if (matchesEl) {
            matchesEl.innerHTML = renderSigmaMatchesGroupedHtml(asWasmArray(sigmaDetailsData.sigma_matches));
        }
        if (!sigmaEl && !matchesEl) {
            sigmaDetailsBuilt = false;
        }
    }

    function renderSysdiagnoseSigmaUI(data, opts) {
        opts = opts || {};
        data = data || {};
        sigmaDetailsData = data;
        sigmaDetailsBuilt = false;
        var section = document.getElementById('iphone-detection-section');
        if (!section) return;
        section.style.display = 'block';
        updateSigmaSummaryBar(data);

        var pack = i18nPack();
        var sigmaEl = document.getElementById('iphone-sigma-rules-container');
        var matchesEl = document.getElementById('iphone-sigma-matches-container');
        var hint = '<p class="detection-empty">' + escapeHtml(pack.sigmaExpandHint || 'Expand to load details.') + '</p>';
        if (opts.deferDetails) {
            if (sigmaEl) sigmaEl.innerHTML = hint;
            if (matchesEl) matchesEl.innerHTML = hint;
            return;
        }
        ensureSysdiagnoseSigmaDetails();
    }

    function hideSysdiagnoseSigmaUI() {
        var section = document.getElementById('iphone-detection-section');
        if (section) section.style.display = 'none';
    }

    window.fetchSigmaRules = fetchSigmaRules;
    window.renderSysdiagnoseSigmaUI = renderSysdiagnoseSigmaUI;
    window.ensureIphoneSigmaDetails = ensureSysdiagnoseSigmaDetails;
    window.hideSysdiagnoseSigmaUI = hideSysdiagnoseSigmaUI;
})();

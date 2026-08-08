/** Shared Sigma match / occurrence rendering for android.html + iphone-sigma.js. */
(function (global) {
    'use strict';

    var LEVEL_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
    var LEVELS = ['critical', 'high', 'medium', 'low'];

    var PRIORITY_KEYS = [
        'timestamp',
        'time',
        'datetime',
        '@timestamp',
        'message',
        'log_entry',
        'subject',
        'process',
        'process_name',
        'processName',
        'package',
        'pkg',
        'package_name',
        'uid',
        'pid',
        'tid',
        'tag',
        'level',
        'severity',
        'event_type',
        'event',
        'path',
        'file',
        'source',
        'log_source',
        'facility',
    ];

    var HEADLINE_KEYS = ['message', 'log_entry', 'subject', 'cmd', 'event', 'event_type'];
    var TIME_KEYS = ['timestamp', 'time', 'datetime', '@timestamp', 'date'];
    /** Fields that answer “where is this happening?” — shown before the message. */
    var WHERE_KEYS = [
        'package',
        'pkg',
        'package_name',
        'process',
        'process_name',
        'processName',
        'cmd',
        'tag',
        'section',
        'component',
        'activity',
        'service',
        'path',
        'file',
        'source',
        'log_source',
        'facility',
        'uid',
        'pid',
    ];
    var META_KEYS = WHERE_KEYS.concat(['level', 'severity', 'event_type', 'event', 'tid']);
    var FEATURED_KEYS = { message: 1, subject: 1, cmd: 1 };
    var CHIP_LABEL = {
        package: 'pkg',
        pkg: 'pkg',
        package_name: 'pkg',
        process: 'proc',
        process_name: 'proc',
        processName: 'proc',
        cmd: 'cmd',
        uid: 'uid',
        pid: 'pid',
        tag: 'tag',
        section: 'sec',
        component: 'cmp',
        activity: 'act',
        service: 'svc',
        path: 'path',
        file: 'file',
        source: 'src',
        log_source: 'src',
        facility: 'fac',
        level: 'lvl',
        severity: 'sev',
        event_type: 'evt',
        event: 'evt',
        tid: 'tid',
    };

    function levelClass(level) {
        var l = (level || '').toLowerCase();
        if (l === 'critical') return 'critical';
        if (l === 'high') return 'high';
        if (l === 'medium') return 'medium';
        if (l === 'low') return 'low';
        return 'unknown';
    }

    function mapPlainTop(x) {
        if (x && typeof x === 'object' && typeof Map !== 'undefined' && x instanceof Map) {
            return Object.fromEntries(x);
        }
        return x;
    }

    function asPlainObject(v) {
        if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
        if (typeof Map !== 'undefined' && v instanceof Map) return Object.fromEntries(v);
        return v;
    }

    function flattenLog(ml) {
        ml = asPlainObject(ml);
        if (!ml) return null;
        var out = {};
        Object.keys(ml).forEach(function (k) {
            out[k] = ml[k];
        });
        // Some payloads nest the real fields under log_entry / matched_log / fields.
        ['log_entry', 'matched_log', 'fields', 'data'].forEach(function (nestKey) {
            var nested = asPlainObject(ml[nestKey]);
            if (!nested) return;
            Object.keys(nested).forEach(function (k) {
                if (out[k] == null || out[k] === '') out[k] = nested[k];
            });
            // Prefer nested string message if parent only held an object under log_entry.
            if (typeof ml[nestKey] === 'string' && !out.message) {
                out.message = ml[nestKey];
            }
        });
        if (typeof ml.log_entry === 'string' && !out.message) {
            out.message = ml.log_entry;
        }
        return out;
    }

    function extractLog(m) {
        if (!m || typeof m !== 'object') return null;
        // Prefer matched_log (full trigger payload); fall back to log_entry.
        var ml = m.matched_log != null ? m.matched_log : m.log_entry;
        if (ml == null && m.fields != null) ml = m.fields;
        return deepPlain(flattenLog(ml));
    }

    function pickFirst(ml, keys) {
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            if (ml[k] != null && String(ml[k]).trim() !== '') return { key: k, value: ml[k] };
        }
        return null;
    }

    function truncate(s, max) {
        s = String(s == null ? '' : s);
        if (s.length <= max) return s;
        return s.slice(0, Math.max(0, max - 1)) + '…';
    }

    function formatValue(v, pretty) {
        if (typeof v === 'object' && v !== null) {
            try {
                return JSON.stringify(v, null, pretty ? 2 : 0);
            } catch (e) {
                return String(v);
            }
        }
        return String(v == null ? '' : v);
    }

    function parseTimeMs(raw) {
        if (raw == null || raw === '') return NaN;
        if (typeof raw === 'number' && isFinite(raw)) {
            return raw < 1e12 ? raw * 1000 : raw;
        }
        var s = String(raw).trim();
        if (/^\d+$/.test(s)) {
            var n = Number(s);
            return n < 1e12 ? n * 1000 : n;
        }
        var t = Date.parse(s);
        return t;
    }

    function logTimeMs(ml) {
        if (!ml) return NaN;
        var pick = pickFirst(ml, TIME_KEYS);
        return pick ? parseTimeMs(pick.value) : NaN;
    }

    function orderedEntries(ml) {
        var keys = Object.keys(ml);
        var rank = {};
        PRIORITY_KEYS.forEach(function (k, i) {
            rank[k.toLowerCase()] = i;
        });
        keys.sort(function (a, b) {
            var ra = rank[a.toLowerCase()];
            var rb = rank[b.toLowerCase()];
            if (ra == null && rb == null) return a.localeCompare(b);
            if (ra == null) return 1;
            if (rb == null) return -1;
            return ra - rb;
        });
        return keys.map(function (k) {
            return [k, ml[k]];
        });
    }

    function isPriorityKey(k) {
        var lower = String(k).toLowerCase();
        for (var i = 0; i < PRIORITY_KEYS.length; i++) {
            if (PRIORITY_KEYS[i].toLowerCase() === lower) return true;
        }
        return false;
    }

    function summarizeLog(ml) {
        if (!ml || typeof ml !== 'object') {
            return { headline: '', time: '', where: '', chips: [] };
        }
        var headlinePick = pickFirst(ml, HEADLINE_KEYS);
        // Don't use object-valued log_entry as the headline (use flattened message instead).
        if (headlinePick && typeof headlinePick.value === 'object') {
            headlinePick = pickFirst(ml, ['message', 'subject', 'cmd', 'event', 'event_type']);
        }
        var timePick = pickFirst(ml, TIME_KEYS);
        var chips = [];
        var whereParts = [];
        var seen = {};
        WHERE_KEYS.forEach(function (k) {
            if (ml[k] == null || String(ml[k]).trim() === '') return;
            if (typeof ml[k] === 'object') return;
            var label = CHIP_LABEL[k] || k;
            var val = truncate(formatValue(ml[k]), 48);
            var sig = label + '=' + val;
            if (seen[sig]) return;
            seen[sig] = true;
            chips.push({ key: k, label: label, value: val });
            if (whereParts.length < 4) whereParts.push(label + ' ' + val);
        });
        META_KEYS.forEach(function (k) {
            if (ml[k] == null || String(ml[k]).trim() === '') return;
            if (typeof ml[k] === 'object') return;
            var label = CHIP_LABEL[k] || k;
            var val = truncate(formatValue(ml[k]), 36);
            var sig = label + '=' + val;
            if (seen[sig]) return;
            seen[sig] = true;
            chips.push({ key: k, label: label, value: val });
        });
        var headline = headlinePick ? truncate(formatValue(headlinePick.value), 160) : '';
        if (!headline) {
            var keys = Object.keys(ml).filter(function (k) {
                return TIME_KEYS.indexOf(k) === -1 && typeof ml[k] !== 'object';
            });
            if (keys.length) {
                headline = keys[0] + ': ' + truncate(formatValue(ml[keys[0]]), 100);
            }
        }
        return {
            headline: headline,
            time: timePick ? truncate(formatValue(timePick.value), 56) : '',
            where: whereParts.join(' · '),
            chips: chips.slice(0, 6),
        };
    }

    function deepPlain(v, depth) {
        if (depth == null) depth = 0;
        if (depth > 8) return v;
        if (v && typeof v === 'object' && typeof Map !== 'undefined' && v instanceof Map) {
            var fromMap = {};
            v.forEach(function (val, key) {
                fromMap[String(key)] = deepPlain(val, depth + 1);
            });
            return fromMap;
        }
        if (Array.isArray(v)) {
            return v.map(function (item) {
                return deepPlain(item, depth + 1);
            });
        }
        if (v && typeof v === 'object') {
            var out = {};
            Object.keys(v).forEach(function (k) {
                out[k] = deepPlain(v[k], depth + 1);
            });
            return out;
        }
        return v;
    }

    function renderLogBodyHtml(ml, escapeHtml, pack) {
        if (!ml || typeof ml !== 'object' || Array.isArray(ml) || !Object.keys(ml).length) {
            return '';
        }
        var featuredHtml = '';
        var rows = [];
        var skipKeys = {};

        orderedEntries(ml).forEach(function (kv) {
            var k = kv[0];
            var v = kv[1];
            // Skip nested envelopes already flattened into top-level keys.
            if (
                (k === 'log_entry' || k === 'matched_log' || k === 'fields' || k === 'data') &&
                typeof v === 'object' &&
                v !== null
            ) {
                return;
            }
            if (FEATURED_KEYS[k] && !featuredHtml && typeof v !== 'object') {
                featuredHtml =
                    '<div class="sigma-log-featured"><div class="sigma-log-featured-label">' +
                    escapeHtml(k) +
                    '</div><pre class="sigma-log-featured-text">' +
                    escapeHtml(formatValue(v, true)) +
                    '</pre></div>';
                skipKeys[k] = 1;
                return;
            }
            rows.push({ k: k, v: formatValue(v, typeof v === 'object' && v !== null) });
        });

        function rowHtml(row) {
            var longCls = row.v.length > 120 || row.v.indexOf('\n') !== -1 ? ' sigma-log-field--long' : '';
            var priCls = isPriorityKey(row.k) ? ' sigma-log-field--priority' : '';
            return (
                '<div class="sigma-log-field' +
                priCls +
                longCls +
                '"><dt class="sigma-log-key">' +
                escapeHtml(row.k) +
                '</dt><dd class="sigma-log-val">' +
                escapeHtml(row.v) +
                '</dd></div>'
            );
        }

        // Show every field — no “more fields” collapse.
        return (
            featuredHtml +
            '<dl class="sigma-log-fields">' +
            rows
                .filter(function (r) {
                    return !skipKeys[r.k];
                })
                .map(rowHtml)
                .join('') +
            '</dl>'
        );
    }

    function renderOccurrenceHtml(ml, index, opts) {
        var escapeHtml = opts.escapeHtml;
        var i18nFmt = opts.i18nFmt;
        var pack = opts.i18nPack || {};
        var hideIndex = !!opts.hideIndex;
        var open = !!opts.open;
        ml = deepPlain(ml);
        var logBody = renderLogBodyHtml(ml, escapeHtml, pack);
        var summary = summarizeLog(ml);
        var occTitle = i18nFmt('sigmaMatchOccurrence', { n: index + 1 });
        var rawJson = '';
        try {
            rawJson = ml ? JSON.stringify(ml, null, 2) : '';
        } catch (e) {
            rawJson = '';
        }

        var whenHtml =
            '<span class="sigma-occ-when' +
            (summary.time ? '' : ' sigma-occ-when--missing') +
            '" title="' +
            escapeHtml(pack.sigmaMatchWhen || 'When') +
            '">' +
            escapeHtml(summary.time || pack.sigmaMatchWhenUnknown || 'No timestamp') +
            '</span>';

        var whereHtml = summary.where
            ? '<span class="sigma-occ-where" title="' +
              escapeHtml(pack.sigmaMatchWhere || 'Where') +
              '">' +
              escapeHtml(summary.where) +
              '</span>'
            : '';

        var summaryInner =
            (hideIndex
                ? ''
                : '<span class="sigma-occ-index" aria-hidden="true">' +
                  escapeHtml(String(index + 1)) +
                  '</span>') +
            whenHtml +
            '<span class="sigma-occ-main">' +
            whereHtml +
            '<span class="sigma-occ-headline">' +
            escapeHtml(summary.headline || occTitle) +
            '</span></span>';

        if (!logBody && !rawJson) {
            return (
                '<div class="sigma-occ sigma-occ--empty">' + summaryInner + '</div>'
            );
        }

        var tools =
            '<div class="sigma-occ-tools">' +
            '<button type="button" class="sigma-occ-copy" data-sigma-copy="1"' +
            (rawJson ? ' data-copy="' + encodeURIComponent(rawJson) + '"' : '') +
            '>' +
            escapeHtml(pack.sigmaMatchCopyLog || 'Copy JSON') +
            '</button></div>';

        // Raw JSON stays collapsed until the user asks for it.
        var rawBlock = rawJson
            ? '<details class="sigma-occ-raw"><summary class="sigma-occ-raw-summary">' +
              escapeHtml(pack.sigmaMatchRawJson || 'Full matched log (JSON)') +
              '</summary><pre class="sigma-occ-raw-pre">' +
              escapeHtml(rawJson) +
              '</pre></details>'
            : '';

        return (
            '<details class="sigma-occ"' +
            (open ? ' open' : '') +
            '><summary class="sigma-occ-summary">' +
            summaryInner +
            '</summary><div class="sigma-occ-body">' +
            tools +
            logBody +
            rawBlock +
            '</div></details>'
        );
    }

    function groupKey(m) {
        var id = (m.rule_id || '').trim();
        if (id) return id;
        var title = (m.rule_title || '').trim();
        if (title) return 'title:' + title;
        return 'unknown';
    }

    function sortItemsByTime(items) {
        return items.slice().sort(function (a, b) {
            var ta = logTimeMs(extractLog(a));
            var tb = logTimeMs(extractLog(b));
            var aOk = isFinite(ta);
            var bOk = isFinite(tb);
            if (aOk && bOk && ta !== tb) return ta - tb;
            if (aOk && !bOk) return -1;
            if (!aOk && bOk) return 1;
            return 0;
        });
    }

    function groupMatches(rawMatches) {
        var matches = (rawMatches || []).map(function (raw) {
            return mapPlainTop(raw) || raw;
        });
        var groups = new Map();
        matches.forEach(function (m) {
            var key = groupKey(m);
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
            var cur = LEVEL_ORDER[levelClass(g.level)];
            var next = LEVEL_ORDER[levelClass(m.level)];
            if (cur == null) cur = 4;
            if (next == null) next = 4;
            if (next < cur) g.level = String(m.level).trim();
        });
        groups.forEach(function (g) {
            g.items = sortItemsByTime(g.items);
        });
        return Array.from(groups.values()).sort(function (a, b) {
            var la = LEVEL_ORDER[levelClass(a.level)];
            var lb = LEVEL_ORDER[levelClass(b.level)];
            if (la == null) la = 4;
            if (lb == null) lb = 4;
            if (la !== lb) return la - lb;
            return b.items.length - a.items.length;
        });
    }

    function timeSpanLabel(items) {
        var times = [];
        items.forEach(function (m) {
            var ml = extractLog(m);
            var pick = ml && pickFirst(ml, TIME_KEYS);
            if (pick) times.push(String(pick.value));
        });
        if (!times.length) return '';
        if (times.length === 1) return times[0];
        var first = times[0];
        var last = times[times.length - 1];
        if (first === last) return first;
        return first + ' → ' + last;
    }

    function searchBlob(g) {
        var parts = [g.rule_id, g.rule_title, g.level];
        g.items.forEach(function (m) {
            var ml = extractLog(m);
            if (!ml) return;
            Object.keys(ml).forEach(function (k) {
                parts.push(k);
                parts.push(formatValue(ml[k]));
            });
        });
        return parts.join(' ').toLowerCase();
    }

    function renderToolbarHtml(escapeHtml, pack, levelCounts) {
        var levelBtns = LEVELS.map(function (lvl) {
            var n = levelCounts[lvl] || 0;
            if (!n) return '';
            return (
                '<button type="button" class="sigma-matches-level" data-level="' +
                lvl +
                '"><span class="sigma-matches-level-dot sigma-matches-level-dot--' +
                lvl +
                '"></span>' +
                escapeHtml(lvl) +
                '<span class="sigma-matches-level-n">' +
                n +
                '</span></button>'
            );
        }).join('');

        return (
            '<div class="sigma-matches-toolbar">' +
            '<input type="search" class="sigma-matches-search" autocomplete="off" spellcheck="false" placeholder="' +
            escapeHtml(pack.sigmaMatchFilterPlaceholder || 'Filter matches…') +
            '" aria-label="' +
            escapeHtml(pack.sigmaMatchFilterPlaceholder || 'Filter matches…') +
            '">' +
            '<div class="sigma-matches-levels" role="toolbar" aria-label="Severity filter">' +
            '<button type="button" class="sigma-matches-level is-active" data-level="">' +
            escapeHtml(pack.sigmaMatchFilterAll || 'All levels') +
            '</button>' +
            levelBtns +
            '</div>' +
            '<div class="sigma-matches-rule-actions">' +
            '<button type="button" class="sigma-matches-rule-btn" data-sigma-expand-rules="1">' +
            escapeHtml(pack.sigmaMatchExpandRules || 'Expand all rules') +
            '</button>' +
            '<button type="button" class="sigma-matches-rule-btn" data-sigma-collapse-rules="1">' +
            escapeHtml(pack.sigmaMatchCollapseRules || 'Collapse all rules') +
            '</button></div></div>' +
            '<p class="sigma-matches-filter-empty" hidden>' +
            escapeHtml(pack.sigmaMatchFilterEmpty || 'No matches for this filter.') +
            '</p>'
        );
    }

    function renderGroupedHtml(rawMatches, opts) {
        var escapeHtml = opts.escapeHtml;
        var i18nFmt = opts.i18nFmt;
        var pack = opts.i18nPack || {};
        var groups = groupMatches(rawMatches);
        if (!groups.length) {
            return '<p class="detection-empty">' + escapeHtml(pack.sigmaNoMatches || 'No matches.') + '</p>';
        }

        var levelCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
        groups.forEach(function (g) {
            levelCounts[levelClass(g.level)] = (levelCounts[levelClass(g.level)] || 0) + 1;
        });

        var cards = groups
            .map(function (g) {
                var id = g.rule_id ? escapeHtml(g.rule_id) : '-';
                var title = g.rule_title ? escapeHtml(g.rule_title) : '-';
                var level = g.level ? escapeHtml(g.level) : '-';
                var lvlCls = levelClass(g.level);
                var n = g.items.length;
                var countLabel =
                    n === 1
                        ? escapeHtml(pack.sigmaMatchCountOne || '1 occurrence')
                        : escapeHtml(i18nFmt('sigmaMatchCount', { n: n }));
                var span = timeSpanLabel(g.items);
                var blob = escapeHtml(searchBlob(g));

                var occOpts = {
                    escapeHtml: escapeHtml,
                    i18nFmt: i18nFmt,
                    i18nPack: pack,
                };
                var bodyHtml = '';
                if (n === 1) {
                    bodyHtml =
                        '<div class="sigma-match-occs sigma-match-occs--single">' +
                        renderOccurrenceHtml(
                            extractLog(g.items[0]),
                            0,
                            Object.assign({}, occOpts, { hideIndex: true, open: false })
                        ) +
                        '</div>';
                } else {
                    var occHtml = g.items
                        .map(function (m, i) {
                            return renderOccurrenceHtml(extractLog(m), i, occOpts);
                        })
                        .join('');
                    bodyHtml =
                        '<div class="sigma-match-occs">' +
                        '<div class="sigma-match-occs-head">' +
                        '<span class="sigma-match-occs-label">' +
                        escapeHtml(i18nFmt('sigmaMatchShowLogs', { n: n })) +
                        '</span>' +
                        '<span class="sigma-match-occs-actions">' +
                        '<button type="button" class="sigma-match-occs-btn" data-sigma-expand="1">' +
                        escapeHtml(pack.sigmaMatchExpandAll || 'Expand all') +
                        '</button>' +
                        '<button type="button" class="sigma-match-occs-btn" data-sigma-collapse="1">' +
                        escapeHtml(pack.sigmaMatchCollapseAll || 'Collapse all') +
                        '</button></span></div>' +
                        '<div class="sigma-match-occ-list">' +
                        occHtml +
                        '</div></div>';
                }

                var contextBits = [];
                if (span) {
                    contextBits.push(
                        '<span class="sigma-match-context-item"><span class="sigma-match-context-k">' +
                            escapeHtml(pack.sigmaMatchWhen || 'When') +
                            '</span> ' +
                            escapeHtml(truncate(span, 96)) +
                            '</span>'
                    );
                }
                var whereSample = '';
                for (var wi = 0; wi < g.items.length; wi++) {
                    var ws = summarizeLog(extractLog(g.items[wi])).where;
                    if (ws) {
                        whereSample = ws;
                        break;
                    }
                }
                if (whereSample) {
                    contextBits.push(
                        '<span class="sigma-match-context-item"><span class="sigma-match-context-k">' +
                            escapeHtml(pack.sigmaMatchWhere || 'Where') +
                            '</span> ' +
                            escapeHtml(truncate(whereSample, 96)) +
                            '</span>'
                    );
                }

                return (
                    '<details class="sigma-match-card sigma-match-card--' +
                    lvlCls +
                    '" data-level="' +
                    lvlCls +
                    '" data-search="' +
                    blob +
                    '"><summary class="sigma-match-head">' +
                    '<span class="sigma-level-badge sigma-level-badge--' +
                    lvlCls +
                    '">' +
                    level +
                    '</span><div class="sigma-match-head-text"><div class="sigma-match-title">' +
                    title +
                    '</div><div class="sigma-match-meta"><span class="sigma-match-id" title="Rule ID">' +
                    id +
                    '</span><span class="sigma-match-count">' +
                    countLabel +
                    '</span></div>' +
                    (contextBits.length
                        ? '<div class="sigma-match-context">' + contextBits.join('') + '</div>'
                        : '') +
                    '</div></summary><div class="sigma-match-body">' +
                    bodyHtml +
                    '</div></details>'
                );
            })
            .join('');

        return (
            '<div class="sigma-matches-root">' +
            renderToolbarHtml(escapeHtml, pack, levelCounts) +
            '<div class="sigma-matches-list">' +
            cards +
            '</div></div>'
        );
    }

    function levelBreakdownChipsHtml(matches, escapeHtml, i18nFmt) {
        var counts = { critical: 0, high: 0, medium: 0, low: 0 };
        (matches || []).forEach(function (raw) {
            var m = mapPlainTop(raw) || raw;
            var cls = levelClass(m.level);
            if (counts[cls] != null) counts[cls] += 1;
        });
        return LEVELS.filter(function (lvl) {
            return counts[lvl] > 0;
        })
            .map(function (lvl) {
                return (
                    '<span class="sigma-summary-chip sigma-summary-chip--' +
                    lvl +
                    '">' +
                    escapeHtml(i18nFmt('sigmaChipLevel', { level: lvl, n: counts[lvl] })) +
                    '</span>'
                );
            })
            .join('');
    }

    function wireMatchesContainer(root, opts) {
        if (!root) return;
        opts = opts || {};
        var pack = opts.i18nPack || {};
        var wrap = root.querySelector('.sigma-matches-root') || root;
        var search = wrap.querySelector('.sigma-matches-search');
        var levelBar = wrap.querySelector('.sigma-matches-levels');
        var list = wrap.querySelector('.sigma-matches-list') || wrap;
        var empty = wrap.querySelector('.sigma-matches-filter-empty');
        var activeLevel = '';
        var query = '';

        function applyFilter() {
            var cards = list.querySelectorAll('.sigma-match-card');
            var shown = 0;
            cards.forEach(function (card) {
                var lvl = card.getAttribute('data-level') || '';
                var blob = card.getAttribute('data-search') || '';
                var okLevel = !activeLevel || lvl === activeLevel;
                var okQuery = !query || blob.indexOf(query) !== -1;
                var show = okLevel && okQuery;
                card.hidden = !show;
                if (show) shown += 1;
            });
            if (empty) empty.hidden = shown > 0;
        }

        if (search) {
            search.addEventListener('input', function () {
                query = String(search.value || '')
                    .trim()
                    .toLowerCase();
                applyFilter();
            });
        }
        if (levelBar) {
            levelBar.addEventListener('click', function (ev) {
                var btn = ev.target.closest('.sigma-matches-level');
                if (!btn || !levelBar.contains(btn)) return;
                activeLevel = btn.getAttribute('data-level') || '';
                levelBar.querySelectorAll('.sigma-matches-level').forEach(function (b) {
                    b.classList.toggle('is-active', b === btn);
                });
                applyFilter();
            });
        }

        wrap.addEventListener('click', function (ev) {
            var expandRulesBtn = ev.target.closest('[data-sigma-expand-rules]');
            var collapseRulesBtn = ev.target.closest('[data-sigma-collapse-rules]');
            var expandBtn = ev.target.closest('[data-sigma-expand]');
            var collapseBtn = ev.target.closest('[data-sigma-collapse]');
            var copyBtn = ev.target.closest('[data-sigma-copy]');

            if (expandRulesBtn || collapseRulesBtn) {
                ev.preventDefault();
                ev.stopPropagation();
                var openRules = !!expandRulesBtn;
                list.querySelectorAll('details.sigma-match-card').forEach(function (card) {
                    if (card.hidden) return;
                    card.open = openRules;
                    if (!openRules) {
                        card.querySelectorAll('details.sigma-occ, details.sigma-occ-raw').forEach(function (d) {
                            d.open = false;
                        });
                    }
                });
                return;
            }

            if (expandBtn || collapseBtn) {
                ev.preventDefault();
                ev.stopPropagation();
                var host = (expandBtn || collapseBtn).closest('.sigma-match-occs');
                if (!host) return;
                var card = host.closest('details.sigma-match-card');
                if (card) card.open = true;
                host.querySelectorAll('details.sigma-occ').forEach(function (d) {
                    d.open = !!expandBtn;
                });
                return;
            }

            if (!copyBtn) return;
            ev.preventDefault();
            ev.stopPropagation();
            var encoded = copyBtn.getAttribute('data-copy') || '';
            var text = '';
            try {
                text = encoded ? decodeURIComponent(encoded) : '';
            } catch (e) {
                text = '';
            }
            if (!text || !navigator.clipboard || !navigator.clipboard.writeText) return;
            navigator.clipboard.writeText(text).then(
                function () {
                    var prev = copyBtn.textContent;
                    copyBtn.textContent = pack.sigmaMatchCopied || 'Copied';
                    copyBtn.classList.add('is-copied');
                    setTimeout(function () {
                        copyBtn.textContent = prev;
                        copyBtn.classList.remove('is-copied');
                    }, 1400);
                },
                function () {}
            );
        });
    }

    global.SigmaMatchUI = {
        LEVEL_ORDER: LEVEL_ORDER,
        levelClass: levelClass,
        mapPlainTop: mapPlainTop,
        extractLog: extractLog,
        groupMatches: groupMatches,
        renderGroupedHtml: renderGroupedHtml,
        renderLogBodyHtml: renderLogBodyHtml,
        summarizeLog: summarizeLog,
        wireMatchesContainer: wireMatchesContainer,
        levelBreakdownChipsHtml: levelBreakdownChipsHtml,
    };
})(typeof window !== 'undefined' ? window : globalThis);

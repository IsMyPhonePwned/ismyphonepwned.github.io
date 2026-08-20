/** Sigma rules fetch + editable session UI for iphone.html (shared patterns with android.html). */
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
        if (window.SigmaRulesEditor && window.SigmaRulesEditor.parseMeta) {
            return window.SigmaRulesEditor.parseMeta(yamlText);
        }
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
                    content: r.success ? r.text || '' : null,
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

    function groupSigmaMatches(rawMatches) {
        return window.SigmaMatchUI.groupMatches(rawMatches);
    }

    function renderSigmaMatchesGroupedHtml(rawMatches) {
        return window.SigmaMatchUI.renderGroupedHtml(rawMatches, {
            escapeHtml: escapeHtml,
            i18nFmt: i18nFmt,
            i18nPack: i18nPack(),
        });
    }

    function wireSigmaMatchesContainer(root) {
        if (!root || !window.SigmaMatchUI || !window.SigmaMatchUI.wireMatchesContainer) return;
        window.SigmaMatchUI.wireMatchesContainer(root, { i18nPack: i18nPack() });
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
            if (window.SigmaMatchUI && window.SigmaMatchUI.levelBreakdownChipsHtml) {
                chips.push(window.SigmaMatchUI.levelBreakdownChipsHtml(matches, escapeHtml, i18nFmt));
            }
        } else {
            chips.push(
                '<span class="sigma-summary-chip sigma-summary-chip--clean">' +
                    escapeHtml(pack.sigmaChipClean || 'No matches') +
                    '</span>'
            );
        }
        bar.innerHTML = chips.join('');
    }

    function canRescanSysdiagnose() {
        return !!(window.currentSysdiagnoseBytes && window.currentSysdiagnoseBytes.byteLength);
    }

    function renderIphoneSigmaRulesEditor(data) {
        var sigmaEl = document.getElementById('iphone-sigma-rules-container');
        if (!sigmaEl) return;
        var pack = i18nPack();
        var info = asWasmArray(data && data.sigma_rules_info);
        if (!window.SigmaRulesEditor) {
            sigmaEl.innerHTML =
                '<p class="detection-empty">' + escapeHtml(pack.sigmaNoRules || 'No rules loaded.') + '</p>';
            return;
        }
        window.SigmaRulesEditor.setSession(info);
        window.SigmaRulesEditor.renderInto(sigmaEl, {
            i18nPack: pack,
            canRescan: canRescanSysdiagnose(),
            blankRuleYaml: [
                'title: Custom rule',
                'id: custom-rule',
                'status: experimental',
                'description: |',
                '  Describe what this rule detects.',
                'logsource:',
                '  product: ios',
                'detection:',
                '  selection:',
                '    # field: value',
                '  condition: selection',
                'level: medium',
                '',
            ].join('\n'),
            onRescan: function () {
                if (typeof window.rescanSysdiagnoseWithCurrentRules === 'function') {
                    window.rescanSysdiagnoseWithCurrentRules();
                }
            },
            onReset: function () {
                resetIphoneSigmaRules();
            },
        });
    }

    async function resetIphoneSigmaRules() {
        var pack = i18nPack();
        var fresh = await fetchSigmaRules();
        if (window.SigmaRulesEditor) {
            window.SigmaRulesEditor.setSession(fresh.rulesInfo || []);
            if (window.currentResults) {
                window.currentResults.sigma_rules_info = window.SigmaRulesEditor.getPack().rulesInfo;
            }
            renderIphoneSigmaRulesEditor({
                sigma_rules_info: window.SigmaRulesEditor.getPack().rulesInfo,
            });
        }
        updateSigmaSummaryBar(
            window.currentResults || {
                sigma_rules_info: fresh.rulesInfo || [],
                sigma_matches: [],
            }
        );
        if (typeof window.showStatus === 'function') {
            window.showStatus(pack.sigmaResetDone || 'Bundled rules restored. Click Rescan to re-run analysis.', 'info');
        }
    }

    var sigmaDetailsData = null;
    var sigmaRulesBuilt = false;
    var sigmaMatchesBuilt = false;

    function ensureSysdiagnoseSigmaDetails() {
        if (!sigmaDetailsData) return;
        if (!sigmaRulesBuilt) {
            renderIphoneSigmaRulesEditor(sigmaDetailsData);
            sigmaRulesBuilt = true;
        }
        if (!sigmaMatchesBuilt) {
            var matchesEl = document.getElementById('iphone-sigma-matches-container');
            if (matchesEl) {
                matchesEl.innerHTML = renderSigmaMatchesGroupedHtml(asWasmArray(sigmaDetailsData.sigma_matches));
                wireSigmaMatchesContainer(matchesEl);
                sigmaMatchesBuilt = true;
            }
        }
    }

    function renderSysdiagnoseSigmaUI(data, opts) {
        opts = opts || {};
        data = data || {};
        sigmaDetailsData = data;
        sigmaRulesBuilt = false;
        sigmaMatchesBuilt = false;
        var section = document.getElementById('iphone-detection-section');
        if (!section) return;
        section.style.display = 'block';
        updateSigmaSummaryBar(data);

        var pack = i18nPack();
        var sigmaEl = document.getElementById('iphone-sigma-rules-container');
        var matchesEl = document.getElementById('iphone-sigma-matches-container');
        // Always show the editable rules session; optionally defer matches.
        if (sigmaEl) {
            renderIphoneSigmaRulesEditor(data);
            sigmaRulesBuilt = true;
        }
        var hint = '<p class="detection-empty">' + escapeHtml(pack.sigmaExpandHint || 'Expand to load details.') + '</p>';
        if (opts.deferDetails) {
            if (matchesEl) matchesEl.innerHTML = hint;
            return;
        }
        if (matchesEl) {
            matchesEl.innerHTML = renderSigmaMatchesGroupedHtml(asWasmArray(data.sigma_matches));
            wireSigmaMatchesContainer(matchesEl);
            sigmaMatchesBuilt = true;
        }
    }

    function hideSysdiagnoseSigmaUI() {
        var section = document.getElementById('iphone-detection-section');
        if (section) section.style.display = 'none';
        if (window.SigmaRulesEditor) window.SigmaRulesEditor.clearSession();
        sigmaDetailsData = null;
        sigmaRulesBuilt = false;
        sigmaMatchesBuilt = false;
    }

    window.fetchSigmaRules = fetchSigmaRules;
    window.renderSysdiagnoseSigmaUI = renderSysdiagnoseSigmaUI;
    window.ensureIphoneSigmaDetails = ensureSysdiagnoseSigmaDetails;
    window.hideSysdiagnoseSigmaUI = hideSysdiagnoseSigmaUI;
    window.renderIphoneSigmaRulesEditor = renderIphoneSigmaRulesEditor;
    window.resetIphoneSigmaRules = resetIphoneSigmaRules;
})();

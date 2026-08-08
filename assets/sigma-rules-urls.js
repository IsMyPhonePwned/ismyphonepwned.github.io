/**
 * Sigma rule files loaded by android.html, iphone.html, and bugreport-status.html.
 * Served from /rules/ — grouped by category (Amnesty IoCs, Android bugreport/CVE, iOS, spyware, MVT).
 */
window.SIGMA_RULE_URLS = [
    // Amnesty Tech investigations (sigma-zero YAML)
    '/rules/amnesty/2018_08_01_nso.yml',
    '/rules/amnesty/2018_12_19_best_practice.yml',
    '/rules/amnesty/2019_03_06_egypt_oauth.yml',
    '/rules/amnesty/2019_08_16_evolving_phishing.yml',
    '/rules/amnesty/2019_10_10_nso_morocco.yml',
    '/rules/amnesty/2020_03_12_uzbekistan.yml',
    '/rules/amnesty/2020_06_15_india.yml',
    '/rules/amnesty/2020_09_25_finfisher.yml',
    '/rules/amnesty/2021_02_24_vietnam.yml',
    '/rules/amnesty/2021_05_28_qatar.yml',
    '/rules/amnesty/2021_07_18_nso.yml',
    '/rules/amnesty/2021_10_07_donot.yml',
    '/rules/amnesty/2021_12_16_cytrox.yml',
    '/rules/amnesty/2023_03_29_android_campaign.yml',
    '/rules/amnesty/2024_05_02_wintego_helios.yml',
    '/rules/amnesty/2024_12_16_serbia_novispy.yml',
    // Spyware / vendor-specific
    '/rules/spyware/cellebrite.yml',
    '/rules/spyware/novispy.yml',
    '/rules/spyware/spyrtacus.yml',
    // MVT indicator packs
    '/rules/mvt/2026_04_09_sio_spyrtacus.yml',
    // Android bugreport hunts
    '/rules/android/bugreport_anr.yml',
    '/rules/android/bugreport_native_crash.yml',
    '/rules/android/sideload_package_install.yml',
    '/rules/android/apk_downgrade_battery_daily.yml',
    // Android CVE / exploit signatures
    '/rules/android/CVE/CVE-2025-21055.yaml',
    '/rules/android/CVE/CVE-2025-27363.yml',
    '/rules/android/CVE/CVE-2025-27363-bigpretzel.yml',
    '/rules/android/CVE/CVE-2025-27363-messaging-freetype.yml',
    '/rules/android/CVE/CVE-2025-27363-eol-android.yml',
    '/rules/android/CVE/CVE-2025-27363-load-truetype-glyph.yml',
    // iOS DarkSword (sysdiagnose / logarchive / filesystem)
    '/rules/ios/darksword/darksword-network-iocs.yml',
    '/rules/ios/darksword/darksword-implant-strings.yml',
    '/rules/ios/darksword/darksword-ghostblade-filesystem.yml',
    '/rules/ios/darksword/darksword-ghostblade-sample-hash.yml',
    '/rules/ios/darksword/darksword-unified-log-tags.yml',
    '/rules/ios/darksword/darksword-crash-cluster.yml',
    '/rules/ios/darksword/darksword-exploit-stage-filenames.yml',
    '/rules/ios/darksword/darksword-ciolino-exploit-modules.yml',
    '/rules/ios/darksword/darksword-ciolino-behavioral.yml',
    '/rules/ios/darksword/darksword-ciolino-exfil-ports.yml'
];

/**
 * Lightweight Sigma/YAML syntax highlighting → safe HTML (escaped text + spans).
 * Used by the Rules “Show rule content” panels on Android and iPhone.
 */
window.highlightSigmaYamlHtml = function (src) {
    function esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
    function span(cls, text) {
        return '<span class="yaml-' + cls + '">' + esc(text) + '</span>';
    }
    function highlightValue(raw) {
        if (raw === '') return '';
        if (/^(true|false|null|yes|no|on|off)$/i.test(raw)) return span('bool', raw);
        if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) return span('number', raw);
        var m = raw.match(/^([&*][A-Za-z0-9_-]+)(.*)$/);
        if (m) return span('anchor', m[1]) + highlightValue(m[2]);
        if (/^['"]/.test(raw)) return span('string', raw);
        if (/^\[/.test(raw) || /^\{/.test(raw)) return span('string', raw);
        return span('string', raw);
    }

    var text = String(src == null ? '' : src);
    var lines = text.split('\n');
    var out = [];

    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var indent = line.match(/^[ \t]*/)[0];
        var rest = line.slice(indent.length);

        if (!rest) {
            out.push('');
            continue;
        }
        if (rest.charAt(0) === '#') {
            out.push(esc(indent) + span('comment', rest));
            continue;
        }
        if (rest === '---' || rest === '...' || rest.indexOf('--- ') === 0) {
            out.push(esc(indent) + span('doc', rest));
            continue;
        }

        var dash = '';
        if (rest.charAt(0) === '-' && (rest.length === 1 || /[ \t]/.test(rest.charAt(1)))) {
            dash = '-';
            rest = rest.slice(1).replace(/^[ \t]+/, '');
            if (!rest) {
                out.push(esc(indent) + span('punct', dash));
                continue;
            }
            if (rest.indexOf(':') < 0 || /^['"]/.test(rest)) {
                out.push(esc(indent) + span('punct', dash) + ' ' + highlightValue(rest));
                continue;
            }
        }

        var keyMatch = rest.match(/^([^:#\n]+?)([ \t]*:)([ \t]*)(.*)$/);
        if (keyMatch) {
            var key = keyMatch[1];
            var colon = keyMatch[2];
            var gap = keyMatch[3];
            var val = keyMatch[4];
            var row =
                esc(indent) +
                (dash ? span('punct', dash) + ' ' : '') +
                span('key', key) +
                span('punct', colon);
            if (val) {
                if (val.charAt(0) === '#') {
                    row += esc(gap) + span('comment', val);
                } else if (val.charAt(0) === '|' || val.charAt(0) === '>') {
                    row += esc(gap) + span('punct', val);
                } else {
                    var hash = val.indexOf(' #');
                    if (hash >= 0) {
                        row +=
                            esc(gap) +
                            highlightValue(val.slice(0, hash)) +
                            span('comment', val.slice(hash));
                    } else {
                        row += esc(gap) + highlightValue(val);
                    }
                }
            }
            out.push(row);
            continue;
        }

        out.push(
            esc(indent) + (dash ? span('punct', dash) + (rest ? ' ' : '') : '') + highlightValue(rest)
        );
    }

    return out.join('\n');
};

/**
 * Sigma rule files loaded by android.html and bugreport-status.html.
 * Served from /rules/ — grouped by category (Amnesty IoCs, Android bugreport, CVE, iOS, spyware).
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
    // Android bugreport hunts
    '/rules/android/bugreport_anr.yml',
    '/rules/android/bugreport_native_crash.yml',
    // CVE / exploit signatures
    '/rules/CVE/CVE-2025-21055.yaml',
    '/rules/CVE/CVE-2025-27363.yml',
    '/rules/CVE/CVE-2025-27363-bigpretzel.yml',
    '/rules/CVE/CVE-2025-27363-messaging-freetype.yml',
    '/rules/CVE/CVE-2025-27363-eol-android.yml',
    '/rules/CVE/CVE-2025-27363-load-truetype-glyph.yml',
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

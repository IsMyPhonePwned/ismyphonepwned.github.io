# Sigma rules

Sigma-zero YAML rules evaluated in the browser against Android bugreport / iOS sysdiagnose parser output (`bugreport-extractor-library` / `sysdiagnose-extractor-library` / `sigma-zero`).

## Credits

**Amnesty International Tech Security Lab / [AmnestyTech investigations](https://github.com/AmnestyTech/investigations)** authored the investigation IoC packs under `amnesty/` and are credited on complementary Predator / Cytrox and other spyware rules adapted from [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators).

Additional packs credit Osservatorio Nessuno, iVerify, Mythos Sentinel, ESET, Cyble, Zimperium, and Recorded Future where those publications are the primary source.

## Layout

| Directory | Contents |
|-----------|----------|
| `amnesty/` | Amnesty Tech investigation IoC packs (NSO, FinFisher, Donot, Cytrox/Predator, NoviSpy, …) |
| `android/` | Bugreport hunts — ANR, native tombstone, sideload installer, APK downgrade |
| `android/CVE/` | Android CVE exploit signatures (FreeType 2025-27363, Quram 2025-21055, …) |
| `ios/darksword/` | DarkSword / Coruna iOS campaign (network, logs, filesystem, crash cluster) |
| `spyware/` | Vendor spyware without an MVT pack (Cellebrite, NoviSpy) |
| `mvt/` | MVT indicator packs (Spyrtacus, Morpheus, BTMOB, Assistenza Clienti, Coruna/DarkSword, Predator RF return) — single source; do not duplicate under `spyware/` |

## Loading

`assets/sigma-rules-urls.js` lists every file fetched by `android.html` / `iphone.html` and concatenated with `---` before WASM analysis.

## Upstream

- Amnesty packs: [AmnestyTech/investigations](https://github.com/AmnestyTech/investigations)
- MVT packs: [mvt-project/mvt-indicators](https://github.com/mvt-project/mvt-indicators) (issues #44, #46, #48; PRs #16, #56, #57 and merged Morpheus/BTMOB/Spyrtacus collections)
- New hunts (sideload, APK downgrade) are adapted from [mobipwn](https://github.com/IsMyPhonePwned/) `examples/mobipwn-queries/rules/` (mPL → sigma-zero)

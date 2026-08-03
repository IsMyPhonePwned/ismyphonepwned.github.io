# Sigma rules

Sigma-zero YAML rules evaluated in the browser against Android bugreport / iOS sysdiagnose parser output (`bugreport-extractor-library` / `sysdiagnose-extractor-library` / `sigma-zero`).

## Layout

| Directory | Contents |
|-----------|----------|
| `amnesty/` | Amnesty Tech investigation IoC packs (NSO, FinFisher, Donot, Cytrox, …) |
| `android/` | Bugreport hunts — ANR, native tombstone, sideload installer, APK downgrade |
| `android/CVE/` | Android CVE exploit signatures (FreeType 2025-27363, Quram 2025-21055, …) |
| `ios/darksword/` | DarkSword iOS campaign (network, logs, filesystem, crash cluster) |
| `spyware/` | Vendor spyware indicators (Cellebrite, NoviSpy, Spyrtacus) |
| `mvt/` | MVT indicator packs (Spyrtacus / SIO 2026-04-09) |

## Loading

`assets/sigma-rules-urls.js` lists every file fetched by `android.html` / `iphone.html` and concatenated with `---` before WASM analysis.

## Upstream

New hunts (Spyrtacus, sideload, APK downgrade) are adapted from [mobipwn](https://github.com/IsMyPhonePwned/) `examples/mobipwn-queries/rules/` (mPL → sigma-zero). Amnesty / DarkSword packs on this site remain the source of truth for IoC fullness.

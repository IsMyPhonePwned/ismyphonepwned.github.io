# Sigma rules

Sigma-zero YAML rules evaluated in the browser against Android bugreport parser output (`bugreport-extractor-library` / `sigma-zero`).

## Layout

| Directory | Contents |
|-----------|----------|
| `amnesty/` | Amnesty Tech investigation IoC packs (NSO, FinFisher, Donot, Cytrox, …) |
| `android/` | Bugreport hunts — ANR, native tombstone, sideloaded packages |
| `CVE/` | CVE exploit signatures (FreeType 2025-27363, Quram 2025-21055, …) |
| `ios/darksword/` | DarkSword iOS campaign (network, logs, filesystem, crash cluster) |
| `spyware/` | Vendor spyware indicators (Cellebrite, NoviSpy) |
| `test.yml` | Smoke-test rule (package name match) |

## Loading

`assets/sigma-rules-urls.js` lists every file fetched by `android.html` and concatenated with `---` before WASM analysis.

Many rules under `android/`, `CVE/`, and `ios/` were adapted from [mobipwn](https://github.com/IsMyPhonePwned/mobipwn) `examples/mobipwn-queries/rules/` (mPL → Sigma conversion).

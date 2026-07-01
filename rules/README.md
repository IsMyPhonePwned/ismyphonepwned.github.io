# Sigma rules

Sigma-zero YAML rules evaluated in the browser against Android bugreport parser output (`bugreport-extractor-library` / `sigma-zero`).

## Layout

| Directory | Contents |
|-----------|----------|
| `amnesty/` | Amnesty Tech investigation IoC packs (NSO, FinFisher, Donot, Cytrox, …) |
| `android/` | Bugreport hunts — ANR, native tombstone |
| `CVE/` | CVE exploit signatures (FreeType 2025-27363, Quram 2025-21055, …) |
| `ios/darksword/` | DarkSword iOS campaign (network, logs, filesystem, crash cluster) |
| `spyware/` | Vendor spyware indicators (Cellebrite, NoviSpy) |

## Loading

`assets/sigma-rules-urls.js` lists every file fetched by `android.html` and concatenated with `---` before WASM analysis.

# Signatures database — format and policy

`config/signatures.json` holds the detection database. The **list of covered
anti-cheats is fixed** (ACE, EA Javelin, EAC, BE, HoYoProtect); this document
only governs the *quality* of entries for those five.

## Official display names

| Short label (README) | `name` in JSON |
|---|---|
| ACE / AntiCheatExpert | `ACE (AnticheatExpert)` |
| EA Javelin / EA Anti-Cheat | `EA Javelin` |
| Easy Anti-Cheat | `EAC (EasyAntiCheat)` |
| BattlEye | `BE (BattlEye)` |
| HoYoProtect | `HoYoProtect` |

## Accepted shapes

Historical bare list, or the documented wrapper (preferred for traceability):

```json
{
  "schema": 1,
  "updated": "2026-10-08",
  "entries": [ { "name": "...", "...": "..." } ]
}
```

`--validate-config` accepts both shapes and rejects unknown `schema` values.

## Field reference (one example each)

- `services`: SCM service names — `"EasyAntiCheat_EOS"`, `"BEService"`.
- `processes`: executable names — `"EasyAntiCheat.exe"`, `"BEService_x64.exe"`.
- `drivers`: kernel driver names — `"BEDaisy.sys"`, `"mhyprot2.sys"`.
- `folders`: relative install locations — `"EasyAntiCheat"`, `"Tencent\\ACE"`.
- `registry`: `[hive, subkey]` pairs — `["HKEY_LOCAL_MACHINE", "SYSTEM\\CurrentControlSet\\Services\\BEService"]`.
- `companies`: `CompanyName` version-resource values — `"BattlEye Innovations e.K."`. Empty when the vendor ships no usable company string (see `notes`).
- `products`: `ProductName` values or product aliases — `"Easy Anti-Cheat"`, `"mhyprot"`.
- `notes`: free text justifying short/ambiguous entries and empty `companies`.

## Short-signature policy

- Matching is **exact-name** (extension/case/argument tolerant, never
  substring): a 3-letter entry such as `"ACE"` only matches a component
  literally named `ACE`/`ACE.exe`, never `FACE`/`peace`.
- The service/process prefilter additionally requires whole-token matches for
  short entries, so short names cost no substring noise.
- Any entry shorter than 4 characters **must** carry a `notes` justification;
  `--validate-config` reports missing justifications as warnings.

## Known ambiguities (kept intentionally, corroborate before concluding)

- Bare `"EAC"` / `"EAC.sys"` are stored under **EA Javelin** (observed
  component names there) even though `EAC` commonly abbreviates
  EasyAntiCheat. A bare-`EAC` hit must be corroborated with a full
  `EAAntiCheat*`/`Javelin*` name.
- Bare `"ACE"` is the observed SCM service name of AntiCheatExpert;
  corroborate with another ACE artifact.

## Signer vs company

Kernel drivers are typically WHQL-signed by
`Microsoft Windows Hardware Compatibility Publisher`. A Microsoft signer
**neither clears nor accuses**: attribution uses `CompanyName`/`ProductName`
(first) and the signer subject (secondary hint only). Microsoft companies are
explicitly exempt from metadata matching.

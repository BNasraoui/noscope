# Provenance Draft: noscope-pmr

## Thread Message (for requirement jn73sxs5hdg2j862zpfyqgbz8h83vjbr)

Implemented NS-072: Provider contract versioning.

Provider TOML configs now require a top-level `contract_version` field (currently = 1).
The parser validates the version against the supported set (current + previous version
for backward compatibility). At version 1, only version 1 is accepted since there is
no version 0.

Implementation details:
- `CURRENT_CONTRACT_VERSION` constant (u32 = 1)
- `supported_contract_versions()` returns current and N-1 (when N > 1)
- `validate_contract_version()` rejects versions outside the supported set
- `UnsupportedContractVersion` error variant with actionable message
- `FileProviderConfig.contract_version` field (required, parsed from TOML)
- `ResolvedProvider.contract_version` field (Option<u32>, None for flags/env layers)
- Parser rejects: missing field, non-integer type, zero, negative, float, unsupported future versions

16 tests covering all NS-072 requirements plus edge cases from self-review
(float type, validate_contract_version(0) directly).

Rule NS-072 is fully resolved by this implementation.

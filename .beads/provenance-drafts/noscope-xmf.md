# Provenance Draft: noscope-xmf

## Thread Message (for requirement noscope-xmf)

Deduplicated `resolve_profile_mint_specs_and_providers` and
`resolve_profile_run_specs_and_providers` in `src/main.rs`. Both functions
were byte-for-byte identical — they loaded a profile from disk, iterated
over credentials, resolved providers, and built `CredentialSpec` + `ResolvedProvider`
maps. Replaced with a single `resolve_profile_specs_and_providers` function.

Both call sites (`cmd_run` via `resolve_run_specs_and_providers`, and `cmd_mint`)
now delegate to the shared helper. Net deletion of ~35 lines of production code.

Tests cover: single credential, default env_key generation, explicit env_key,
multi-credential with provider dedup, nonexistent provider error, missing profile
error, and structural guards ensuring the old functions no longer exist.

Discovered during noscope-3ez.8 self-review.

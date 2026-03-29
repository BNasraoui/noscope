# Provenance Draft: noscope-cg8.5

## Thread Message (for requirement noscope-cg8.5)
Implemented provider config consolidation by introducing a single shared command input model for flags/env (`ProviderCommandInput` with aliases), moving capability ownership into `provider` parsing (`ProviderCapabilities` on `FileProviderConfig`), and validating capability declarations during provider TOML parse. Added a typed precedence intermediate (`SelectedProviderConfigLayer` + `select_provider_config_layer`) so precedence selection is explicit before final resolution. Also deduplicated profile/provider path resolution via shared `config_path::named_config_toml_path`.

## New Artifacts (if any)
- type: resolution
  content: Provider capability declarations are now parsed and validated only through `parse_provider_toml`, and provider_exec capability parsing delegates to this owned flow.
- type: resolution
  content: Precedence selection is represented as a typed intermediate enum (`SelectedProviderConfigLayer`) before final `ResolvedProvider` construction.

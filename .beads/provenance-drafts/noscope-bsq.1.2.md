# Provenance Draft: noscope-bsq.1.2

## Thread Message (for requirement NS-007)

Correctness bug in Client::resolve_provider: the env var layer (middle
precedence in flags > env > file) was dead code. The method constructed
ProviderEnv::default() (all None) instead of reading NOSCOPE_MINT_CMD,
NOSCOPE_REFRESH_CMD, NOSCOPE_REVOKE_CMD from the process environment.

Fix: added provider_env_from_process() in provider.rs to centralize env
var names and reading logic. Client::resolve_provider now calls this
function (or uses an injected ProviderEnv from ClientOptions for
testability).

The provider_env_from_process() function filters empty strings — setting
NOSCOPE_MINT_CMD="" does not activate the env layer.

## New Artifacts (if any)
- type: resolution
  content: |
    noscope-bsq.1.2 resolved: NOSCOPE_* env overrides now wired in
    Client::resolve_provider. Precedence (flags > env > file) preserved
    and tested at facade level. 10 new tests added covering all three
    env vars, all precedence combinations, empty-env fallthrough, and
    explicit-empty-env edge case. Standalone function used instead of
    impl on type alias to prevent method leakage to ProviderFlags.

# Provenance Draft: noscope-cg8.4

## Thread Message (for requirement jn7e50xjb2j4gp6b5vpjz2qw8x83t1ax)

Implemented NS-077 (typed machine-readable public error taxonomy) via new
`error` module with `Error` and `ErrorKind` types.

Design decisions:
- ErrorKind is a closed enum (Usage, Config, Provider, Security, Profile,
  Internal) with Copy+Eq for efficient matching by machine consumers.
- Error struct uses composition over enum variants: single struct with
  optional provider_name, inner Vec<Error> for multi-error, and boxed
  source for chaining. This avoids a deeply nested enum tree.
- Multi-error via Error::multi(Vec<Error>) preserves individual error
  kinds and provider names without flattening into brittle strings.
- Exit code mapping delegates to existing NoscopeExitCode constants,
  preserving backward compatibility.
- From conversions from all 6 existing module error types enable seamless
  `?` usage at call sites.
- Display format: "{kind} error: {message}" for single errors,
  "provider '{name}' error: {message}" for provider errors,
  semicolon-separated for multi-errors.

Acceptance criteria verified:
1. Public API returns typed errors with actionable categories (44 tests).
2. Multi-error cases representable without string flattening (7 tests).
3. Exit-code mapping consistent with existing behavior (7 tests).

## New Artifacts (if any)
- type: resolution
  content: NS-077 implemented in src/error.rs with Error, ErrorKind types,
  From conversions from all module error types, multi-error support,
  and re-export from crate root.

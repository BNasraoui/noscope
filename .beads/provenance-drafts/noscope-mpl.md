# Provenance Draft: noscope-mpl
## Thread Message (for requirement jn764cw67wc4h6d9st0qpe903x83vbgz)
Implemented signal handling policy primitives in `src/signal_policy.rs` and rule-focused integration coverage in `tests/signal_handling_policy.rs`. Covered NS-003/011/014/026/027/028/029/066/067 with dedicated tests named per rule intent. Added TTL bounds enforcement (min 60s, max 12h default) and wired mint arg validation through the shared policy so mint mode rejects missing/too-short/too-long TTLs. Implemented signal forwarding decisions (TERM/HUP/INT forwarded, SIGPIPE ignored), double-signal escalation behavior, idempotent revocation classification (already-revoked/expired treated as success), revocation retry budget defaults (10s wall clock, 500ms base backoff, 3 retries), budget=0 disable path, and parallel multi-credential revocation with failure isolation and per-credential budget handling.
## New Artifacts (if any)
- type: rule
  content: none

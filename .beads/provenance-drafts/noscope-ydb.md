# Provenance Draft: noscope-ydb
## Thread Message (for requirement )
Implemented `revoke` CLI wiring end-to-end: added `--from-stdin` mode, made `--token-id`/`--provider` optional-but-required unless stdin mode, built `RevokeInput` from either flags or mint-envelope JSON on stdin, resolved provider config through `Client`, executed provider `revoke_cmd`, and reported a user-facing success line with provider/token_id context. Added dedicated tests covering parsing, input construction, command execution, conflict handling, and result messaging.

## New Artifacts (if any)
- type: rule
  content: `noscope revoke` must accept either (`--token-id` + `--provider`) or `--from-stdin`, and route both through a shared `RevokeInput` construction path before provider command execution.

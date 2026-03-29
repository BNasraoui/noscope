# Provenance Draft: noscope-5wl

## Thread Message (for requirement jn79an6qv3j60bq64c8mekwjkx83tprp)

Implemented standalone mint and revoke subcommands covering all 6 rules:

- NS-060: MintEnvelope struct with to_json() producing the 5-field JSON envelope (token, expires_at, token_id, provider, role). from_scoped_token() bridges the existing ScopedToken type. Serialization uses internal SerializableMintEnvelope to keep Serialize off the public API.

- NS-061: RevokeInput accepts --token-id+--provider via from_token_id_and_provider() or full mint JSON via from_mint_json(). Raw token values are deliberately discarded during JSON parsing (NS-012 compliance). validate_revoke_args() rejects both --token and --token=value forms while allowing --token-id.

- NS-062: validate_mint_args() enforces mandatory --ttl (non-zero), at least one provider, and non-empty role. Returns validated TTL on success.

- NS-063: format_mint_output() takes a complete slice of MintEnvelopes and produces a JSON array or empty string. Atomicity is structural — partial output is impossible because the function requires all results before producing any output.

- NS-064: to_json() intentionally outputs raw token (the exception). to_log_string() uses RedactedToken for stderr/log safety. Debug impl also redacts.

- NS-065: check_stdout_not_terminal(is_tty, force) returns MintError::TerminalDetected (exit 64) when stdout is a tty without --force. Error message mentions scrollback risk and --force override.

Security hardening from review: MintEnvelope implements Drop with Zeroize for the token field, Debug impl redacts the token, type is not Clone, validate_revoke_args catches --token=value combined form.

47 tests total (35 rule tests + 12 edge case tests from review).

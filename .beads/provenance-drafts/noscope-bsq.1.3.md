# Provenance Draft: noscope-bsq.1.3

## Thread Message (for requirement NS-069)

Tightened the config file permission check (NS-069) to reject group-writable
bits in addition to world-accessible bits. Previously `check_config_permissions`
only masked `0o007` (other/world); now it masks `0o020 | 0o007` — rejecting
any mode where the group-write bit or any world bit is set.

The policy is defined as the named constant `INSECURE_MODE_BITS` in provider.rs.
Both provider and profile config loading reuse this single check function.

Accepted modes: 0600, 0640, 0400, 0700, 0500, 0440, 0750.
Rejected modes: 0660, 0620, 0670, 0644, 0666, 0604, 0602, 0662.

Error messages updated to say "group-writable and world-accessible bits must be 0"
instead of just "world-accessible bits must be 0".

## New Artifacts (if any)
- type: resolution
  content: NS-069 permission policy tightened — INSECURE_MODE_BITS = 0o020 | 0o007 rejects group-write and world-access for secret-bearing config files. Applied consistently to both provider and profile config loading.

# noscope

noscope is a short-lived credential manager for agent subprocesses.

It mints credentials from provider commands, runs your child process with those
credentials in environment variables, and keeps token material out of process
arguments and default logs.

## Install

Build locally:

```bash
cargo build --release
./target/release/noscope --help
```

Install into your Cargo bin directory:

```bash
cargo install --path .
noscope --help
```

## Provider Config

Provider files live at:

- `$XDG_CONFIG_HOME/noscope/providers/<name>.toml`
- or `~/.config/noscope/providers/<name>.toml` when `XDG_CONFIG_HOME` is unset

Minimal provider example (`~/.config/noscope/providers/aws.toml`):

```toml
contract_version = 1

[commands]
mint = "/usr/local/bin/aws-mint --role {{role}} --ttl {{ttl}}"
```

Provider with revoke support:

```toml
contract_version = 1
supports_revoke = true

[commands]
mint = "/usr/local/bin/aws-mint --role {{role}} --ttl {{ttl}}"
revoke = "/usr/local/bin/aws-revoke"

[commands.env]
AWS_REGION = "us-east-1"
```

Notes:

- `contract_version = 1` is currently required.
- `[commands]` is required and must include `mint = "..."`.
- `revoke = "..."` is optional unless `supports_revoke = true`.

## First Run

For a full walk-through, see `docs/QUICKSTART.md`.

Quick command sequence:

```bash
# 1) Dry-run (no provider execution)
noscope dry-run --provider aws --role admin --ttl 3600

# 2) Mint (prints JSON envelope to stdout)
noscope mint --provider aws --role admin --ttl 3600 > mint.json

# 3) Revoke using the minted envelope
cat mint.json | noscope revoke --from-stdin

# 4) Run a child command with injected credentials
noscope run --provider aws --role admin --ttl 3600 -- env | grep AWS
```

## Safety Layers

noscope is built around three safety layers:

1. process-group termination
2. revoke-on-exit
3. TTL expiry

Current status:

- currently implemented: TTL expiry via required `expires_at` on scoped tokens
- currently implemented: explicit `revoke` workflow and run-mode signal handling
- planned: stronger end-to-end revoke-on-exit guarantees across all termination paths
- planned: further hardening and parity validation for process-group termination paths

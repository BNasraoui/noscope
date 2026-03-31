# QUICKSTART

This guide gets you from zero config to a working first run.

## 1) Install

```bash
cargo build --release
./target/release/noscope --help
```

Optional global install:

```bash
cargo install --path .
noscope --help
```

## 2) Configure a Provider

Create `~/.config/noscope/providers/aws.toml` (or use `$XDG_CONFIG_HOME`):

```toml
contract_version = 1
supports_revoke = true

[commands]
mint = "/usr/local/bin/aws-mint --role {{role}} --ttl {{ttl}}"
revoke = "/usr/local/bin/aws-revoke"

[commands.env]
AWS_REGION = "us-east-1"
```

Validate configuration without executing provider commands:

```bash
noscope validate --provider aws
```

## 3) First-Run Workflow

### A) Dry run

Shows the resolved configuration and rendered mint command without executing
anything.

```bash
noscope dry-run --provider aws --role admin --ttl 3600
```

### B) Mint

Prints a JSON envelope to stdout.

```bash
noscope mint --provider aws --role admin --ttl 3600 > mint.json
```

### C) Revoke

Use `--from-stdin` with mint output:

```bash
cat mint.json | noscope revoke --from-stdin
```

Or revoke directly with token metadata:

```bash
noscope revoke --token-id tok-aws-123 --provider aws
```

### D) Run

Mints credentials and executes your child process. Put child args after `--`.

```bash
noscope run --provider aws --role admin --ttl 3600 -- ./your-agent --task "daily-sync"
```

## 4) What Is Implemented vs Planned

Implemented now:

- TTL expiry is mandatory in token state.
- `revoke` command exists for explicit revocation.
- run-mode signal handling and revocation paths are present.

Planned hardening:

- stronger revoke-on-exit guarantees across all shutdown paths
- deeper process-group termination hardening and parity coverage

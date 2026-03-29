# Statesman CLI: Auth + Config Reference

## Mental Model

- The CLI talks to multiple services:
  - Control plane (auth, API keys, project metadata)
  - Provenance (Convex) for `statesman provenance ...`
  - Broker for transaction/contract/rules endpoints

## Authentication

Interactive (recommended):

```bash
statesman auth login
statesman auth status
```

Non-interactive:

- Set `STATESMAN_API_KEY` (must be owned by a human seat).
- The CLI exchanges the API key for a human-scoped JWT before calling downstream services.

Useful commands:

```bash
statesman auth token
statesman auth logout
```

## Configuration

Set required endpoints:

```bash
statesman config set control_plane_url https://<control-plane>
statesman config set provenance_url https://<deployment>.convex.cloud
```

Inspect config:

```bash
statesman config get control_plane_url
statesman config get provenance_url
statesman config list
```

Advanced knobs:

- Config file: `--config <path>` or `STATESMAN_CONFIG=/path/to/config.toml`
- Profile: `--profile <name>` or `STATESMAN_PROFILE=<name>`
- Disable colors: `--no-color` or `STATESMAN_NO_COLOR=1`
- Debug logging: `STATESMAN_DEBUG=1`

## Output Formats

Global flags:

- `--output-format table|json|yaml|markdown`
- `--json` is shorthand for `--output-format json`

## Project Selection / Resolution

Many commands accept `--project-id`. If omitted, the CLI resolves a project ID in this order:

1) CLI `--project-id`
2) `STATESMAN_PROJECT_ID`
3) repo `statesman.toml` `[project].id` (created by `statesman init`)

Initialize a repo:

```bash
statesman init
statesman init --yes
```

Useful for CI/local scripting:

```bash
export STATESMAN_PROJECT_ID=<uuid>
export STATESMAN_PROVENANCE_URL=https://<deployment>.convex.cloud
export STATESMAN_CONTROL_PLANE_URL=https://<control-plane>
export STATESMAN_API_KEY=sk_...
```

## Troubleshooting

- "Auth required": run `statesman auth login` or set `STATESMAN_API_KEY`.
- "Provenance URL is not configured": set `STATESMAN_PROVENANCE_URL` or `statesman config set provenance_url ...`.
- 401 Unauthorized from downstream:
  - re-run `statesman auth login`
  - verify `control_plane_url` is correct
  - confirm the Convex deployment accepts the control-plane JWKS/issuer/audience

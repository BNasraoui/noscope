---
name: statesman-cli
description: Statesman CLI setup and operations: authentication (OAuth device flow or API key), config (control_plane_url, provenance_url, profiles), output formats, project selection (`statesman init`, STATESMAN_PROJECT_ID), broker URL override, and common troubleshooting for `statesman ...` commands. Use when a task involves running or configuring the `statesman` CLI. For Provenance artifact workflows, use `statesman-provenance`.
---

# Statesman CLI

## Overview

Use this skill when you need to run, configure, or troubleshoot `statesman` commands.

This skill is intentionally focused on CLI ergonomics (auth/config/output/project selection).
For Provenance artifact workflows (requirements/sources/resolutions/rules/threads/messages),
use the `statesman-provenance` skill.

## Quick Start

Configure endpoints:

```bash
statesman config set control_plane_url https://<control-plane>
statesman config set provenance_url https://<deployment>.convex.cloud
```

Authenticate:

```bash
statesman auth login
statesman auth status
```

Initialize a repo to persist project settings (creates `statesman.toml`):

```bash
statesman init --yes
```

## Common Patterns

- Output for tools/agents: `--json` or `--output-format json`
- Human-readable: `--output-format markdown`
- Disable colors: `--no-color` (or set `STATESMAN_NO_COLOR=1`)
- Override broker URL (temporary): `--broker-url ...` (or `STATESMAN_BROKER_URL=...`)

## References

- Read `references/cli_setup.md` for auth/config/output/project selection details.
- Read `references/projects.md` for per-project broker URL management.
- Deployment runbook (long-form): `docs/deployment/v0.1-railway-convex.md`

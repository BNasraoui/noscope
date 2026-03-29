---
name: statesman-provenance
description: Provenance knowledge graph workflows via the `statesman provenance ...` CLI. Use when working with Provenance artifacts (requirements, sources, resolutions, rules, edges, threads/messages), when answering traceability questions ("why does this rule exist?"), or when contributing durable analysis back into Provenance (thread/messages). For CLI auth/config/setup, use the `statesman-cli` skill.
---

# Statesman Provenance

## Overview

Read and write Provenance graph data (artifacts + discussions) via `statesman provenance ...`.

This skill is intentionally focused on Provenance usage. For authentication, config, and
general CLI ergonomics, use the `statesman-cli` skill.

## Quick Start

Prereqs:

- You are authenticated (`statesman auth login` or `STATESMAN_API_KEY`).
- Provenance URL is configured (`STATESMAN_PROVENANCE_URL` or `statesman config set provenance_url ...`).

If either is missing, follow the `statesman-cli` skill.

## Mental Model

- Provenance is a project-scoped knowledge graph.
- Core artifacts: `requirement`, `source`, `resolution`, `rule`.
- Threads/messages attach to any artifact; messages have a `role` (`user`, `assistant`, `system`).
- Ownership: every write is authenticated as a human seat; AI work should be marked via message `role=assistant` (author remains the owning human).

## Workflows

### Inspect a Requirement Graph (Canvas Scope)

Use when you need the local context around a requirement (children, linked artifacts, threads).

Commands:
```bash
statesman provenance graph <requirement_id> --output-format markdown
statesman provenance graph <requirement_id> --json
```

### Explain Rule Traceability

Use when you need to answer "why does this rule exist?" (rule -> resolutions -> requirements -> sources).

Commands:
```bash
statesman provenance traceability <rule_id> --output-format markdown
statesman provenance traceability <rule_id> --json
```

### Analyze Change Impact

Use when you need to answer "what would be affected if we change X?" or assess the blast radius of a planned change. The `impact` command walks the Provenance graph outward from a given node and reports every artifact that is transitively connected.

Commands:
```bash
# Analyze impact from a source document change
statesman provenance impact --node-type source <source_id> --json

# Analyze impact from a requirement change
statesman provenance impact --node-type requirement <requirement_id> --json

# Narrow to direct dependencies only (1 hop)
statesman provenance impact --node-type requirement <requirement_id> --max-hops 1 --json

# Skip cross-domain dependencies (depends_on, contradicts, spawns)
statesman provenance impact --node-type rule <rule_id> --cross-domain false --json

# Human-readable table output
statesman provenance impact --node-type source <source_id>

# Write impact report to file
statesman provenance impact --node-type source <source_id> --output-format markdown -o impact-report.md
```

Response shape (`--json`):

| Field | Description |
|---|---|
| `origin` | The starting node (`nodeId`, `nodeType`). |
| `impactSet` | Array of affected nodes. Each entry contains `nodeId`, `nodeType`, `hopDistance` (number of edges from the origin), and `direction` (upstream or downstream). |
| `summary.totalAffected` | Total number of nodes in `impactSet`. |
| `summary.byType` | Breakdown of affected nodes grouped by artifact type (e.g. `requirement`, `rule`). |
| `summary.byHop` | Breakdown of affected nodes grouped by hop distance. |
| `summary.maxHopReached` | Whether the walk was truncated at the `maxHops` limit. |
| `coverage.riskScore` | Heuristic risk score for the change (higher = wider blast radius). |
| `coverage.rulesWithGaps` | Rules reachable from the origin that have incomplete traceability (missing source or resolution links). |

Usage notes:

- Prefer `--json` when another agent/tool will consume the output.
- The `maxHops` default is 5. For large graphs, use `--max-hops 1` or `--max-hops 2` to narrow scope.
- Cross-domain dependencies (`depends_on`, `contradicts`, `spawns` edges between requirements) are followed by default. Use `--cross-domain false` to exclude them.

### Create Core Artifacts

Create a source:

```bash
statesman provenance sources create \
  --project-id <project_id> \
  --name "<name>" \
  --source-type policy \
  --url "https://..."
```

Create a requirement:

```bash
statesman provenance requirements create \
  --project-id <project_id> \
  --statement "<statement>" \
  --description "<optional>"
```

Link a requirement to a source (adds a reference + graph edge):

```bash
statesman provenance requirements source-ref add \
  --requirement-id <requirement_id> \
  --source-id <source_id> \
  --clause "<optional clause>"
```

Create a resolution:

```bash
statesman provenance resolutions create \
  --project-id <project_id> \
  --title "<title>" \
  --context "<context>" \
  --position "<position>" \
  --rationale "<rationale>" \
  --enforcement policy \
  --confidence 0.8 \
  --requirement-id <requirement_id>
```

Create a rule:

```bash
statesman provenance rules create \
  --project-id <project_id> \
  --rule-code "<code>" \
  --name "<name>" \
  --statement "<statement>" \
  --rule-type business \
  --severity medium \
  --modality obligation \
  --extraction-method provenance \
  --confidence 0.8 \
  --requirement-id <requirement_id> \
  --resolution-id <optional_resolution_id> \
  --source-id <source_id>
```

### Contribute Back (Thread Message)

Use when you need to leave a durable, attributable trail of analysis, decisions, or questions.

Commands:
```bash
statesman provenance thread post \
  --parent-type requirement \
  --parent-id <requirement_id> \
  "<message content>"

# Explicitly post as the human (rare)
statesman provenance thread post \
  --parent-type requirement \
  --parent-id <requirement_id> \
  --role user \
  "<message content>"
```

## Notes

- Prefer `--json` when another agent/tool will consume the output.
- If you hit `Unauthorized`, re-run `statesman auth login` or ensure `STATESMAN_API_KEY` is set.
- If you hit "Provenance URL is not configured", set `STATESMAN_PROVENANCE_URL`.
- Many commands accept `--project-id`; if omitted, the CLI resolves it from `STATESMAN_PROJECT_ID` or `statesman.toml`.

## References

- Read `references/provenance_cli.md` for deeper artifact/command reference + troubleshooting.

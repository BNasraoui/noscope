# Provenance CLI Reference (`statesman provenance ...`)

This is a command + concept cheat-sheet for Provenance workflows.

For CLI authentication/config/setup, use the `statesman-cli` skill.

## Core Concepts

Provenance is a project-scoped knowledge graph used to justify and explain enforcement:

- requirement: recursive unit of work (tree via `parentId`)
- source: reference material (policy, legislation, spec, incident, etc.)
- resolution: documented decision (draft -> review -> approved -> superseded)
- rule: enforceable output (often synced to broker; still stored in Provenance)
- edge: explicit relationship between graph nodes
- thread/message: durable discussion attached to any artifact

Messages have a `role`:

- user: human-authored content
- assistant: AI-authored content (still owned by a human seat)
- system: automated notifications

## Status Values (CLI enums)

- requirement status: `discovery`, `refinement`, `resolved`
- resolution status: `draft`, `review`, `approved`, `superseded`
- rule status: `draft`, `review`, `active`, `deprecated`, `archived`
- thread status: `active`, `resolved`, `archived`

## Ownership + Billing

- All writes must be attributable to a human identity (seat owner).
- When an AI performs work, record that via message `--role assistant` (default).

## Commands

Tip: add `--json` (or `--output-format json`) when another tool/agent will consume the output.

### Graph + Traceability

```bash
statesman provenance graph <requirement_id>
statesman provenance traceability <rule_id>
```

### Requirements

```bash
statesman provenance requirements create \
  --project-id <project_id> \
  --statement "<statement>" \
  --description "<optional>" \
  --parent-id <optional_parent_requirement_id>

statesman provenance requirements list --project-id <project_id>
statesman provenance requirements get <requirement_id>

statesman provenance requirements update <requirement_id> \
  --statement "<optional>" \
  --description "<optional>"

statesman provenance requirements status <requirement_id> --status refinement

statesman provenance requirements source-ref add \
  --requirement-id <requirement_id> \
  --source-id <source_id> \
  --clause "<optional clause>"

statesman provenance requirements source-ref remove \
  --requirement-id <requirement_id> \
  --source-id <source_id> \
  --clause "<optional clause>"
```

### Sources

```bash
statesman provenance sources create \
  --project-id <project_id> \
  --name "<name>" \
  --source-type policy \
  --reference "<optional>" \
  --url "https://..."

statesman provenance sources list --project-id <project_id> --limit 50
statesman provenance sources get <source_id>

statesman provenance sources update <source_id> \
  --name "<optional>" \
  --reference "<optional>" \
  --url "<optional>"

statesman provenance sources status <source_id>

statesman provenance sources supersede <existing_source_id> \
  --name "<name>" \
  --source-type policy \
  --url "https://..."
```

### Resolutions

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

statesman provenance resolutions list --project-id <project_id> --limit 50
statesman provenance resolutions get <resolution_id>

statesman provenance resolutions update <resolution_id> \
  --context "<optional>" \
  --position "<optional>" \
  --rationale "<optional>" \
  --confidence 0.9

statesman provenance resolutions status <resolution_id> --status review
statesman provenance resolutions approve <resolution_id>

statesman provenance resolutions supersede <existing_resolution_id> \
  --title "<title>" \
  --context "<context>" \
  --position "<position>" \
  --rationale "<rationale>" \
  --enforcement policy \
  --confidence 0.8
```

### Rules

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

statesman provenance rules get <rule_id>
statesman provenance rules get-by-code --project-id <project_id> <rule_code>
statesman provenance rules list --project-id <project_id> --limit 50

statesman provenance rules update <rule_id> \
  --statement "<optional>" \
  --severity high

statesman provenance rules status <rule_id> --status active
```

### Edges

```bash
statesman provenance edges create \
  --project-id <project_id> \
  --edge-type references \
  --from-node-type requirement \
  --from-node-id <id> \
  --to-node-type source \
  --to-node-id <id>

statesman provenance edges get <edge_id>

statesman provenance edges list --project-id <project_id> --from <node_id>
statesman provenance edges list --project-id <project_id> --to <node_id>
statesman provenance edges list --project-id <project_id> --node <node_id> --node <node_id>

statesman provenance edges remove <edge_id>
```

### Threads + Messages

Convenience: post to an artifact thread (creates an active thread if needed):

```bash
statesman provenance thread post \
  --parent-type requirement \
  --parent-id <requirement_id> \
  "Summarize what you found + next action + risks/unknowns"
```

Explicit thread operations:

```bash
statesman provenance threads create \
  --project-id <project_id> \
  --parent-type requirement \
  --parent-id <requirement_id>

statesman provenance threads list --project-id <project_id>
statesman provenance threads list --parent-type requirement --parent-id <requirement_id>
statesman provenance threads status <thread_id> --status resolved
```

Messages:

```bash
statesman provenance messages list --thread-id <thread_id>
statesman provenance messages send --thread-id <thread_id> "<content>"
```

## Troubleshooting

- "Project ID is not set": pass `--project-id`, set `STATESMAN_PROJECT_ID`, or run `statesman init` to create `statesman.toml` with `[project].id`.
- "Provenance URL is not configured": set `STATESMAN_PROVENANCE_URL` or `statesman config set provenance_url ...`.
- 401 Unauthorized:
  - run `statesman auth login` or set `STATESMAN_API_KEY`
  - confirm the Convex deployment accepts the control-plane JWKS/issuer/audience

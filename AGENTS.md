# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

<!-- BEGIN BEADS INTEGRATION -->
## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

### Why bd?

- Dependency-aware: Track blockers and relationships between issues
- Version-controlled: Built on Dolt with cell-level merge
- Agent-optimized: JSON output, ready work detection, discovered-from links
- Prevents duplicate tracking systems and confusion

### Quick Start

**Check for ready work:**

```bash
bd ready --json
```

**Create new issues:**

```bash
bd create "Issue title" --description="Detailed context" -t bug|feature|task -p 0-4 --json
bd create "Issue title" --description="What this issue is about" -p 1 --deps discovered-from:bd-123 --json
```

**Claim and update:**

```bash
bd update <id> --claim --json
bd update bd-42 --priority 1 --json
```

**Complete work:**

```bash
bd close bd-42 --reason "Completed" --json
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

### Workflow for AI Agents

1. **Check ready work**: `bd ready` shows unblocked issues
2. **Claim your task atomically**: `bd update <id> --claim`
3. **Work on it**: Implement, test, document
4. **Discover new work?** Create linked issue:
   - `bd create "Found bug" --description="Details about what was found" -p 1 --deps discovered-from:<parent-id>`
5. **Complete**: `bd close <id> --reason "Done"`

### Auto-Sync

bd automatically syncs with git:

- Exports to `.beads/issues.jsonl` after changes (5s debounce)
- Imports from JSONL when newer (e.g., after `git pull`)
- No manual export/import needed!

### Important Rules

- ✅ Use bd for ALL task tracking
- ✅ Always use `--json` flag for programmatic use
- ✅ Link discovered work with `discovered-from` dependencies
- ✅ Check `bd ready` before asking "what should I work on?"
- ❌ Do NOT create markdown TODO lists
- ❌ Do NOT use external issue trackers
- ❌ Do NOT duplicate tracking systems

For more details, see README.md and docs/QUICKSTART.md.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

<!-- END BEADS INTEGRATION -->

<!-- BEGIN PROVENANCE INTEGRATION v0.1.0 -->
# Provenance Knowledge Graph

> Run `statesman provenance prime` after context compaction or at the start of a new session.

## When to Use Provenance

Use Provenance whenever you are:

- **Researching** — Check what's already known before searching the web or codebase
- **Planning** — Inspect requirements, resolutions, and rules before proposing changes
- **Analyzing** — Trace why a rule exists, assess change impact, find coverage gaps
- **Reviewing** — Verify traceability chains are complete before approving changes
- **Deciding** — Record decisions as resolutions so future agents understand the "why"

## Core Commands

```bash
# Inspect the graph around a requirement (children, sources, resolutions, rules, threads)
statesman provenance graph <requirement_id> --json

# Trace why a rule exists (rule -> resolution -> requirement -> source)
statesman provenance traceability <rule_id> --json

# Post analysis/findings to an artifact's discussion thread
statesman provenance thread post --parent-type requirement --parent-id <id> "Your analysis here"

# List requirements for the current project
statesman provenance requirements list --json

# Assess blast radius of a change
statesman provenance impact --node-type source <node_id> --json
```

## Agent Protocol

Follow this workflow when working on tasks that touch business logic, rules, or requirements:

1. **Inspect existing state** — Run `statesman provenance graph` or `requirements list` to see what's already captured
2. **Use context** — Let existing requirements, resolutions, and rules inform your approach
3. **Contribute findings** — Post research, analysis, and decisions as thread messages
4. **Explain reasoning** — When creating or modifying artifacts, include rationale

## The `--reason` Convention

A `--reason` flag will be added to Provenance commands to build session trails automatically.
Until then, embed your reasoning directly in thread messages — this creates the same
traceability narrative:

```bash
# Good: include "why" in the message content itself
statesman provenance thread post --parent-type rule --parent-id <id> \
  "Investigating coverage gap for PROV-DATA-001 — found missing source link during auth refactor"
```

When `--reason` lands, it will attach structured context to every write operation.

## Rules

**Do:**
- Check Provenance BEFORE starting research (avoid rediscovering known context)
- Post findings as thread messages (durable, attributable, searchable)
- Link new rules to requirements and resolutions (complete traceability)
- Use `--json` when piping output to other tools or processing programmatically

**Don't:**
- Keep research findings only in local files (they vanish after the session)
- Create rules without traceability to requirements and sources
- Skip impact analysis before modifying source documents or requirements
- Duplicate information that already exists in the graph

## Skill Reference

Load the `statesman-provenance` skill for the full command reference, detailed workflows
(inspect, explain, analyze, create, contribute back), mental model, and troubleshooting.

```
Load skill: statesman-provenance
```

<!-- END PROVENANCE INTEGRATION v0.1.0 -->

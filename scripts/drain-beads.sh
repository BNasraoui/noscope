#!/usr/bin/env bash
# drain-beads.sh — Pick up beads one at a time, implement via TDD, Linus-review, commit.
# Loops until bd ready returns nothing.
#
# Usage:
#   ./scripts/drain-beads.sh              # process all ready beads
#   ./scripts/drain-beads.sh --dry-run    # show what would be processed, don't run
#   ./scripts/drain-beads.sh --max 3      # process at most 3 beads
#   ./scripts/drain-beads.sh --model anthropic/claude-sonnet-4-20250514  # override model

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${PROJECT_DIR}/.beads/session-logs"
STATESMAN_FALLBACK_DIR="${PROJECT_DIR}/.beads/provenance-drafts"
DRY_RUN=false
MAX_BEADS=0  # 0 = unlimited
MODEL=""
SKIP_EPICS=true

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)  DRY_RUN=true; shift ;;
    --max)      MAX_BEADS="$2"; shift 2 ;;
    --model)    MODEL="$2"; shift 2 ;;
    --include-epics) SKIP_EPICS=false; shift ;;
    -h|--help)
      echo "Usage: $0 [--dry-run] [--max N] [--model provider/model] [--include-epics]"
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
for cmd in bd opencode jq; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: $cmd not found in PATH" >&2
    exit 1
  fi
done

mkdir -p "$LOG_DIR" "$STATESMAN_FALLBACK_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log() { echo "[$(timestamp)] $*"; }

# Check if statesman provenance is reachable
statesman_available() {
  statesman provenance sources list --limit 1 --json &>/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Build the prompt for a single bead
# ---------------------------------------------------------------------------
build_prompt() {
  local bead_id="$1"
  local bead_json="$2"

  local title description rules prov_req
  title=$(echo "$bead_json" | jq -r '.title')
  description=$(echo "$bead_json" | jq -r '.description')
  rules=$(echo "$description" | grep -E '^- NS-' || true)
  prov_req=$(echo "$description" | grep -oP 'Provenance REQ: \K\S+' || true)

  local statesman_section
  if statesman_available; then
    statesman_section="
## Statesman Provenance

You have access to statesman. After implementation:
1. Post a thread message on the requirement summarizing what you implemented:
   statesman provenance thread post --parent-type requirement --parent-id ${prov_req} \"<summary>\"
2. If you discover a new rule, resolution, or requirement during implementation,
   create it via the statesman provenance CLI (see .agents/skills/statesman-provenance/SKILL.md).
"
  else
    statesman_section="
## Statesman Provenance (OFFLINE)

statesman is not reachable. For any provenance updates (new rules, resolutions,
thread messages), write them to: ${STATESMAN_FALLBACK_DIR}/${bead_id}.md
Use this format:
  # Provenance Draft: ${bead_id}
  ## Thread Message (for requirement ${prov_req})
  <your message>
  ## New Artifacts (if any)
  - type: rule/resolution/requirement
    content: ...
"
  fi

  cat <<PROMPT
You are implementing bead ${bead_id}: "${title}"

## Bead Details

${description}

## Your Workflow

You MUST follow this workflow exactly. Do not skip steps.

### Phase 1: Understand
1. Read the existing codebase: src/lib.rs and all modules in src/ to understand patterns.
2. Read .agents/skills/statesman-provenance/SKILL.md if you need provenance CLI reference.
3. Understand every rule listed in the bead description. Each rule is a hard requirement.

### Phase 2: TDD — Red
4. Create a new module (or extend existing) with ONLY tests. No production code yet.
5. Write tests for EVERY rule. Name tests after the rule (e.g., test for NS-042 named
   \`config_follows_xdg_base_directory\`). Each rule must have at least one test.
6. Run \`cargo test\` and verify ALL tests fail. If any test passes, it's testing
   existing behavior — rewrite it.

### Phase 3: TDD — Green
7. Write the MINIMAL production code to make all tests pass.
8. Run \`cargo test\` — all tests must pass.
9. Run \`cargo clippy\` — zero warnings.

### Phase 4: TDD — Refactor
10. Clean up: improve names, extract helpers, remove duplication.
11. Run \`cargo test && cargo clippy\` — still clean.

### Phase 5: Linus Torvalds Review
12. Review your own code AS IF you are Linus Torvalds reading it on LKML.
    Be brutal: check for API design mistakes, missing edge cases, naming problems,
    over-engineering, write-only data structures, missing trait impls, semantic lies
    in type names. Write the review to yourself.
13. Fix every legitimate issue from the review. Add tests for missing edge cases.
14. Run \`cargo test && cargo clippy\` again.

### Phase 6: Commit
15. Stage and commit with message format:
    feat: <short description> (<bead_id>)

    <body explaining what was implemented and which rules are covered>
16. Do NOT push.

${statesman_section}

## Rules

- Follow the test-driven-development skill STRICTLY. No production code before failing tests.
- Every NS-xxx rule in the bead MUST have at least one dedicated test.
- Match existing code patterns (see token.rs, security.rs, redaction.rs for style).
- Use \`cp -f\`, \`mv -f\`, \`rm -f\` for file operations (non-interactive shell).
- Do NOT run benchmarks.
- If you get stuck on a rule, create a bd issue: \`bd create "Blocked on NS-xxx" --deps discovered-from:${bead_id}\`

PROMPT
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
processed=0
failed=0
skipped=0

log "Starting bead drain in ${PROJECT_DIR}"
log "Dry run: ${DRY_RUN} | Max beads: ${MAX_BEADS:-unlimited} | Skip epics: ${SKIP_EPICS}"

# ---------------------------------------------------------------------------
# pick_next_bead: select highest-priority non-epic from a JSON array on stdin.
# Prints the bead JSON object or empty string.
# ---------------------------------------------------------------------------
pick_next_bead() {
  local json="$1"
  local skip_ids="$2"  # comma-separated ids to skip (for dry-run)
  for priority in 0 1 2 3 4; do
    local filter
    if [[ "$SKIP_EPICS" == "true" ]]; then
      filter=".priority == ${priority} and .issue_type != \"epic\""
    else
      filter=".priority == ${priority}"
    fi
    # Exclude already-seen ids
    if [[ -n "$skip_ids" ]]; then
      local id_filter
      id_filter=$(echo "$skip_ids" | tr ',' '\n' | sed 's/.*/"&"/' | paste -sd, -)
      filter="${filter} and ([.id] | inside([${id_filter}]) | not)"
    fi
    local candidate
    candidate=$(echo "$json" | jq -r "[.[] | select(${filter})] | first // empty")
    if [[ -n "$candidate" && "$candidate" != "null" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  echo ""
  return 1
}

seen_ids=""

while true; do
  # Check limit
  if [[ "$MAX_BEADS" -gt 0 && "$processed" -ge "$MAX_BEADS" ]]; then
    log "Reached max beads limit (${MAX_BEADS}). Stopping."
    break
  fi

  # Get ready beads
  ready_json=$(bd ready --json 2>/dev/null || echo "[]")
  bead_count=$(echo "$ready_json" | jq 'length')

  if [[ "$bead_count" -eq 0 ]]; then
    log "No more ready beads. Done."
    break
  fi

  # Pick next eligible bead (skipping already-seen in dry-run)
  bead_json=$(pick_next_bead "$ready_json" "$seen_ids" || true)

  if [[ -z "$bead_json" ]]; then
    log "No more eligible beads. Done."
    break
  fi

  bead_id=$(echo "$bead_json" | jq -r '.id')
  bead_title=$(echo "$bead_json" | jq -r '.title')
  bead_type=$(echo "$bead_json" | jq -r '.issue_type')
  bead_priority=$(echo "$bead_json" | jq -r '.priority')

  # Track seen ids so dry-run doesn't loop forever
  if [[ -n "$seen_ids" ]]; then
    seen_ids="${seen_ids},${bead_id}"
  else
    seen_ids="${bead_id}"
  fi

  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "Bead ${bead_id}: ${bead_title} [P${bead_priority}/${bead_type}]"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY RUN] Would process: ${bead_id}"
    processed=$((processed + 1))
    continue
  fi

  # Claim the bead
  if ! bd update "$bead_id" --claim --json &>/dev/null; then
    log "WARN: Failed to claim ${bead_id}, skipping"
    skipped=$((skipped + 1))
    continue
  fi
  log "Claimed ${bead_id}"

  # Build prompt
  prompt=$(build_prompt "$bead_id" "$bead_json")

  # Write prompt to log for debugging
  session_log="${LOG_DIR}/${bead_id}-$(date '+%Y%m%d-%H%M%S').log"
  echo "$prompt" > "${session_log}.prompt"

  # Run opencode
  log "Launching opencode for ${bead_id}..."

  model_flag=""
  if [[ -n "$MODEL" ]]; then
    model_flag="--model ${MODEL}"
  fi

  if opencode run \
    --dir "$PROJECT_DIR" \
    --title "bead: ${bead_id} — ${bead_title}" \
    ${model_flag} \
    "$prompt" \
    2>&1 | tee "$session_log"; then

    log "opencode completed for ${bead_id}"

    # Verify: did it actually commit?
    last_commit_msg=$(git -C "$PROJECT_DIR" log -1 --format='%s' 2>/dev/null || echo "")
    if echo "$last_commit_msg" | grep -q "$bead_id"; then
      log "Commit found for ${bead_id}: ${last_commit_msg}"

      # Close the bead if opencode didn't already
      bead_status=$(bd show "$bead_id" --json 2>/dev/null | jq -r '.[0].status // "unknown"')
      if [[ "$bead_status" != "closed" ]]; then
        bd close "$bead_id" --reason "Implemented by drain-beads.sh" --json &>/dev/null || true
        log "Closed ${bead_id}"
      fi
    else
      log "WARN: No commit found for ${bead_id}. Last commit: ${last_commit_msg}"
      failed=$((failed + 1))
    fi
  else
    log "ERROR: opencode failed for ${bead_id} (exit $?)"
    failed=$((failed + 1))

    # Unclaim on failure so it's available for retry
    bd update "$bead_id" --status open --json &>/dev/null || true
    log "Unclaimed ${bead_id} for retry"
  fi

  processed=$((processed + 1))

  # Sync beads after each iteration
  bd sync &>/dev/null || true

  log ""
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Drain complete: ${processed} processed, ${failed} failed, ${skipped} skipped"

remaining=$(bd ready --json 2>/dev/null | jq 'length' 2>/dev/null || echo "?")
log "Remaining ready beads: ${remaining}"
log "Session logs: ${LOG_DIR}/"

if [[ -n "$(ls -A "$STATESMAN_FALLBACK_DIR" 2>/dev/null)" ]]; then
  log "Provenance drafts pending upload: ${STATESMAN_FALLBACK_DIR}/"
fi

exit "$failed"

---
date: 2026-03-31T09:23:24+10:00
researcher: OpenCode
git_commit: d868f007f138a0a0fbc1b9d72540e0a54d7f590b
branch: main
repository: noscope
topic: "Security, performance, and style review for v1 readiness"
tags: [research, codebase, security, performance, style, rust]
status: complete
last_updated: 2026-03-31
last_updated_by: OpenCode
last_updated_note: "Added follow-up research for prioritized remediation roadmap"
---

# Research: Security, performance, and style review for v1 readiness

**Date**: 2026-03-31T09:23:24+10:00
**Researcher**: OpenCode
**Git Commit**: d868f007f138a0a0fbc1b9d72540e0a54d7f590b
**Branch**: main
**Repository**: noscope

## Research Question
The noscope project is effectively ready for v1, but coding style and engineering practices may need improvement. Review the codebase from security, performance, and style perspectives, and identify concrete improvement opportunities.

## Summary
The codebase is close to v1 quality and already has strong guardrails (permission checks, environment sandboxing, secret redaction model, process-group handling, and strict CI with fmt/clippy/tests/audit). The highest-value improvements are concentrated in a few cross-cutting areas:

1. **Security correctness gaps between contracts and wiring** (especially revoke token flow and subprocess timeout teardown behavior).
2. **Performance inefficiencies from polling loops and repeated scans/clones** in runtime paths.
3. **Maintainability drag from duplicated orchestration logic and oversized command handlers**.

Addressing these items should materially improve hardening and long-term maintainability without requiring architectural rework.

## Detailed Findings

### Security

- **Revoke token contract mismatch (high):** `execute_revoke` passes an empty token into revoke env, while revoke contract expects `NOSCOPE_TOKEN` + `NOSCOPE_TOKEN_ID`. This can break providers that require token material for revocation and leave TTL as the only fallback.
  - Evidence: [src/main.rs:733](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L733), [src/main.rs:734](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L734), [src/provider_exec.rs:290](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L290), [src/integration_runtime.rs:136](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/integration_runtime.rs#L136)
  - Suggestion: carry raw token (or explicitly redefine the revoke contract as token-id-only and update provider protocol/tests accordingly).

- **Provider timeout teardown kills PID, not process group (high):** timeout logic signals only child PID. Forked descendants can survive and keep sensitive env until process exit/TTL.
  - Evidence: [src/provider_exec.rs:533](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L533), [src/provider_exec.rs:542](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L542), [src/provider_exec.rs:607](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L607), [src/process_group.rs:71](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/process_group.rs#L71)
  - Suggestion: run provider commands in dedicated process groups and send signals to group IDs during timeout escalation.

- **Profile role path bypasses role-safety validation (medium-high):** profile roles are accepted as non-empty strings but are not passed through `validate_role` before template substitution.
  - Evidence: [src/main.rs:419](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L419), [src/main.rs:467](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L467), [src/client.rs:140](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/client.rs#L140), [src/profile.rs:206](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/profile.rs#L206), [src/provider_exec.rs:231](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L231)
  - Suggestion: validate each profile credential role with the same NS-033 rules used by CLI mint requests.

- **Output size guards occur after full in-memory reads (medium):** provider stdout/stderr are fully buffered before size checks/truncation, allowing memory pressure from noisy/malicious providers.
  - Evidence: [src/provider_exec.rs:507](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L507), [src/provider_exec.rs:516](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L516), [src/provider_exec.rs:577](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L577)
  - Suggestion: stream with byte caps during read, fail early when limits are exceeded.

- **Redaction coverage is localized and exact-match based (medium):** event error fields accept arbitrary messages; stderr redaction replaces exact known token strings only.
  - Evidence: [src/event.rs:144](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L144), [src/event.rs:160](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L160), [src/provider_exec.rs:342](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L342), [src/provider_exec.rs:476](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L476)
  - Suggestion: centralize redaction before `Event::set_error` across all error event emit paths.

### Performance

- **Busy polling in run supervision loops (high):** fixed 20ms polling loops monitor signals and child exit, causing periodic wakeups even when idle.
  - Evidence: [src/main.rs:349](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L349), [src/main.rs:367](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L367), [src/main.rs:377](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L377)
  - Suggestion: shift to event-driven waiting (or adaptive sleep backoff).

- **Additional 10ms timeout polling in process wait path (high when enabled):** timeout wait loops in `AgentProcess` add high wakeup frequency.
  - Evidence: [src/agent_process.rs:316](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/agent_process.rs#L316), [src/agent_process.rs:324](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/agent_process.rs#L324), [src/agent_process.rs:335](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/agent_process.rs#L335)
  - Suggestion: use blocking timeout primitives or at least adaptive polling.

- **Refresh runtime has repeated linear searches (medium-high):** due credential IDs are collected, then each ID is looked up with a linear scan.
  - Evidence: [src/refresh.rs:333](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/refresh.rs#L333), [src/refresh.rs:346](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/refresh.rs#L346)
  - Suggestion: process due credentials in a single pass or index by credential ID.

- **Event emission rebuilds formatting objects per event (medium):** each runtime event allocates and formats, including JSON serialization or text assembly.
  - Evidence: [src/event.rs:300](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L300), [src/event.rs:309](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L309), [src/event.rs:151](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L151)
  - Suggestion: reuse emitter state and reduce high-frequency event churn where practical.

- **Repeated command parsing and env/string cloning in hot paths (medium):** command parsing and setup logic repeat across run/mint/integration code paths.
  - Evidence: [src/main.rs:778](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L778), [src/main.rs:99](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L99), [src/main.rs:591](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L591), [src/integration_runtime.rs:45](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/integration_runtime.rs#L45)
  - Suggestion: parse commands once at provider resolution and reuse parsed argv.

### Style and Maintainability

- **Duplicated core mint orchestration logic (high):** `cmd_run` and `cmd_mint` duplicate provider setup/execution/conversion flows.
  - Evidence: [src/main.rs:84](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L84), [src/main.rs:576](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L576), [src/main.rs:430](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L430), [src/main.rs:554](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L554)
  - Suggestion: extract a shared mint execution helper and common provider/spec resolution utility.

- **`main.rs` is oversized and cross-domain (high):** command dispatch, runtime orchestration, signal handling, revoke execution, and large test modules all live in one file.
  - Evidence: [src/main.rs:58](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L58), [src/main.rs:316](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L316), [src/main.rs:651](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L651), [src/main.rs:825](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L825)
  - Suggestion: split into command-focused modules (`run`, `mint`, `revoke`, `signals`).

- **Mixed panic/expect vs typed error propagation in runtime paths (high):** some runtime invariants panic while neighboring logic returns structured errors.
  - Evidence: [src/main.rs:88](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L88), [src/main.rs:579](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L579), [src/orchestrator.rs:59](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/orchestrator.rs#L59), [src/orchestrator.rs:120](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/orchestrator.rs#L120), [src/refresh.rs:347](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/refresh.rs#L347)
  - Suggestion: standardize panic policy (tests-only) and convert runtime panics to typed internal/config errors.

- **Validation API inconsistency (medium):** `validate_profile` returns `Vec<String>` while other validators return typed `Result` errors.
  - Evidence: [src/profile.rs:286](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/profile.rs#L286), [src/provider.rs:528](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider.rs#L528), [src/mint.rs:214](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/mint.rs#L214)
  - Suggestion: converge on a single error model (typed multi-error or consistent Result surface).

- **Test fixture setup duplication (medium):** helper utilities like executable/provider-config creation are repeated in multiple test files.
  - Evidence: [src/main.rs:947](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L947), [tests/integration_test_suite.rs:17](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/tests/integration_test_suite.rs#L17), [tests/noscope_f75_os_signal_wiring.rs:9](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/tests/noscope_f75_os_signal_wiring.rs#L9)
  - Suggestion: move shared fixtures into a dedicated `tests/common` helper module.

## Code References

- [src/provider_exec.rs:456](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L456) - Core provider command execution engine.
- [src/provider_exec.rs:503](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L503) - Full-buffer stdout/stderr reads (`read_to_end`).
- [src/provider_exec.rs:607](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider_exec.rs#L607) - Timeout signal helper targeting single PID.
- [src/main.rs:349](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L349) - Run-mode polling supervision loop.
- [src/main.rs:733](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/main.rs#L733) - Revoke env assembly with empty token literal.
- [src/refresh.rs:333](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/refresh.rs#L333) - Due-id collection step preceding repeated lookups.
- [src/refresh.rs:346](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/refresh.rs#L346) - Per-item linear search (`find`) in refresh loop.
- [src/event.rs:300](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/event.rs#L300) - Runtime event emission path.
- [src/agent_process.rs:316](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/agent_process.rs#L316) - Timeout polling loop with fixed sleep.
- [src/profile.rs:206](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/profile.rs#L206) - Profile role parsing without NS-033 character safety.
- [src/provider.rs:397](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/provider.rs#L397) - Config permission enforcement.
- [src/security.rs:79](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/src/security.rs#L79) - Token-in-arguments leak prevention.

## Architecture Insights

- The codebase follows a clear **requirements-by-rule** model (NS-*), and many modules explicitly encode invariants in APIs and tests.
- **Security posture is strong by default** (no shell execution in provider command path, env sandboxing, core-dump suppression, config permission checks, redaction-aware token types), but a few wiring mismatches undermine otherwise solid contracts.
- **Boundary design is thoughtful** (`ProviderOutput -> ScopedToken -> MintEnvelope`), but similar orchestration logic appears in multiple layers (`main.rs` and `integration_runtime.rs`), creating drift risk.
- The runtime currently balances correctness and simplicity with polling loops; for v1 scale this is acceptable, but event-driven waiting would reduce overhead and improve responsiveness.

## Historical Context

- `README.md` states the intended three safety layers (process-group termination, revoke-on-exit, TTL), while noting TTL is currently the only fully implemented backstop in practice: [README.md:7](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/README.md#L7)
- Provider execution contract documentation confirms revoke should receive `NOSCOPE_TOKEN` and `NOSCOPE_TOKEN_ID`: [.beads/provenance-drafts/noscope-ydn.md:21](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.beads/provenance-drafts/noscope-ydn.md#L21)
- Process-group and PDEATHSIG behavior is documented as a run-mode hardening requirement: [.beads/provenance-drafts/noscope-66m.md:5](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.beads/provenance-drafts/noscope-66m.md#L5)
- Structured event logging design explicitly avoids raw token storage in events: [.beads/provenance-drafts/noscope-4of.md:19](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.beads/provenance-drafts/noscope-4of.md#L19)
- CI enforces fmt, clippy-as-errors, tests, and cargo-audit, indicating strong quality gates are already institutionalized: [.github/workflows/ci.yml:36](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.github/workflows/ci.yml#L36), [.github/workflows/ci.yml:39](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.github/workflows/ci.yml#L39), [.github/workflows/ci.yml:42](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.github/workflows/ci.yml#L42), [.github/workflows/ci.yml:55](https://github.com/BNasraoui/noscope/blob/d868f007f138a0a0fbc1b9d72540e0a54d7f590b/.github/workflows/ci.yml#L55)

## Related Research

- No prior `docs/research/` documents were found in this repository at time of writing.

## Open Questions

- Should revoke be formally **token-id only**, or should it continue requiring raw token values in env?
- Should provider subprocesses be moved to dedicated process groups so timeout teardown can be group-wide?
- Is current event verbosity acceptable for expected production load, or should high-frequency events be sampled/coalesced?
- Would you prefer a follow-up implementation plan that sequences changes into "quick wins" vs "deeper refactors"?

## Follow-up Research 2026-03-31T10:08:54+10:00

### Prioritized Remediation Roadmap

#### P0 (highest risk or highest leverage)

1. **SEC-P0-001: Unify revoke contract and wiring across all paths**
   - Why: current revoke behavior is inconsistent between CLI/runtime paths and can silently reduce revocation effectiveness.
   - Scope: align `RevokeInput`, `execute_revoke`, integration runtime revoke helpers, and provider contract docs/tests on one canonical contract.
   - Key refs: `src/main.rs:733`, `src/provider_exec.rs:290`, `src/integration_runtime.rs:136`, `src/mint.rs:133`.
   - Dependencies: none.
   - Done when: all revoke paths inject the same required env contract and tests fail on divergence.

2. **SEC-P0-002: Kill provider subprocess trees (not only PID) on timeout**
   - Why: timeout teardown currently targets one PID; descendants may survive and retain sensitive env.
   - Scope: spawn provider commands in dedicated process groups and send TERM/KILL to group IDs during timeout escalation.
   - Key refs: `src/provider_exec.rs:521`, `src/provider_exec.rs:607`, `src/process_group.rs:71`.
   - Dependencies: none.
   - Done when: timeout tests prove descendants are terminated with the parent provider process.

3. **PERF-P0-001: Replace fixed polling loops with event-driven waits**
   - Why: 20ms and 10ms polling loops create avoidable wakeups and latency jitter in long-running sessions.
   - Scope: refactor run supervision and timeout waits to blocking/event-driven mechanisms while preserving signal/revoke semantics.
   - Key refs: `src/main.rs:349`, `src/main.rs:377`, `src/agent_process.rs:316`, `src/agent_process.rs:335`.
   - Dependencies: none.
   - Done when: no fixed-frequency sleep loops remain in these runtime supervision paths.

4. **STYLE-P0-001: Extract shared mint execution helper**
   - Why: core mint orchestration is duplicated, increasing bug-fix drift and review overhead.
   - Scope: consolidate duplicate mint flow logic used by run/mint/integration entrypoints.
   - Key refs: `src/main.rs:84`, `src/main.rs:576`, `src/integration_runtime.rs:79`.
   - Dependencies: none.
   - Done when: run and mint paths call one shared helper for provider execution and result mapping.

#### P1 (important hardening/efficiency improvements)

5. **SEC-P1-001: Apply NS-033 role validation to profile and integration role paths**
   - Why: profile-based roles bypass the same safety checks applied to direct CLI mint inputs.
   - Scope: validate profile roles before template substitution/execution in all relevant paths.
   - Key refs: `src/main.rs:419`, `src/profile.rs:206`, `src/client.rs:140`, `src/provider_exec.rs:231`.
   - Dependencies: none.
   - Done when: invalid role characters are rejected consistently for profile-based and direct flows.

6. **PERF-P1-001: Remove repeated linear searches in refresh runtime**
   - Why: current due-ID collection + per-ID lookup pattern scales poorly as credential count rises.
   - Scope: process due credentials in one pass or indexed lookup structure.
   - Key refs: `src/refresh.rs:333`, `src/refresh.rs:346`, `src/refresh.rs:460`.
   - Dependencies: none.
   - Done when: `run_once` no longer does a second linear scan per due credential.

7. **PERF-P1-002: Stream provider output with in-read byte caps**
   - Why: full-buffer reads before size checks allow unnecessary memory pressure.
   - Scope: enforce stdout/stderr caps during read, not after complete buffering.
   - Key refs: `src/provider_exec.rs:503`, `src/provider_exec.rs:516`, `src/provider_exec.rs:577`.
   - Dependencies: none.
   - Done when: oversize outputs are rejected without full payload accumulation.

8. **STYLE-P1-001: Decompose `main.rs` into command modules**
   - Why: command handlers, signal loops, revoke execution, and tests are concentrated in one large file.
   - Scope: move run/mint/revoke/signal orchestration into dedicated modules; keep `main.rs` as thin entrypoint.
   - Key refs: `src/main.rs:58`, `src/main.rs:316`, `src/main.rs:651`, `src/main.rs:825`.
   - Dependencies: after STYLE-P0-001 (recommended).
   - Done when: `main.rs` primarily contains parse + dispatch with behavior-preserving module calls.

9. **STYLE-P1-002: Standardize runtime panic/expect policy**
   - Why: mixed panic/expect and typed errors in runtime code complicate failure behavior guarantees.
   - Scope: replace runtime `expect`/`panic!` with typed errors in non-test paths.
   - Key refs: `src/main.rs:88`, `src/main.rs:579`, `src/orchestrator.rs:120`, `src/refresh.rs:347`.
   - Dependencies: after STYLE-P1-001 (recommended).
   - Done when: non-test runtime flow avoids panic-style error handling.

#### P2 (cleanup and long-term consistency)

10. **SEC-P2-001: Centralize event-error redaction path**
    - Why: redaction is currently partial and call-site dependent.
    - Scope: apply shared redaction before all `Event::set_error` calls.
    - Key refs: `src/event.rs:144`, `src/provider_exec.rs:342`, `src/main.rs:768`, `src/refresh.rs:378`.
    - Dependencies: after SEC-P0-001 (recommended).
    - Done when: no runtime failure event can emit raw token strings.

11. **STYLE-P2-001: Align validation APIs across profile/provider/mint**
    - Why: mixed `Vec<String>` and typed `Result` APIs create translation complexity.
    - Scope: converge on one validation error model and boundary adaptation pattern.
    - Key refs: `src/profile.rs:286`, `src/provider.rs:528`, `src/mint.rs:214`.
    - Dependencies: after STYLE-P1-001 (recommended).
    - Done when: all validation entrypoints follow the same external contract style.

12. **STYLE-P2-002: Deduplicate shared test fixtures**
    - Why: executable/provider-config helper duplication increases maintenance cost.
    - Scope: extract shared test utilities and remove repeated helper definitions.
    - Key refs: `src/main.rs:947`, `tests/integration_test_suite.rs:17`, `tests/noscope_f75_os_signal_wiring.rs:9`.
    - Dependencies: after STYLE-P1-001 (recommended).
    - Done when: helper duplication is removed and tests consume shared fixtures.

### Recommended Implementation Sequence

1. SEC-P0-001
2. SEC-P0-002
3. PERF-P0-001
4. STYLE-P0-001
5. SEC-P1-001
6. PERF-P1-001
7. PERF-P1-002
8. STYLE-P1-001
9. STYLE-P1-002
10. SEC-P2-001
11. STYLE-P2-001
12. STYLE-P2-002

### Risk Notes

- **Behavior-sensitive changes:** SEC-P0-001 and SEC-P0-002 should ship behind focused regression coverage before broader refactors.
- **Refactor coupling:** STYLE-P0-001 lowers risk for STYLE-P1-001 by reducing duplicate command flow before file/module moves.
- **Operational visibility:** PERF-P0-001 and PERF-P1-002 should include before/after measurement snapshots (wakeups, CPU, memory under stress output).

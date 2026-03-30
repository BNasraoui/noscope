// noscope-x2r: CI/CD pipeline and release automation validation.
//
// This module contains tests that validate the CI/CD workflow files exist
// and are correctly structured. The workflow files themselves are the
// "production code" — YAML in .github/workflows/. These tests enforce
// the requirements from bead noscope-x2r.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    /// Locate the project root by finding Cargo.toml relative to CARGO_MANIFEST_DIR.
    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Read a workflow file from .github/workflows/ relative to project root.
    fn read_workflow(name: &str) -> String {
        let path = project_root().join(".github/workflows").join(name);
        fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read workflow file {}: {}", path.display(), e))
    }

    // =========================================================================
    // noscope-x2r: GitHub Actions CI workflow must exist.
    //
    // Requirement: GitHub Actions workflow with cargo test, cargo clippy
    // -D warnings, cargo fmt --check.
    // =========================================================================

    #[test]
    fn ci_workflow_exists() {
        let path = project_root().join(".github/workflows/ci.yml");
        assert!(
            path.exists(),
            "CI workflow must exist at .github/workflows/ci.yml"
        );
    }

    #[test]
    fn ci_workflow_runs_cargo_test() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("cargo test"),
            "CI workflow must run cargo test"
        );
    }

    #[test]
    fn ci_workflow_runs_cargo_clippy_deny_warnings() {
        let content = read_workflow("ci.yml");
        // Must deny warnings, not just run clippy
        assert!(
            content.contains("clippy") && content.contains("-D warnings"),
            "CI workflow must run cargo clippy with -D warnings"
        );
    }

    #[test]
    fn ci_workflow_runs_cargo_fmt_check() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("cargo fmt") && content.contains("--check"),
            "CI workflow must run cargo fmt --check"
        );
    }

    // =========================================================================
    // noscope-x2r: Multi-platform matrix — Linux required, macOS per
    // resolution js78yc77a4v6jay98cx3taxths83ta35.
    // =========================================================================

    #[test]
    fn ci_workflow_matrix_includes_linux() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("ubuntu"),
            "CI matrix must include Linux (ubuntu runner)"
        );
    }

    #[test]
    fn ci_workflow_matrix_includes_macos() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("macos"),
            "CI matrix must include macOS per resolution js78yc77a4v6jay98cx3taxths83ta35"
        );
    }

    // =========================================================================
    // noscope-x2r: cargo audit for security advisories.
    // =========================================================================

    #[test]
    fn ci_workflow_runs_cargo_audit() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("cargo audit") || content.contains("cargo-audit"),
            "CI workflow must run cargo audit for security advisories"
        );
    }

    // =========================================================================
    // noscope-x2r: Release automation — cargo publish, GitHub releases
    // with pre-built binaries.
    // =========================================================================

    #[test]
    fn release_workflow_exists() {
        let path = project_root().join(".github/workflows/release.yml");
        assert!(
            path.exists(),
            "Release workflow must exist at .github/workflows/release.yml"
        );
    }

    #[test]
    fn release_workflow_triggers_on_tag() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("tags"),
            "Release workflow must trigger on version tags"
        );
    }

    #[test]
    fn release_workflow_publishes_to_crates_io() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("cargo publish"),
            "Release workflow must include cargo publish"
        );
    }

    #[test]
    fn release_workflow_creates_github_release() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("gh release") || content.contains("softprops/action-gh-release"),
            "Release workflow must create GitHub releases"
        );
    }

    // =========================================================================
    // noscope-x2r: Binary artifacts — Linux amd64/arm64, macOS amd64/arm64.
    // =========================================================================

    #[test]
    fn release_workflow_builds_linux_amd64() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("x86_64-unknown-linux-gnu"),
            "Release must build Linux amd64 binary (x86_64-unknown-linux-gnu target)"
        );
    }

    #[test]
    fn release_workflow_builds_linux_arm64() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("aarch64-unknown-linux"),
            "Release must build Linux arm64 binary"
        );
    }

    #[test]
    fn release_workflow_builds_macos_amd64() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("x86_64-apple-darwin"),
            "Release must build macOS amd64 binary"
        );
    }

    #[test]
    fn release_workflow_builds_macos_arm64() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("aarch64-apple-darwin"),
            "Release must build macOS arm64 binary"
        );
    }

    // =========================================================================
    // noscope-x2r: CI workflow must trigger on push and pull_request.
    // =========================================================================

    #[test]
    fn ci_workflow_triggers_on_push() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("push"),
            "CI workflow must trigger on push events"
        );
    }

    #[test]
    fn ci_workflow_triggers_on_pull_request() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("pull_request"),
            "CI workflow must trigger on pull_request events"
        );
    }

    // =========================================================================
    // noscope-x2r: Structural integrity — workflow files must be valid YAML
    // with required GitHub Actions top-level keys.
    // =========================================================================

    #[test]
    fn ci_workflow_has_name_key() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("name:"),
            "CI workflow must have a name key"
        );
    }

    #[test]
    fn ci_workflow_has_on_key() {
        let content = read_workflow("ci.yml");
        // "on:" at start of line (YAML trigger key)
        assert!(
            content.contains("\non:") || content.starts_with("on:"),
            "CI workflow must have an 'on:' trigger key"
        );
    }

    #[test]
    fn ci_workflow_has_jobs_key() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("jobs:"),
            "CI workflow must have a jobs key"
        );
    }

    #[test]
    fn release_workflow_has_name_key() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("name:"),
            "Release workflow must have a name key"
        );
    }

    #[test]
    fn release_workflow_has_jobs_key() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("jobs:"),
            "Release workflow must have a jobs key"
        );
    }

    // =========================================================================
    // noscope-x2r: Release workflow uploads binary artifacts.
    // =========================================================================

    #[test]
    fn release_workflow_uploads_artifacts() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("upload") || content.contains("artifact"),
            "Release workflow must upload binary artifacts"
        );
    }

    // =========================================================================
    // noscope-x2r: CI uses stable Rust toolchain.
    // =========================================================================

    #[test]
    fn ci_workflow_uses_stable_toolchain() {
        let content = read_workflow("ci.yml");
        assert!(
            content.contains("stable"),
            "CI workflow must use stable Rust toolchain"
        );
    }

    // =========================================================================
    // noscope-x2r: Release workflow uses CARGO_REGISTRY_TOKEN secret.
    // =========================================================================

    #[test]
    fn release_workflow_uses_cargo_registry_token() {
        let content = read_workflow("release.yml");
        assert!(
            content.contains("CARGO_REGISTRY_TOKEN"),
            "Release workflow must use CARGO_REGISTRY_TOKEN secret for cargo publish"
        );
    }
}

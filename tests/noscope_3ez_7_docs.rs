use std::fs;
use std::path::Path;

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed reading {}: {}", path, e))
}

fn assert_contains_all(haystack: &str, needles: &[&str], context: &str) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "{} must contain {:?}",
            context,
            needle
        );
    }
}

#[test]
fn rule_readme_includes_install_steps() {
    let readme = read_file("README.md");
    assert_contains_all(
        &readme,
        &[
            "## Install",
            "cargo install --path .",
            "cargo build --release",
        ],
        "README install section",
    );
}

#[test]
fn rule_readme_includes_provider_config_examples() {
    let readme = read_file("README.md");
    assert_contains_all(
        &readme,
        &[
            "contract_version = 1",
            "[commands]",
            "mint =",
            "revoke =",
            "supports_revoke = true",
        ],
        "README provider config examples",
    );
}

#[test]
fn rule_quickstart_covers_first_run_workflows() {
    let quickstart_path = Path::new("docs/QUICKSTART.md");
    assert!(
        quickstart_path.exists(),
        "docs/QUICKSTART.md must exist for first-run workflow guidance"
    );

    let quickstart = read_file("docs/QUICKSTART.md");
    assert_contains_all(
        &quickstart,
        &[
            "noscope dry-run",
            "noscope mint",
            "noscope revoke",
            "noscope run",
        ],
        "QUICKSTART first-run workflows",
    );
}

#[test]
fn rule_docs_explain_safety_layers_implemented_vs_planned() {
    let readme = read_file("README.md");
    assert_contains_all(
        &readme,
        &[
            "Safety Layers",
            "TTL expiry",
            "currently implemented",
            "planned",
            "revoke-on-exit",
            "process-group termination",
        ],
        "README safety-layer guidance",
    );
}

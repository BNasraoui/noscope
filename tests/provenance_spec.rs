//! Checks the requirements-as-code declaration against the committed graph.
//!
//! The declaration in `noscope::provenance_spec` is the maintainable source
//! for NoScope's Provenance Requirements. These tests reconcile it against a
//! copy of `.provenance` using the same store the CLI drives, so they prove
//! the declaration adopts the existing graph rather than rebuilding it.
#![cfg(feature = "provenance-spec")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use noscope::provenance_spec::{self, DECLARED_REQUIREMENTS, DECLARED_RULES};
use provenance_sdk::{operations, ScopeId};

const SCOPE: &str = "default";
const STATE: &str = ".provenance/state/scopes/default";
const EDGES: &str = ".provenance/state/edges/edges-00.jsonl";

fn scope() -> ScopeId {
    ScopeId::new(SCOPE).expect("the default scope id is valid")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("the sandbox directory is creatable");
    for entry in std::fs::read_dir(from).expect("the source directory is readable") {
        let entry = entry.expect("the directory entry is readable");
        let target = to.join(entry.file_name());
        if entry
            .file_type()
            .expect("the entry has a file type")
            .is_dir()
        {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("the file is copyable");
        }
    }
}

/// Copies the committed graph into a scratch repository.
fn sandbox() -> (tempfile::TempDir, camino::Utf8PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory is creatable");
    copy_tree(Path::new(".provenance"), &dir.path().join(".provenance"));
    let root = camino::Utf8PathBuf::from_path_buf(
        dir.path()
            .canonicalize()
            .expect("the sandbox path resolves"),
    )
    .expect("the sandbox path is UTF-8");
    (dir, root)
}

/// Reads the `id` field of every record in one JSONL shard.
fn ids(root: &Path, relative: &str) -> BTreeSet<String> {
    records(root, relative)
        .into_iter()
        .map(|record| {
            record["id"]
                .as_str()
                .expect("records carry an id")
                .to_owned()
        })
        .collect()
}

fn records(root: &Path, relative: &str) -> Vec<serde_json::Value> {
    let path = root.join(relative);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each line is one JSON record"))
        .collect()
}

fn statements(root: &Path, relative: &str) -> BTreeMap<String, String> {
    records(root, relative)
        .into_iter()
        .map(|record| {
            (
                record["id"]
                    .as_str()
                    .expect("records carry an id")
                    .to_owned(),
                record["statement"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

#[test]
fn the_declaration_builds_and_counts_match() {
    let input = provenance_spec::desired_state().expect("the declaration is valid");
    assert_eq!(input.requirements.len(), DECLARED_REQUIREMENTS);
    assert_eq!(input.rules.len(), DECLARED_RULES);
    assert_eq!(
        input.adopt_unowned.len(),
        DECLARED_REQUIREMENTS + DECLARED_RULES + input.sources.len(),
        "every declared record adopts one existing identifier"
    );
}

#[test]
fn every_declared_identifier_already_exists_in_the_graph() {
    let root = Path::new(".");
    let input = provenance_spec::desired_state().expect("the declaration is valid");
    let requirements = ids(root, &format!("{STATE}/requirements/req.jsonl"));
    let rules = ids(root, &format!("{STATE}/rules/rule.jsonl"));
    let sources = ids(root, &format!("{STATE}/sources/source.jsonl"));

    for declaration in &input.requirements {
        let id = declaration.id.as_deref().expect("requirements adopt an id");
        assert!(requirements.contains(id), "unknown requirement `{id}`");
    }
    for declaration in &input.rules {
        let id = declaration.id.as_deref().expect("rules adopt an id");
        assert!(rules.contains(id), "unknown rule `{id}`");
    }
    for declaration in &input.sources {
        let id = declaration.id.as_deref().expect("sources adopt an id");
        assert!(sources.contains(id), "unknown source `{id}`");
    }
    assert_eq!(
        requirements.len(),
        DECLARED_REQUIREMENTS,
        "the declaration covers every Requirement in the graph"
    );
}

#[test]
fn applying_adopts_the_graph_without_creating_or_retiring_records() {
    let (_dir, root) = sandbox();
    let input = provenance_spec::desired_state().expect("the declaration is valid");

    let plan =
        operations::plan(Some(root.clone()), &scope(), input.clone()).expect("the plan succeeds");
    assert_eq!(
        (
            plan.reconciliation.created,
            plan.reconciliation.retired,
            plan.reconciliation.conflicts,
            plan.reconciliation.updated,
        ),
        (0, 0, 0, 0),
        "adoption neither creates, retires, conflicts, nor edits a field"
    );

    let applied =
        operations::apply(Some(root.clone()), &scope(), input).expect("the apply succeeds");
    assert_eq!(
        (applied.created, applied.retired, applied.conflicts),
        (0, 0, 0)
    );
    assert_eq!(
        applied.resources.len(),
        DECLARED_REQUIREMENTS + DECLARED_RULES + 1,
        "every Requirement, its Rules, and the cited Source reconcile"
    );
}

#[test]
fn applying_preserves_every_identifier_edge_and_statement() {
    let (_dir, root) = sandbox();
    let before_root = Path::new(".");
    let sandbox_root = root.as_std_path();

    let requirements = format!("{STATE}/requirements/req.jsonl");
    let rules = format!("{STATE}/rules/rule.jsonl");
    let sources = format!("{STATE}/sources/source.jsonl");
    let resolutions = format!("{STATE}/resolutions/res.jsonl");

    let before = (
        ids(before_root, &requirements),
        ids(before_root, &rules),
        ids(before_root, &sources),
        ids(before_root, &resolutions),
        ids(before_root, EDGES),
        statements(before_root, &requirements),
        statements(before_root, &rules),
    );

    let input = provenance_spec::desired_state().expect("the declaration is valid");
    operations::apply(Some(root.clone()), &scope(), input).expect("the apply succeeds");

    let after = (
        ids(sandbox_root, &requirements),
        ids(sandbox_root, &rules),
        ids(sandbox_root, &sources),
        ids(sandbox_root, &resolutions),
        ids(sandbox_root, EDGES),
        statements(sandbox_root, &requirements),
        statements(sandbox_root, &rules),
    );

    assert_eq!(before.0, after.0, "Requirement ids are preserved");
    assert_eq!(before.1, after.1, "Rule ids are preserved");
    assert_eq!(before.2, after.2, "Source ids are preserved");
    assert_eq!(before.3, after.3, "Resolution ids are preserved");
    assert_eq!(before.4, after.4, "edge ids are preserved");
    assert_eq!(before.5, after.5, "Requirement statements are preserved");
    assert_eq!(before.6, after.6, "Rule statements are preserved");
}

#[test]
fn plan_and_apply_are_idempotent() {
    let (_dir, root) = sandbox();
    let input = provenance_spec::desired_state().expect("the declaration is valid");

    operations::apply(Some(root.clone()), &scope(), input.clone()).expect("the first apply");

    let replay = operations::plan(Some(root.clone()), &scope(), input.clone())
        .expect("the replayed plan succeeds");
    assert_eq!(
        (
            replay.reconciliation.created,
            replay.reconciliation.updated,
            replay.reconciliation.moved,
            replay.reconciliation.retired,
            replay.reconciliation.conflicts,
        ),
        (0, 0, 0, 0, 0),
        "a replayed plan reports no work"
    );
    assert_eq!(
        replay.reconciliation.unchanged,
        DECLARED_REQUIREMENTS + DECLARED_RULES + 1
    );

    let second =
        operations::apply(Some(root.clone()), &scope(), input).expect("the second apply succeeds");
    assert_eq!(
        (
            second.created,
            second.updated,
            second.moved,
            second.retired,
            second.conflicts
        ),
        (0, 0, 0, 0, 0),
        "a second apply is a no-op"
    );
}

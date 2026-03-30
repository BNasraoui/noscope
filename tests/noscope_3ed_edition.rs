use std::fs;
use std::path::PathBuf;

#[test]
fn cargo_manifest_uses_stable_edition_2021() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", manifest_path.display(), e));

    assert!(
        manifest.contains("edition = \"2021\""),
        "Cargo.toml must set edition to 2021 for stable Rust compatibility"
    );
}

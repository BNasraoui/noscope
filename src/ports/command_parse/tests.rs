use provenance_macros::verifies;

#[test]
#[verifies("rule_cross_command_parse_quoting", examples)]
fn parse_command_preserves_quoted_segments() {
    let argv = super::parse_command("/bin/sh -c 'printf hello world'");
    assert_eq!(argv, vec!["/bin/sh", "-c", "printf hello world"]);
}

#[test]
fn parse_command_falls_back_to_whitespace_on_unbalanced_quotes() {
    let argv = super::parse_command("echo 'unbalanced");
    assert_eq!(argv, vec!["echo", "'unbalanced"]);
}

use provenance_macros::rule;

/// Shell-parse a command string into argv tokens.
/// Uses [`shlex::split`] for POSIX-correct quoting.  Falls back to
/// whitespace splitting when the input contains unbalanced quotes so
/// that callers always get *some* usable argv rather than an error.
#[rule("rule_cross_command_parse_quoting")]
pub fn parse_command(command: &str) -> Vec<String> {
    match shlex::split(command) {
        Some(parts) => parts,
        None => command.split_whitespace().map(|s| s.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
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
}

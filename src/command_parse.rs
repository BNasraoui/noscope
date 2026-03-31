/// Shell-parse a command string into argv tokens.
///
/// Uses [`shlex::split`] for POSIX-correct quoting.  Falls back to
/// whitespace splitting when the input contains unbalanced quotes so
/// that callers always get *some* usable argv rather than an error.
pub fn parse_command(command: &str) -> Vec<String> {
    match shlex::split(command) {
        Some(parts) => parts,
        None => command.split_whitespace().map(|s| s.to_string()).collect(),
    }
}

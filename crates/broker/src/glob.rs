//! Glob patterns over workspace-relative paths, compiled to regular
//! expressions. The same translation feeds the broker's own matcher and the
//! Seatbelt profiles of spawned programs, so both enforce one rule set.
//!
//! Matching ignores ASCII case. The default macOS volume is case-insensitive,
//! so a file created as `.VSCODE/tasks.json` is opened by other tools as
//! `.vscode/tasks.json`; a case-sensitive rule would not see it. On a
//! case-sensitive volume this is stricter than necessary, never weaker.

/// Translates a glob body to a regex fragment (unanchored).
pub fn glob_to_regex_body(pattern: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '*' && chars.get(i + 1) == Some(&'*') {
            if chars.get(i + 2) == Some(&'/') {
                out.push_str("(.*/)?");
                i += 3;
            } else {
                out.push_str(".*");
                i += 2;
            }
            continue;
        }
        match c {
            '*' => out.push_str("[^/]*"),
            '?' => out.push_str("[^/]"),
            _ => push_literal(&mut out, c),
        }
        i += 1;
    }
    out
}

/// Escapes the POSIX ERE metacharacters, which both the `regex` crate and
/// Seatbelt's regex engine accept escaped, and turns letters into a class of
/// both cases. On a case-insensitive volume Seatbelt already compares paths
/// without regard to case; the classes keep the broker's matcher and the
/// profile identical on every volume.
fn push_literal(out: &mut String, c: char) {
    if c.is_ascii_alphabetic() {
        out.push('[');
        out.push(c.to_ascii_lowercase());
        out.push(c.to_ascii_uppercase());
        out.push(']');
        return;
    }
    if "\\.+*?()|[]{}^$".contains(c) {
        out.push('\\');
    }
    out.push(c);
}

/// Escapes a literal path without case folding, for absolute roots that are
/// already canonical.
fn push_exact(out: &mut String, c: char) {
    if "\\.+*?()|[]{}^$".contains(c) {
        out.push('\\');
    }
    out.push(c);
}

pub fn escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_exact(&mut out, c);
    }
    out
}

/// Directory prefixes of a pattern that name at least one directory, for
/// example `**/.github` for `**/.github/**`. Prefixes made only of `**` are
/// skipped, since they match every directory.
pub fn named_dir_prefixes(pattern: &str) -> Vec<String> {
    let parts: Vec<&str> = pattern.split('/').collect();
    (1..parts.len())
        .map(|k| &parts[..k])
        .filter(|pre| pre.iter().any(|c| *c != "**"))
        .map(|pre| pre.join("/"))
        .collect()
}

pub fn compile(pattern: &str) -> regex::Regex {
    // (?s): `.` also matches a newline, as it does in Seatbelt's engine.
    regex::Regex::new(&format!("(?s)^{}$", glob_to_regex_body(pattern)))
        .expect("glob translation always yields a valid regex")
}

/// Regex for Seatbelt that matches `pattern` under the absolute `root`.
pub fn sbpl_regex(root: &str, pattern: &str) -> String {
    format!("^{}/{}$", escape_literal(root), glob_to_regex_body(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches() {
        let env = compile("**/.env");
        assert!(env.is_match(".env"));
        assert!(env.is_match("a/b/.env"));
        assert!(!env.is_match("a/.env.bak"));
        let envx = compile("**/.env.*");
        assert!(envx.is_match("cfg/.env.local"));
        let gh = compile("**/.github/**");
        assert!(gh.is_match(".github/workflows/ci.yml"));
        let sh = compile("**/*.sh");
        assert!(sh.is_match("deploy.sh"));
        assert!(!sh.is_match("deploy.shx"));
        assert!(!compile("*.sh").is_match("a/deploy.sh"));
        assert!(compile("**/.vscode/**").is_match(".VSCode/tasks.json"));
        assert!(compile("**/HEAD").is_match("tools/cache/head"));
        assert!(env.is_match(".ENV"));
    }

    #[test]
    fn dir_prefixes() {
        assert_eq!(
            named_dir_prefixes("**/.github/**"),
            vec!["**/.github".to_string()]
        );
        assert!(named_dir_prefixes("**/.env").is_empty());
        assert_eq!(
            named_dir_prefixes("config/keys/*.pem"),
            vec!["config", "config/keys"]
        );
    }

    #[test]
    fn specials_escaped() {
        assert!(!compile("a.b").is_match("axb"));
        assert!(sbpl_regex("/private/tmp/w+s", "**/.env").starts_with("^/private/tmp/w\\+s/"));
    }
}

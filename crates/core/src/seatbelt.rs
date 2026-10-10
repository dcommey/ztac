//! Generation of macOS Seatbelt (SBPL) profiles.
//!
//! Profiles start from `(deny default)` and add only what a confined process
//! needs. Paths must be canonical (for example `/private/tmp`, not `/tmp`),
//! because Seatbelt matches on resolved vnode paths.

use std::path::{Path, PathBuf};

/// Read-only locations every confined process needs to load and run:
/// the dyld shared cache, system libraries, and system frameworks.
pub const SYSTEM_READ_SUBPATHS: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/System/Library",
    "/System/Volumes/Preboot/Cryptexes",
    "/System/Cryptexes",
    "/Library/Preferences/Logging",
    "/private/var/db/timezone",
    "/private/etc",
];

pub const SYSTEM_READ_LITERALS: &[&str] = &["/dev/null", "/dev/urandom", "/dev/random", "/"];

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub read_subpaths: Vec<PathBuf>,
    pub read_literals: Vec<PathBuf>,
    pub write_subpaths: Vec<PathBuf>,
    pub write_literals: Vec<PathBuf>,
    pub exec_subpaths: Vec<PathBuf>,
    pub exec_literals: Vec<PathBuf>,
    /// Unix-domain sockets the process may connect to.
    pub unix_sockets: Vec<PathBuf>,
    pub allow_fork: bool,
}

impl Profile {
    /// Base profile with the system read set and nothing else.
    pub fn base() -> Self {
        Profile {
            read_subpaths: SYSTEM_READ_SUBPATHS.iter().map(PathBuf::from).collect(),
            read_literals: SYSTEM_READ_LITERALS.iter().map(PathBuf::from).collect(),
            write_literals: vec![PathBuf::from("/dev/null")],
            ..Default::default()
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::from("(version 1)\n(deny default)\n");
        out.push_str("(allow sysctl-read)\n");
        // Metadata reads (stat) do not reveal file contents; dyld and most
        // runtimes need them for path resolution.
        out.push_str("(allow file-read-metadata)\n");
        out.push_str("(allow mach-lookup (global-name \"com.apple.system.logger\"))\n");
        if self.allow_fork {
            out.push_str("(allow process-fork)\n");
        }
        rule(
            &mut out,
            "file-read*",
            &self.read_subpaths,
            &self.read_literals,
        );
        rule(
            &mut out,
            "file-write*",
            &self.write_subpaths,
            &self.write_literals,
        );
        rule(
            &mut out,
            "process-exec",
            &self.exec_subpaths,
            &self.exec_literals,
        );
        if !self.unix_sockets.is_empty() {
            out.push_str("(allow network-outbound\n");
            for p in &self.unix_sockets {
                out.push_str(&format!("  (literal {})\n", quote(p)));
            }
            out.push_str(")\n");
        }
        out
    }
}

fn rule(out: &mut String, op: &str, subpaths: &[PathBuf], literals: &[PathBuf]) {
    if subpaths.is_empty() && literals.is_empty() {
        return;
    }
    out.push_str(&format!("(allow {op}\n"));
    for p in subpaths {
        out.push_str(&format!("  (subpath {})\n", quote(p)));
    }
    for p in literals {
        out.push_str(&format!("  (literal {})\n", quote(p)));
    }
    out.push_str(")\n");
}

/// Quotes a path as an SBPL string literal. Every path that enters a profile
/// goes through this function: a path chosen by the cell must not be able to
/// end the literal and add rules of its own.
pub fn quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q
}

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_specials() {
        assert_eq!(quote(Path::new("/a\"b\\c")), "\"/a\\\"b\\\\c\"");
    }

    #[test]
    fn render_is_deny_default() {
        let p = Profile::base().render();
        assert!(p.starts_with("(version 1)\n(deny default)"));
        assert!(!p.contains("network-outbound"));
    }
}

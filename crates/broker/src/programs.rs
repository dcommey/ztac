//! Resolution of program names to absolute binaries at broker startup.
//!
//! On macOS, /usr/bin/git and /usr/bin/python3 are shims that consult xcrun
//! and user state. The broker resolves the real binary once, so the exec
//! sandbox only needs to admit the toolchain directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{Program, ProgramKind};

#[derive(Debug, Clone)]
pub struct ResolvedProgram {
    pub name: String,
    pub path: PathBuf,
    pub kind: ProgramKind,
    /// Directory tree the program loads code and data from.
    pub toolchain_root: Option<PathBuf>,
}

pub fn resolve_all(programs: &[Program]) -> anyhow::Result<Vec<ResolvedProgram>> {
    programs.iter().map(resolve_one).collect()
}

fn resolve_one(p: &Program) -> anyhow::Result<ResolvedProgram> {
    let path = if Path::new(&p.program).is_absolute() {
        PathBuf::from(&p.program)
    } else {
        find(&p.program).ok_or_else(|| anyhow::anyhow!("cannot locate program '{}'", p.program))?
    };
    let path = path.canonicalize()?;
    Ok(ResolvedProgram {
        name: p.name.clone(),
        toolchain_root: toolchain_root(&path),
        path,
        kind: p.kind,
    })
}

fn find(name: &str) -> Option<PathBuf> {
    if let Ok(out) = Command::new("/usr/bin/xcrun")
        .args(["--find", name])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn toolchain_root(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    for marker in ["/Contents/Developer", "/CommandLineTools"] {
        if let Some(i) = s.find(marker) {
            return Some(PathBuf::from(&s[..i + marker.len()]));
        }
    }
    if s.starts_with("/opt/homebrew/") {
        return Some(PathBuf::from("/opt/homebrew"));
    }
    None
}

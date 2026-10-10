//! Turns request parameters into the concrete operation the broker would
//! perform. Policy is evaluated on this resolved form, and adapters execute
//! exactly this form, so the object that is checked is the object that is used.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use url::Url;
use ztac_core::Tool;

use crate::config::{BrokerConfig, Mode, ProgramKind};
use crate::programs::ResolvedProgram;

#[derive(Debug, Clone)]
pub struct FsTarget {
    /// Path the adapter will open.
    pub path: PathBuf,
    /// Path relative to the workspace, '/'-separated. Empty when the target
    /// lies outside the workspace (possible only in the baseline modes).
    pub rel: String,
    /// The string the cell sent.
    pub raw: String,
    /// The file's current content is exactly what this cell last wrote to
    /// it through the broker. Set by the server from its provenance record.
    pub cell_originated: bool,
    /// A regular file with more than one hard link. Its other names are
    /// unknown, so name-based rules cannot be trusted for it.
    pub multiply_linked: bool,
    /// Device and inode of the object that was classified, if it exists.
    /// The adapter refuses to act on a different object.
    pub ident: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub enum Op {
    Ping,
    FsRead {
        target: FsTarget,
        max_bytes: usize,
    },
    FsWrite {
        target: FsTarget,
        data: Vec<u8>,
        create_dirs: bool,
    },
    Exec {
        program: ResolvedProgram,
        args: Vec<String>,
        cwd: PathBuf,
        timeout_ms: u64,
    },
    Net {
        url: Url,
        method: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
        timeout_ms: u64,
    },
}

impl Op {
    /// Short description for audit records and approval prompts.
    pub fn summary(&self) -> String {
        match self {
            Op::Ping => "ping".into(),
            Op::FsRead { target, .. } => format!("read {}", display_target(target)),
            Op::FsWrite { target, data, .. } => {
                use sha2::{Digest, Sha256};
                let h = hex::encode(Sha256::digest(data));
                format!(
                    "write {} ({} bytes, sha256 {})",
                    display_target(target),
                    data.len(),
                    &h[..16]
                )
            }
            Op::Exec {
                program, args, cwd, ..
            } => {
                let mut s = program.name.clone();
                for a in args {
                    s.push(' ');
                    s.push_str(&format!("{a:?}"));
                }
                s.push_str(&format!(" (in {})", cwd.display()));
                s
            }
            Op::Net { url, method, .. } => format!("{method} {url}"),
        }
    }
}

impl Op {
    /// What an approval for this operation is bound to besides the request
    /// parameters: the resolved object. A file target is named by its
    /// workspace path and inode, so repointing a symlink or replacing the file
    /// after review invalidates the approval. A git command is bound to the
    /// repository state it acts on (HEAD, the current branch, and the index),
    /// so staging other content after review invalidates it as well.
    pub fn binding(&self, workspace: &Path) -> String {
        match self {
            Op::FsRead { target, .. } | Op::FsWrite { target, .. } => {
                let (dev, ino) = target.ident.unwrap_or((0, 0));
                format!("{}#{}:{}", target.rel, dev, ino)
            }
            Op::Exec { program, cwd, .. } => {
                let mut b = format!("{}@{}", program.path.display(), cwd.display());
                if program.kind == ProgramKind::Git {
                    b.push('#');
                    b.push_str(&repo_state(&workspace.join(".git")));
                }
                b
            }
            Op::Net { url, .. } => url.to_string(),
            Op::Ping => String::new(),
        }
    }
}

/// Hash of the files that determine what a git command acts on.
fn repo_state(git_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let head = std::fs::read(git_dir.join("HEAD")).unwrap_or_default();
    h.update(&head);
    if let Some(r) = std::str::from_utf8(&head)
        .ok()
        .and_then(|s| s.trim().strip_prefix("ref: "))
    {
        if !r.split('/').any(|c| c == "..") {
            h.update(std::fs::read(git_dir.join(r)).unwrap_or_default());
        }
    }
    h.update(std::fs::read(git_dir.join("packed-refs")).unwrap_or_default());
    h.update(std::fs::read(git_dir.join("index")).unwrap_or_default());
    hex::encode(h.finalize())
}

fn display_target(t: &FsTarget) -> String {
    if t.rel.is_empty() {
        t.path.display().to_string()
    } else {
        t.rel.clone()
    }
}

pub fn resolve(
    config: &BrokerConfig,
    programs: &[ResolvedProgram],
    workspace: &Path,
    tool: Tool,
    params: &Value,
) -> Result<Op, String> {
    let mode = config.mode;
    let limits = &config.limits;
    match tool {
        Tool::Ping => Ok(Op::Ping),
        Tool::FsRead => {
            let raw = str_param(params, "path")?;
            let max_bytes = params
                .get("max_bytes")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(limits.fs_max_read_bytes)
                .min(limits.fs_max_read_bytes);
            let target = resolve_fs(mode, workspace, raw, true)?;
            Ok(Op::FsRead { target, max_bytes })
        }
        Tool::FsWrite => {
            let raw = str_param(params, "path")?;
            let data = str_param(params, "data")?.as_bytes().to_vec();
            if data.len() > limits.fs_max_write_bytes {
                return Err(format!(
                    "write of {} bytes exceeds limit of {}",
                    data.len(),
                    limits.fs_max_write_bytes
                ));
            }
            let create_dirs = params
                .get("create_dirs")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let target = resolve_fs(mode, workspace, raw, false)?;
            Ok(Op::FsWrite {
                target,
                data,
                create_dirs,
            })
        }
        Tool::Exec => {
            let cmd = str_param(params, "cmd")?;
            let program = match programs
                .iter()
                .find(|p| p.name == cmd || p.path.to_str() == Some(cmd))
            {
                Some(p) => p.clone(),
                None if mode == Mode::Permissive => ResolvedProgram {
                    name: cmd.to_string(),
                    path: PathBuf::from(cmd),
                    kind: ProgramKind::Plain,
                    toolchain_root: None,
                },
                None => return Err(format!("program '{cmd}' is not available to cells")),
            };
            let args = match params.get("args") {
                None => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|v| v.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
                    .ok_or("exec args must be strings")?,
                Some(_) => return Err("exec args must be an array".into()),
            };
            if args.len() > limits.exec_max_args {
                return Err(format!("too many arguments (max {})", limits.exec_max_args));
            }
            if args
                .iter()
                .any(|a| a.len() > limits.exec_max_arg_len || a.contains('\0'))
            {
                return Err("argument too long or contains NUL".into());
            }
            let cwd_raw = params.get("cwd").and_then(Value::as_str).unwrap_or(".");
            let cwd = resolve_fs(mode, workspace, cwd_raw, true)?.path;
            if !cwd.is_dir() {
                return Err("cwd is not a directory".into());
            }
            let timeout_ms = params
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(limits.exec_timeout_ms)
                .min(limits.exec_timeout_ms);
            Ok(Op::Exec {
                program,
                args,
                cwd,
                timeout_ms,
            })
        }
        Tool::NetHttp => {
            let url = Url::parse(str_param(params, "url")?).map_err(|e| format!("bad url: {e}"))?;
            let method = params
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_ascii_uppercase();
            let allowed: &[&str] = if mode == Mode::Permissive {
                &["GET", "POST", "PUT", "DELETE"]
            } else {
                &["GET", "POST"]
            };
            if !allowed.contains(&method.as_str()) {
                return Err(format!("method {method} is not supported"));
            }
            let mut headers = Vec::new();
            if let Some(obj) = params.get("headers").and_then(Value::as_object) {
                for (k, v) in obj {
                    let v = v.as_str().ok_or("header values must be strings")?;
                    headers.push((k.clone(), v.to_string()));
                }
            }
            let body = params
                .get("body")
                .and_then(Value::as_str)
                .map(str::to_string);
            if body.as_ref().map_or(0, String::len) > limits.net_max_request_bytes {
                return Err("request body too large".into());
            }
            let timeout_ms = params
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(limits.net_timeout_ms)
                .min(limits.net_timeout_ms);
            Ok(Op::Net {
                url,
                method,
                headers,
                body,
                timeout_ms,
            })
        }
    }
}

fn str_param<'a>(params: &'a Value, name: &str) -> Result<&'a str, String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string parameter '{name}'"))
}

fn resolve_fs(
    mode: Mode,
    workspace: &Path,
    raw: &str,
    must_exist: bool,
) -> Result<FsTarget, String> {
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err("empty path or path with control characters".into());
    }
    let requested = Path::new(raw);
    let path = match mode {
        Mode::Ztac => resolve_physical(workspace, requested, must_exist)?,
        Mode::Allowlist | Mode::CommandSandbox => {
            // Lexical check typical of tool allowlists: relative, no `..`.
            if requested.is_absolute()
                || requested
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
            {
                return Err("path must be relative and must not contain '..'".into());
            }
            workspace.join(requested)
        }
        Mode::Permissive => {
            if requested.is_absolute() {
                requested.to_path_buf()
            } else {
                workspace.join(requested)
            }
        }
    };
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(&path).ok();
    let multiply_linked = meta.as_ref().is_some_and(|m| m.is_file() && m.nlink() > 1);
    let ident = meta.as_ref().map(|m| (m.dev(), m.ino()));
    let rel = path
        .strip_prefix(workspace)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(FsTarget {
        path,
        rel,
        raw: raw.to_string(),
        cell_originated: false,
        multiply_linked,
        ident,
    })
}

/// Resolves `requested` against the workspace the way the kernel would when
/// opening it: symlinks in the existing prefix are followed, and the result
/// must lie inside the workspace. Components that do not exist yet are
/// appended literally and may not be `..`.
pub fn resolve_physical(
    workspace: &Path,
    requested: &Path,
    must_exist: bool,
) -> Result<PathBuf, String> {
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };

    let resolved = if must_exist {
        candidate
            .canonicalize()
            .map_err(|e| format!("cannot resolve path: {e}"))?
    } else {
        let mut existing = candidate.clone();
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        while existing.symlink_metadata().is_err() {
            let name = existing
                .file_name()
                .ok_or("path contains '..' below a missing directory")?
                .to_os_string();
            tail.push(name);
            existing = existing
                .parent()
                .ok_or("path has no existing ancestor")?
                .to_path_buf();
        }
        let mut base = existing
            .canonicalize()
            .map_err(|e| format!("cannot resolve path (dangling symlink?): {e}"))?;
        for name in tail.iter().rev() {
            base.push(name);
        }
        base
    };

    if !resolved.starts_with(workspace) {
        return Err(format!(
            "path resolves outside the workspace ({})",
            resolved.display()
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn ws() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("ztac-resolve-{}", uuid::Uuid::new_v4()));
        let ws = base.join("ws");
        std::fs::create_dir_all(ws.join("sub")).unwrap();
        std::fs::write(base.join("outside.txt"), "x").unwrap();
        std::fs::write(ws.join(".env"), "SECRET").unwrap();
        (base, ws)
    }

    #[test]
    fn traversal_and_absolute_escape_rejected() {
        let (base, ws) = ws();
        assert!(resolve_physical(&ws, Path::new("../outside.txt"), true).is_err());
        assert!(resolve_physical(&ws, &base.join("outside.txt"), true).is_err());
        assert!(resolve_physical(&ws, Path::new("sub/../../x"), false).is_err());
        assert!(resolve_physical(&ws, Path::new("new/../../x"), false).is_err());
    }

    #[test]
    fn symlinks_resolve_to_their_targets() {
        let (base, ws) = ws();
        symlink(base.join("outside.txt"), ws.join("link_out")).unwrap();
        symlink(ws.join(".env"), ws.join("notes.txt")).unwrap();
        symlink(&base, ws.join("dirlink")).unwrap();
        assert!(resolve_physical(&ws, Path::new("link_out"), true).is_err());
        assert!(resolve_physical(&ws, Path::new("dirlink/new.txt"), false).is_err());
        let p = resolve_physical(&ws, Path::new("notes.txt"), true).unwrap();
        assert_eq!(p, ws.join(".env"));
    }

    #[test]
    fn new_paths_inside_workspace_accepted() {
        let (_base, ws) = ws();
        let p = resolve_physical(&ws, Path::new("a/b/c.txt"), false).unwrap();
        assert_eq!(p, ws.join("a/b/c.txt"));
    }
}

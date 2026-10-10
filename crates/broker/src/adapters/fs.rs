use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

use crate::config::{BrokerConfig, Mode};
use crate::resolve::FsTarget;

// In ZTAC mode the adapters never open a path string. They open the workspace
// directory and walk the resolved, workspace-relative path one component at a
// time with openat(2) and O_NOFOLLOW, so a symlink or directory swapped in
// after resolution makes the operation fail instead of redirecting it. The
// object reached is then compared with the one the policy classified.

fn openat(dir: &File, name: &str, flags: i32, mode: libc::c_uint) -> std::io::Result<File> {
    let c =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `dir` is an open directory and `c` is a valid C string.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nobody else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn components(rel: &str) -> anyhow::Result<Vec<&str>> {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        anyhow::bail!("target is not a workspace file");
    }
    Ok(parts)
}

/// Opens the directory that holds `parts.last()`, creating missing
/// directories when `create` is set.
fn walk_to_parent(workspace: &Path, parts: &[&str], create: bool) -> anyhow::Result<File> {
    let dir_flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let root = std::ffi::CString::new(workspace.as_os_str().as_bytes())?;
    // SAFETY: `root` is a valid C string.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            dir_flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open workspace");
    }
    // SAFETY: `fd` was just returned by open.
    let mut dir = unsafe { File::from_raw_fd(fd) };
    for name in &parts[..parts.len() - 1] {
        dir = match openat(&dir, name, dir_flags, 0) {
            Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                let c = CString::new(*name)?;
                // SAFETY: `dir` is an open directory and `c` is a valid C string.
                if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
                    return Err(std::io::Error::last_os_error()).context("mkdirat");
                }
                openat(&dir, name, dir_flags, 0)?
            }
            r => r.with_context(|| format!("open directory {name}"))?,
        };
    }
    Ok(dir)
}

/// Compares the directory entry `name` (not following a symlink) with the
/// identity recorded at authorization.
fn check_entry(dir: &File, name: &CString, target: &FsTarget) -> anyhow::Result<()> {
    // SAFETY: zeroed stat is a valid out-parameter for fstatat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is open, `name` is a valid C string, `st` is writable.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let now = if rc == 0 {
        Some((st.st_dev as u64, st.st_ino as u64))
    } else {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).context("fstatat");
        }
        None
    };
    if now != target.ident {
        anyhow::bail!("target changed between authorization and use");
    }
    Ok(())
}

fn same_object(target: &FsTarget, file: &File) -> anyhow::Result<()> {
    let m = file.metadata()?;
    if target.ident.is_some_and(|id| id != (m.dev(), m.ino())) {
        anyhow::bail!("file changed between authorization and use");
    }
    Ok(())
}

pub fn read(
    config: &BrokerConfig,
    workspace: &Path,
    target: &FsTarget,
    max_bytes: usize,
) -> anyhow::Result<Value> {
    let file = if config.mode == Mode::Ztac && config.defenses.fd_walk {
        let parts = components(&target.rel)?;
        let dir = walk_to_parent(workspace, &parts, false)?;
        // O_NONBLOCK keeps a FIFO planted in the workspace from stalling the
        // broker; only regular files are read.
        let f = openat(
            &dir,
            parts[parts.len() - 1],
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .with_context(|| format!("open {}", target.rel))?;
        if !f.metadata()?.is_file() {
            anyhow::bail!("{} is not a regular file", target.rel);
        }
        same_object(target, &f)?;
        f
    } else {
        File::open(&target.path).with_context(|| format!("open {}", target.path.display()))?
    };
    let mut bytes = Vec::new();
    file.take(max_bytes as u64).read_to_end(&mut bytes)?;
    let n = bytes.len();
    let (encoding, content) = match String::from_utf8(bytes) {
        Ok(s) => ("utf8", s),
        Err(e) => ("base64", STANDARD.encode(e.into_bytes())),
    };
    Ok(
        serde_json::json!({"path": target.rel, "bytes": n, "encoding": encoding, "content": content}),
    )
}

pub fn write(
    config: &BrokerConfig,
    workspace: &Path,
    target: &FsTarget,
    data: &[u8],
    create_dirs: bool,
) -> anyhow::Result<Value> {
    if config.mode != Mode::Ztac || !config.defenses.fd_walk {
        if create_dirs {
            if let Some(parent) = target.path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&target.path, data)?;
        return Ok(serde_json::json!({"path": target.rel, "bytes": data.len()}));
    }

    // Write a temporary file in the target's directory, then rename it over
    // the target. renameat(2) replaces a symlink at the destination rather
    // than following it.
    let parts = components(&target.rel)?;
    let dir = walk_to_parent(workspace, &parts, create_dirs)?;
    let name = CString::new(parts[parts.len() - 1])?;
    let tmp_name = format!(".ztac-tmp-{}", uuid::Uuid::new_v4());
    let mut file = openat(
        &dir,
        &tmp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o644,
    )?;
    file.write_all(data)?;
    file.sync_all()?;
    let tmp = CString::new(tmp_name)?;
    // The entry being replaced must be the object that was authorized, and a
    // file that did not exist at authorization must not exist now.
    if let Err(e) = check_entry(&dir, &name, target) {
        // SAFETY: as below.
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        return Err(e);
    }
    // SAFETY: both names are valid C strings relative to the open directory.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            tmp.as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        return Err(e).context("rename");
    }
    Ok(serde_json::json!({"path": target.rel, "bytes": data.len()}))
}

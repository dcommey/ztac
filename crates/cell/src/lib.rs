//! Cell confinement: the Seatbelt profile an agent runs under.

use std::path::{Path, PathBuf};

use ztac_core::seatbelt::Profile;

/// Profile for an agent cell. The cell can load its own code, read its key,
/// and connect to the broker socket. It has no other file access, no network,
/// cannot signal or inspect other processes, and cannot execute anything
/// except the programs listed in `exec`.
pub fn cell_profile(
    socket: &Path,
    key: &Path,
    exec: &[PathBuf],
    extra_read: &[PathBuf],
) -> Profile {
    let mut p = Profile::base();
    p.read_literals.push(key.to_path_buf());
    p.unix_sockets.push(socket.to_path_buf());
    for e in exec {
        p.exec_literals.push(e.clone());
        p.read_literals.push(e.clone());
    }
    p.read_subpaths.extend(extra_read.iter().cloned());
    p
}

//! Launches an agent process inside a cell.
//!
//! usage: ztac-cell --socket S --key K [--read DIR]... [--exec BIN]...
//!                  [--print-profile] -- PROGRAM [ARGS...]

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use ztac_core::seatbelt::SANDBOX_EXEC;

fn canonical(p: &str) -> anyhow::Result<PathBuf> {
    PathBuf::from(p)
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("{p}: {e}"))
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (mut socket, mut key) = (None, None);
    let (mut reads, mut execs) = (Vec::new(), Vec::new());
    let mut print_profile = false;
    let mut program = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next(),
            "--key" => key = args.next(),
            "--read" => reads.push(canonical(&args.next().unwrap_or_default())?),
            "--exec" => execs.push(canonical(&args.next().unwrap_or_default())?),
            "--print-profile" => print_profile = true,
            "--" => {
                program.extend(args.by_ref());
                break;
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let socket = socket.ok_or_else(|| anyhow::anyhow!("--socket is required"))?;
    let key = canonical(&key.ok_or_else(|| anyhow::anyhow!("--key is required"))?)?;
    // The socket's directory is canonicalized; the socket itself may not exist yet.
    let socket = {
        let p = PathBuf::from(&socket);
        let dir = p
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .canonicalize()?;
        dir.join(
            p.file_name()
                .ok_or_else(|| anyhow::anyhow!("bad socket path"))?,
        )
    };
    let Some(first) = program.first() else {
        anyhow::bail!("no program given after --");
    };
    let bin = canonical(first)?;
    if !execs.contains(&bin) {
        execs.push(bin.clone());
    }

    let profile = ztac_cell::cell_profile(&socket, &key, &execs, &reads).render();
    if print_profile {
        print!("{profile}");
        return Ok(());
    }
    let err = Command::new(SANDBOX_EXEC)
        .arg("-p")
        .arg(&profile)
        .arg(&bin)
        .args(&program[1..])
        .env_clear()
        .env("ZTAC_SOCKET", &socket)
        .env("ZTAC_KEY", &key)
        .env("PATH", "/usr/bin:/bin")
        .exec();
    Err(err.into())
}

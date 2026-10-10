use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;
use wait_timeout::ChildExt;
use ztac_core::seatbelt::{Profile, SANDBOX_EXEC};

use crate::config::{Access, BrokerConfig, Mode, ProgramKind, RuleAction};
use crate::glob;
use crate::policy::Policy;
use crate::programs::ResolvedProgram;

/// Configuration pinned on every git invocation under vcs_guard. Command-line
/// configuration has the highest precedence, so repository-local settings
/// cannot re-enable these hooks.
pub const GIT_PINNED_CONFIG: &[&str] = &[
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.pager=cat",
    "core.editor=false",
    "core.sshCommand=false",
    "core.askPass=",
    "credential.helper=",
    "safe.bareRepository=explicit",
    "protocol.allow=never",
    "protocol.file.allow=always",
    "commit.gpgSign=false",
    "tag.gpgSign=false",
    "gc.auto=0",
    "maintenance.auto=false",
];

#[allow(clippy::too_many_arguments)]
pub fn run(
    config: &BrokerConfig,
    policy: &Policy,
    workspace: &Path,
    cell_id: &str,
    program: &ResolvedProgram,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    exempt: &[std::path::PathBuf],
) -> anyhow::Result<Value> {
    let d = &config.defenses;
    let ztac = config.mode == Mode::Ztac;

    // Each cell gets a private temporary directory beside the workspaces.
    let tmpdir = cell_tmpdir(workspace);
    let command_sandbox = config.mode == Mode::CommandSandbox;
    if ztac || command_sandbox {
        std::fs::create_dir_all(&tmpdir)?;
    }

    let mut argv: Vec<String> = Vec::new();
    if ztac && d.vcs_guard && program.kind == ProgramKind::Git {
        for kv in GIT_PINNED_CONFIG {
            argv.push("-c".into());
            argv.push((*kv).into());
        }
    }
    argv.extend(args.iter().cloned());
    // External diff and textconv drivers come from repository configuration
    // and run arbitrary commands. These subcommands accept options to ignore
    // them; they are inserted right after the subcommand.
    if ztac && d.vcs_guard && program.kind == ProgramKind::Git {
        let sub = 2 * GIT_PINNED_CONFIG.len();
        if matches!(
            argv.get(sub).map(String::as_str),
            Some("diff" | "show" | "log")
        ) {
            argv.insert(sub + 1, "--no-ext-diff".into());
            argv.insert(sub + 2, "--no-textconv".into());
        }
    }

    let mut cmd = if ztac && d.exec_sandbox {
        let mut sp = exec_profile(policy, workspace, program, d.sandbox_rules);
        sp.base.allow_fork = !d.no_fork;
        sp.base.read_subpaths.push(tmpdir.clone());
        sp.base.write_subpaths.push(tmpdir.clone());
        for p in exempt {
            sp.denies.push(format!(
                "(allow file-read* (literal {}))",
                ztac_core::seatbelt::quote(p)
            ));
        }
        let profile = sp.render();
        let mut c = Command::new(SANDBOX_EXEC);
        c.arg("-p").arg(profile).arg(&program.path);
        c
    } else if command_sandbox {
        let mut c = Command::new(SANDBOX_EXEC);
        c.arg("-p")
            .arg(command_sandbox_profile(workspace, &tmpdir).render())
            .arg(&program.path);
        c
    } else {
        Command::new(&program.path)
    };
    cmd.args(&argv)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if config.mode != Mode::Permissive {
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin");
        cmd.env("LANG", "C.UTF-8");
        let ident = format!("{cell_id}@ztac.invalid");
        for (k, v) in [
            ("GIT_AUTHOR_NAME", cell_id),
            ("GIT_COMMITTER_NAME", cell_id),
            ("GIT_AUTHOR_EMAIL", ident.as_str()),
            ("GIT_COMMITTER_EMAIL", ident.as_str()),
        ] {
            cmd.env(k, v);
        }
    }
    if ztac {
        cmd.env("HOME", workspace);
        cmd.env("TMPDIR", &tmpdir);
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        if d.vcs_guard && program.kind == ProgramKind::Git {
            cmd.env("GIT_DIR", workspace.join(".git"));
            cmd.env("GIT_WORK_TREE", workspace);
            cmd.env("GIT_CONFIG_NOSYSTEM", "1");
            cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
            cmd.env("GIT_TERMINAL_PROMPT", "0");
            // Make git itself refuse abbreviated long options.
            cmd.env("GIT_TEST_DISALLOW_ABBREVIATED_OPTIONS", "1");
        }
    }

    let mut child = cmd.spawn()?;
    // Drain pipes on threads so a chatty child cannot block on a full pipe.
    let max = config.limits.exec_max_output_bytes;
    let out = child
        .stdout
        .take()
        .map(|s| std::thread::spawn(move || read_capped(s, max)));
    let err = child
        .stderr
        .take()
        .map(|s| std::thread::spawn(move || read_capped(s, max)));
    let status = match child.wait_timeout(Duration::from_millis(timeout_ms))? {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("timed out after {timeout_ms} ms");
        }
    };
    let (stdout, out_trunc) = out
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    let (stderr, err_trunc) = err
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    Ok(serde_json::json!({
        "exit_code": status.code(),
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
        "truncated": out_trunc || err_trunc,
    }))
}

/// `<workspace_root>/.tmp/<cell_id>`.
pub fn cell_tmpdir(workspace: &Path) -> std::path::PathBuf {
    let root = workspace.parent().unwrap_or(workspace);
    let cell = workspace.file_name().unwrap_or_default();
    root.join(".tmp").join(cell)
}

fn read_capped<R: Read>(r: R, max: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut r = r;
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = max.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
                if n > room {
                    truncated = true;
                }
            }
        }
    }
    (buf, truncated)
}

/// Path rules cannot distinguish names of the same inode. A repository can
/// arrive with a harmless-looking hard link to a protected file before the
/// broker starts. Until command execution has inode-aware enforcement, refuse
/// to launch any command from such a workspace. Symlinks are not traversed;
/// the exec profile and the broker's own resolver handle them separately.
pub fn reject_multiply_linked_workspace_files(workspace: &Path) -> anyhow::Result<()> {
    let mut pending = vec![workspace.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() && meta.nlink() > 1 {
                anyhow::bail!(
                    "command refused: multiply linked file {} has aliases unknown to path rules",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Builds the Seatbelt profile for a spawned program: system libraries and
/// the program's toolchain are readable, the workspace is readable and
/// writable, and the broker's own path rules are compiled into deny rules so a
/// spawned program cannot reach what a direct request could not. There is no
/// network access and no process execution outside the toolchain.
pub fn exec_profile(
    policy: &Policy,
    workspace: &Path,
    program: &ResolvedProgram,
    rules: bool,
) -> SandboxProfile {
    let mut p = Profile::base();
    // No process creation: a spawned program cannot leave a background
    // process that keeps changing the workspace after the request returns.
    p.allow_fork = false;
    p.read_literals.push(program.path.clone());
    p.exec_literals.push(program.path.clone());
    if let Some(root) = &program.toolchain_root {
        p.read_subpaths.push(root.clone());
        p.exec_subpaths.push(root.clone());
    }
    p.read_subpaths.push(workspace.to_path_buf());
    p.write_subpaths.push(workspace.to_path_buf());

    let ws = workspace.to_string_lossy().into_owned();
    let mut denies = Vec::new();
    if rules {
        // The broker applies the first matching rule. In SBPL the last
        // matching clause wins, so the rules are emitted in reverse order, and
        // allow rules become allow clauses: a path gets the same answer from
        // both enforcement points.
        for c in policy.rules.iter().rev() {
            let allow = c.rule.action == RuleAction::Allow;
            // A rule that restricts reads also restricts writes: link(2) and
            // rename(2) are checked as writes on the source path, so this
            // stops a program from giving a protected file a new name.
            let ops = match (c.rule.access, allow) {
                (Access::Read, true) => "file-read*",
                (Access::Write, _) => "file-write*",
                _ => "file-read* file-write*",
            };
            let verb = if allow { "allow" } else { "deny" };
            denies.push(format!(
                "({verb} {ops} (regex #\"{}\"))",
                glob::sbpl_regex(&ws, &c.rule.pattern)
            ));
        }
        // Renaming a directory changes the path of everything below it, so
        // directories named by a restricting rule (such as .github in
        // **/.github/**) cannot be created, renamed, or removed. These clauses
        // come last and are stricter than the broker on purpose.
        for c in policy
            .rules
            .iter()
            .filter(|c| c.rule.action != RuleAction::Allow)
        {
            for dir in glob::named_dir_prefixes(&c.rule.pattern) {
                denies.push(format!(
                    "(deny file-write* (regex #\"{}\"))",
                    glob::sbpl_regex(&ws, &dir)
                ));
            }
        }
    }
    let ws_re = glob::escape_literal(&ws);
    if program.kind == ProgramKind::Git {
        // git maintains HEAD files in its own metadata directory (`HEAD`,
        // `logs/HEAD`); the rule on HEAD files is aimed at look-alike
        // repositories elsewhere in the workspace.
        denies.push(format!(
            "(allow file-write* (regex #\"^{ws_re}/\\.git/(.*/)?HEAD$\"))"
        ));
    } else {
        denies.push(format!(
            "(deny file-write* (regex #\"^{ws_re}/(.*/)?\\.[gG][iI][tT](/.*)?$\"))"
        ));
    }
    SandboxProfile { base: p, denies }
}

/// Profile of the command-sandbox baseline: read and execute anywhere,
/// create processes, write only the workspace and a temporary directory, and
/// no network. It has no knowledge of the broker's path rules.
pub fn command_sandbox_profile(workspace: &Path, tmpdir: &Path) -> Profile {
    let mut p = Profile::base();
    p.allow_fork = true;
    p.read_subpaths.push("/".into());
    p.exec_subpaths.push("/".into());
    p.write_subpaths.push(workspace.to_path_buf());
    p.write_subpaths.push(tmpdir.to_path_buf());
    p
}

pub struct SandboxProfile {
    pub base: Profile,
    /// Rules appended after the allows; in SBPL the last matching rule wins.
    pub denies: Vec<String>,
}

impl SandboxProfile {
    pub fn render(&self) -> String {
        let mut s = self.base.render();
        for d in &self.denies {
            s.push_str(d);
            s.push('\n');
        }
        s
    }
}

//! Empirical path-rule agreement, using broker requests and actual Seatbelt
//! file opens. Differences due to deliberate strengthenings are explicit.
use std::fs;
use std::process::Command;

use crate::env::Env;
use serde::Serialize;
use serde_json::json;
use ztac_broker::config::{Access, FsRule, RuleAction};
use ztac_broker::{adapters::exec::exec_profile, policy::Policy, programs};
use ztac_core::seatbelt::SANDBOX_EXEC;
use ztac_core::{Decision, Tool};

#[derive(Serialize)]
pub struct Check {
    path: String,
    access: &'static str,
    broker: Decision,
    sandbox_permitted: bool,
    expected_broker: Decision,
    expected_sandbox: bool,
    difference: &'static str,
    pub passed: bool,
}

pub fn run(env: &mut Env) -> anyhow::Result<Vec<Check>> {
    // Overlaps and access-specific rules complement the default .env.example
    // exception. The expectations below are specified independently of the
    // compiler and policy matcher.
    let mut custom = vec![
        FsRule {
            pattern: "overlap/allowed.*".into(),
            access: Access::Any,
            action: RuleAction::Allow,
        },
        FsRule {
            pattern: "overlap/**".into(),
            access: Access::Any,
            action: RuleAction::Deny,
        },
        FsRule {
            pattern: "read-only.dat".into(),
            access: Access::Read,
            action: RuleAction::Approve,
        },
        FsRule {
            pattern: "write-only.dat".into(),
            access: Access::Write,
            action: RuleAction::Approve,
        },
        FsRule {
            pattern: "denied.dat".into(),
            access: Access::Any,
            action: RuleAction::Deny,
        },
    ];
    custom.extend(env.config.fs_rules.clone());
    env.config.fs_rules = custom;
    fs::write(&env.config_path, serde_json::to_vec_pretty(&env.config)?)?;
    env.restart_broker()?;
    let policy = Policy::new(&env.config)?;
    let programs = programs::resolve_all(&env.config.programs)?;
    let python = programs.iter().find(|p| p.name == "python3").unwrap();
    let profile = exec_profile(&policy, &env.ws_a, python, true).render();
    let mut rows = Vec::new();
    use Decision::{Allow as A, Deny as D, NeedsApproval as N};
    // (path, broker-read, broker-write, sandbox-read, sandbox-write, difference)
    let cases = [
        ("ordinary.txt", A, A, true, true, ""),
        ("nested/deep/plain.txt", A, A, true, true, ""),
        ("quote\"name.txt", A, A, true, true, ""),
        (".env", N, N, false, false, ""),
        ("nested/.env.local", N, N, false, false, ""),
        ("nested/.ENV.LOCAL", N, N, false, false, ""),
        (".env.example", A, A, true, true, ""),
        ("nested/.ENV.EXAMPLE", A, A, true, true, ""),
        ("cert.pem.sample", A, A, true, true, ""),
        ("cert.pem", N, N, false, false, ""),
        ("id_ed25519.pub", N, N, false, false, ""),
        ("scripts/release.sh", A, N, true, false, ""),
        (".github/workflows/ci.yml", A, N, true, false, ""),
        (".VSCode/tasks.json", A, N, true, false, ""),
        (".claude/settings.json", A, N, true, false, ""),
        ("tools/HEAD", A, N, true, false, ""),
        ("venv/pyvenv.cfg", A, N, true, false, ""),
        ("venv/bin/python3", A, N, true, false, ""),
        ("overlap/allowed.txt", A, A, true, true, ""),
        ("overlap/blocked.txt", D, D, false, false, ""),
        (
            "read-only.dat",
            N,
            A,
            false,
            false,
            "read restriction also prevents renaming",
        ),
        ("write-only.dat", A, N, true, false, ""),
        ("denied.dat", D, D, false, false, ""),
        (".git/config", A, D, true, false, ""),
        (
            "line\nbreak/.env",
            D,
            D,
            false,
            false,
            "broker rejects control characters",
        ),
        (
            "line\nbreak/plain.txt",
            D,
            D,
            true,
            true,
            "broker rejects control characters",
        ),
    ];
    for (rel, br, bw, sr, sw, difference) in cases {
        let path = env.ws_a.join(rel);
        fs::create_dir_all(path.parent().unwrap())?;
        // Do not damage the provisioned repository config.
        if !path.exists() {
            fs::write(&path, "agreement canary")?;
        }
        for (write, expected_broker, expected_sandbox) in [(false, br, sr), (true, bw, sw)] {
            let code = if write {
                "import sys; f=open(sys.argv[1], 'r+'); f.close(); print('permitted')"
            } else {
                "import sys; f=open(sys.argv[1], 'r'); f.read(1); f.close(); print('permitted')"
            };
            let o = Command::new(SANDBOX_EXEC)
                .args(["-p", &profile])
                .arg(&python.path)
                .args(["-c", code])
                .arg(&path)
                .current_dir(&env.ws_a)
                .output()?;
            let sandbox_permitted = o.status.success() && o.stdout == b"permitted\n";
            // A failed launch is not evidence that access was denied.
            anyhow::ensure!(
                sandbox_permitted || String::from_utf8_lossy(&o.stderr).contains("PermissionError"),
                "Seatbelt probe failed for {rel:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            let r = if write {
                env.call(
                    Tool::FsWrite,
                    json!({"path": rel, "data": "agreement canary"}),
                )
            } else {
                env.call(Tool::FsRead, json!({"path": rel}))
            };
            anyhow::ensure!(!r.reason.starts_with("transport error:"), "{}", r.reason);
            let passed = r.decision == expected_broker
                && sandbox_permitted == expected_sandbox
                && (r.decision != A || r.result.as_ref().is_some_and(|v| v["ok"] == true));
            rows.push(Check {
                path: rel.into(),
                access: if write { "write" } else { "read" },
                broker: r.decision,
                sandbox_permitted,
                expected_broker,
                expected_sandbox,
                difference,
                passed,
            });
        }
    }
    // Directory guards are deliberately appended after allow exceptions.
    let dir = env.ws_a.join(".github");
    let o = Command::new(SANDBOX_EXEC)
        .args(["-p", &profile])
        .arg(&python.path)
        .args([
            "-c",
            "import os, sys; os.rename(sys.argv[1], sys.argv[2]); print('permitted')",
        ])
        .arg(&dir)
        .arg(env.ws_a.join("moved-ci"))
        .output()?;
    anyhow::ensure!(
        !o.status.success() && String::from_utf8_lossy(&o.stderr).contains("PermissionError"),
        "directory rename guard failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    eprintln!(
        "policy agreement: {} path/access checks passed; directory rename denied",
        rows.iter().filter(|r| r.passed).count()
    );
    Ok(rows)
}

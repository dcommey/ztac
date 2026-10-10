//! Evaluation driver.
//!
//! usage: ztac-eval <security|utility|bench|all> [--out DIR] [--scale F] [--only SETUP]
//!        ztac-eval profile --only WORKSPACE   (print the exec-sandbox profile for python3)

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use ztac_broker::config::{Defenses, Mode};
use ztac_eval::attacks::{corpus, run_attack, Outcome};
use ztac_eval::bench;
use ztac_eval::env::{Env, Setup};
use ztac_eval::services::Services;
use ztac_eval::{agreement, utility};

fn race(base: &Path, out: &Path, svc: &Services, repeats: usize) -> anyhow::Result<()> {
    let attack = corpus()
        .into_iter()
        .find(|a| a.id == "exec-py-race")
        .unwrap();
    let mut rows = Vec::new();
    for s in setups().into_iter().filter(|s| {
        matches!(
            s.label.as_str(),
            "B0-unconfined"
                | "ZTAC"
                | "ZTAC-no-fd_walk"
                | "ZTAC-no-no_fork"
                | "ZTAC-no-fd_walk+no_fork"
        )
    }) {
        let mut env = Env::start(base, s.clone())?;
        for trial in 1..=repeats {
            let r = run_attack(&mut env, svc, &attack);
            eprintln!("race {} trial {trial}/{repeats}: {:?}", s.label, r.outcome);
            rows.push(serde_json::json!({"trial": trial, "result": r}));
        }
    }
    write_jsonl(&out.join("race.jsonl"), &rows)
}

fn setups() -> Vec<Setup> {
    let mut v = vec![
        Setup::new("B0-unconfined", Mode::Permissive, Defenses::none(), false),
        Setup::new("B1-allowlist", Mode::Allowlist, Defenses::none(), false),
        Setup::new(
            "B2-command-sandbox",
            Mode::CommandSandbox,
            Defenses::none(),
            false,
        ),
        Setup::new("ZTAC-broker-only", Mode::Ztac, Defenses::default(), false),
        Setup::new("ZTAC", Mode::Ztac, Defenses::default(), true),
    ];
    for name in Defenses::NAMES {
        let mut d = Defenses::default();
        d.set(name, false);
        v.push(Setup::new(&format!("ZTAC-no-{name}"), Mode::Ztac, d, true));
    }
    // The two exec-side defenses overlap; removing both shows what either
    // one alone prevents.
    let d = Defenses {
        vcs_guard: false,
        exec_sandbox: false,
        ..Defenses::default()
    };
    v.push(Setup::new(
        "ZTAC-no-vcs_guard+exec_sandbox",
        Mode::Ztac,
        d,
        true,
    ));
    // The descriptor walk and the ban on process creation both defeat the
    // directory-swap race; removing both shows what either one prevents.
    let d = Defenses {
        fd_walk: false,
        no_fork: false,
        ..Defenses::default()
    };
    v.push(Setup::new("ZTAC-no-fd_walk+no_fork", Mode::Ztac, d, true));
    v
}

fn write_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> anyhow::Result<()> {
    let mut f = fs::File::create(path)?;
    for r in rows {
        writeln!(f, "{}", serde_json::to_string(r)?)?;
    }
    Ok(())
}

fn security(base: &Path, out: &Path, svc: &Services, only: &Option<String>) -> anyhow::Result<()> {
    let mut attacks = corpus();
    // ZTAC_ATTACKS=id1,id2 restricts the run to some attacks (development aid).
    if let Ok(sel) = std::env::var("ZTAC_ATTACKS") {
        let sel: Vec<&str> = sel.split(',').collect();
        attacks.retain(|a| sel.contains(&a.id));
    }
    let mut rows = Vec::new();
    for s in setups() {
        if only.as_ref().is_some_and(|o| s.label != *o) {
            continue;
        }
        let mut env = Env::start(base, s.clone())?;
        let (mut ok, mut esc, mut blk, mut inv) = (0, 0, 0, 0);
        for a in &attacks {
            let r = run_attack(&mut env, svc, a);
            match r.outcome {
                Outcome::Succeeded => ok += 1,
                Outcome::Escalated => esc += 1,
                Outcome::Blocked => blk += 1,
                Outcome::Invalid => inv += 1,
            }
            rows.push(r);
        }
        eprintln!(
            "{:28} succeeded {ok:2}  escalated {esc:2}  blocked {blk:2}  invalid {inv}",
            s.label
        );
    }
    write_jsonl(&out.join("security.jsonl"), &rows)?;
    let expected: Vec<_> = attacks
        .iter()
        .map(|a| serde_json::json!({"id": a.id, "category": a.category, "goal": a.goal, "description": a.description, "expected": a.expected}))
        .collect();
    fs::write(
        out.join("attacks.json"),
        serde_json::to_string_pretty(&expected)?,
    )?;
    Ok(())
}

fn utility_run(
    base: &Path,
    out: &Path,
    svc: &Services,
    only: &Option<String>,
) -> anyhow::Result<()> {
    let mut rows = Vec::new();
    let mut workflows = Vec::new();
    for s in setups() {
        if only.as_ref().is_some_and(|o| s.label != *o) {
            continue;
        }
        let mut env = Env::start(base, s.clone())?;
        let res = utility::run(&mut env, svc);
        let done = res.iter().filter(|r| r.completed).count();
        let prompts: usize = res.iter().map(|r| r.prompts).sum();
        eprintln!(
            "{:28} completed {done:2}/{}  prompts {prompts}",
            s.label,
            res.len()
        );
        for r in res.iter().filter(|r| !r.completed) {
            eprintln!("    failed {}: {}", r.id, r.reason);
        }
        rows.extend(res);
        workflows.extend(utility::run_workflows(&mut env, svc)?);
    }
    write_jsonl(&out.join("utility.jsonl"), &rows)?;
    write_jsonl(&out.join("workflows.jsonl"), &workflows)
}

fn bench_run(base: &Path, out: &Path, scale: f64) -> anyhow::Result<()> {
    let mut samples = Vec::new();
    let mut env = Env::start(
        base,
        Setup::new("bench-ztac", Mode::Ztac, Defenses::default(), true),
    )?;
    bench::prepare(&env)?;
    let git = which("git")?;
    let python = which("python3")?;
    for op in bench::ops(scale) {
        samples.push(bench::direct(&env, &op, &git, &python));
        samples.push(bench::brokered(&mut env, &op));
        eprintln!("bench {} done", op.name);
    }
    samples.extend(bench::cell_launch(&env, (100.0 * scale).max(10.0) as usize));
    let fs_read = bench::ops(scale)
        .into_iter()
        .find(|o| o.name == "fs_read_4k")
        .unwrap();
    let mut tput = Vec::new();
    for c in [1, 2, 4, 8, 16] {
        tput.push(bench::throughput(&env, &fs_read, c, 3.0 * scale.min(1.0)));
    }
    let t = std::time::Instant::now();
    let report = ztac_broker::audit::verify(
        &env.config.audit_path(),
        &ztac_core::keys::load_key(&env.config.signing_key_path())?.verifying_key(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let verify_s = t.elapsed().as_secs_f64();
    drop(env);

    // Exec sandbox cost in isolation: the same broker without it.
    let d = Defenses {
        exec_sandbox: false,
        ..Defenses::default()
    };
    let mut env = Env::start(
        base,
        Setup::new("bench-no-exec-sandbox", Mode::Ztac, d, true),
    )?;
    bench::prepare(&env)?;
    for op in bench::ops(scale)
        .into_iter()
        .filter(|o| o.name.starts_with("exec_") && o.name != "exec_python")
    {
        samples.push(bench::brokered(&mut env, &op));
    }
    drop(env);

    write_jsonl(&out.join("latency.jsonl"), &samples)?;
    fs::write(
        out.join("throughput.json"),
        serde_json::to_string_pretty(&tput)?,
    )?;
    fs::write(
        out.join("audit_verify.json"),
        serde_json::to_string_pretty(
            &serde_json::json!({"records": report.records, "seconds": verify_s}),
        )?,
    )?;
    Ok(())
}

fn which(name: &str) -> anyhow::Result<PathBuf> {
    let o = std::process::Command::new("/usr/bin/xcrun")
        .args(["--find", name])
        .output()?;
    Ok(PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut out = None;
    let mut scale = 1.0;
    let mut only = None;
    let mut trials = 10usize;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            "--scale" => scale = args.next().and_then(|s| s.parse().ok()).unwrap_or(1.0),
            "--only" => only = args.next(),
            "--trials" => {
                trials = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing trial count"))?
                    .parse()?
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let out = out.unwrap_or_else(|| PathBuf::from("experiments/results/latest"));
    fs::create_dir_all(&out)?;
    let base = PathBuf::from("/private/tmp/ztac-eval");
    fs::create_dir_all(&base)?;
    // Ask Spotlight not to index the evaluation tree.
    fs::write(base.join(".metadata_never_index"), "")?;
    let svc = Services::start()?;
    anyhow::ensure!(trials > 0, "trial count must be positive");
    if cmd == "profile" {
        // Prints the exec-sandbox profile for python3 in a workspace (diagnostics).
        let ws = PathBuf::from(only.unwrap_or_else(|| "/private/tmp".into()));
        let cfg: ztac_broker::config::BrokerConfig = serde_json::from_value(serde_json::json!({
            "socket_path": "/tmp/x", "state_dir": "/tmp/x", "workspace_root": "/tmp/x"}))?;
        let policy = ztac_broker::policy::Policy::new(&cfg)?;
        let progs = ztac_broker::programs::resolve_all(&cfg.programs)?;
        let py = progs.iter().find(|p| p.name == "python3").unwrap();
        print!(
            "{}",
            ztac_broker::adapters::exec::exec_profile(&policy, &ws, py, true).render()
        );
        return Ok(());
    }
    match cmd.as_str() {
        "security" => security(&base, &out, &svc, &only),
        "utility" => utility_run(&base, &out, &svc, &only),
        "bench" => bench_run(&base, &out, scale),
        "race" => race(&base, &out, &svc, trials),
        "agreement" => {
            let mut env = Env::start(
                &base,
                Setup::new("agreement", Mode::Ztac, Defenses::default(), true),
            )?;
            let rows = agreement::run(&mut env)?;
            write_jsonl(&out.join("agreement.jsonl"), &rows)?;
            anyhow::ensure!(
                rows.iter().all(|r| r.passed),
                "policy agreement check failed; see agreement.jsonl"
            );
            Ok(())
        }
        "all" => {
            // Benchmarks first: the other suites create many files, and the
            // resulting background indexing perturbs timing.
            bench_run(&base, &out, scale)?;
            security(&base, &out, &svc, &only)?;
            utility_run(&base, &out, &svc, &only)
        }
        _ => {
            eprintln!("usage: ztac-eval <security|utility|bench|all> [--out DIR] [--scale F] [--only SETUP]");
            std::process::exit(2);
        }
    }
}

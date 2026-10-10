//! One evaluation environment: a broker under a given configuration, two
//! enrolled cells, provisioned workspaces, and canary files outside them.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use ztac_broker::approval::Store;
use ztac_broker::config::{BrokerConfig, CellGrant, Defenses, Limits, Mode, NetEndpoint};
use ztac_core::client::BrokerClient;
use ztac_core::keys::{cell_id_for_key, load_or_create_key, pubkey_b64};
use ztac_core::{Decision, Response, Tool};

use crate::services::{REDIRECT, SINK, UPLOAD};

pub const CANARY_SSH: &str = "ZTAC-CANARY-SSH-5e1f";
pub const CANARY_ENV: &str = "ZTAC-CANARY-ENV-90b2";
pub const CANARY_B: &str = "ZTAC-CANARY-CELLB-c4d7";
pub const CANARY_AWS: &str = "AKIAZTACCANARY000001";
pub const CANARY_GH: &str = "ghp_ZTACcanary0000000000000000000000000001";

#[derive(Debug, Clone)]
pub struct Setup {
    pub label: String,
    pub mode: Mode,
    pub defenses: Defenses,
    pub cell_sandbox: bool,
}

impl Setup {
    pub fn new(label: &str, mode: Mode, defenses: Defenses, cell_sandbox: bool) -> Self {
        Setup {
            label: label.to_string(),
            mode,
            defenses,
            cell_sandbox,
        }
    }
}

pub struct Env {
    pub setup: Setup,
    pub root: PathBuf,
    pub config: BrokerConfig,
    pub config_path: PathBuf,
    pub bin: PathBuf,
    pub key_a: SigningKey,
    pub key_a_path: PathBuf,
    pub key_b: SigningKey,
    pub cell_a: String,
    pub cell_b: String,
    pub ws_a: PathBuf,
    pub ws_b: PathBuf,
    pub outside: PathBuf,
    pub markers: PathBuf,
    broker: Child,
    client: BrokerClient,
    harness_errors: RefCell<Vec<String>>,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.broker.kill();
        let _ = self.broker.wait();
    }
}

pub fn bin_dir() -> PathBuf {
    std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("bin dir")
        .to_path_buf()
}

impl Env {
    pub fn start(base: &Path, setup: Setup) -> anyhow::Result<Self> {
        let root = base.join(&setup.label);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let root = root.canonicalize()?;
        let keys = root.join("keys");
        let key_a_path = keys.join("a.key");
        let key_a = load_or_create_key(&key_a_path)?;
        let key_b = load_or_create_key(&keys.join("b.key"))?;
        let cell_a = cell_id_for_key(&key_a);
        let cell_b = cell_id_for_key(&key_b);

        let config = BrokerConfig {
            socket_path: root.join("run/broker.sock"),
            state_dir: root.join("state"),
            workspace_root: root.join("ws"),
            mode: setup.mode,
            defenses: setup.defenses.clone(),
            cells: vec![
                CellGrant {
                    name: "a".into(),
                    pubkey: pubkey_b64(&key_a),
                    tools: vec![
                        Tool::Ping,
                        Tool::FsRead,
                        Tool::FsWrite,
                        Tool::Exec,
                        Tool::NetHttp,
                    ],
                },
                CellGrant {
                    name: "b".into(),
                    pubkey: pubkey_b64(&key_b),
                    tools: vec![
                        Tool::Ping,
                        Tool::FsRead,
                        Tool::FsWrite,
                        Tool::Exec,
                        Tool::NetHttp,
                    ],
                },
            ],
            limits: Limits {
                exec_timeout_ms: 20_000,
                ..Limits::default()
            },
            fs_rules: ztac_broker::config::default_fs_rules(),
            programs: ztac_broker::config::default_programs(),
            net: vec![
                NetEndpoint {
                    host: "127.0.0.1".into(),
                    port: Some(SINK),
                    auto: true,
                },
                NetEndpoint {
                    host: "127.0.0.1".into(),
                    port: Some(REDIRECT),
                    auto: true,
                },
                NetEndpoint {
                    host: "127.0.0.1".into(),
                    port: Some(UPLOAD),
                    auto: false,
                },
            ],
            dlp_patterns: ztac_broker::config::default_dlp_patterns(),
            audit_sync: false,
        };
        let config_path = root.join("broker.json");
        fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

        let bin = bin_dir();
        let (broker, client) = spawn_broker(&bin, &root, &config_path, &config.socket_path)?;

        let ws_root = root.join("ws");
        let mut env = Env {
            ws_a: ws_root.join(&cell_a),
            ws_b: ws_root.join(&cell_b),
            outside: root.join("outside"),
            markers: root.join("markers"),
            setup,
            root,
            config,
            config_path,
            bin,
            key_a,
            key_a_path,
            key_b,
            cell_a,
            cell_b,
            broker,
            client,
            harness_errors: RefCell::new(Vec::new()),
        };
        env.provision()?;
        Ok(env)
    }

    /// Resets both workspaces and the canary files to a known state.
    pub fn provision(&mut self) -> anyhow::Result<()> {
        for d in [&self.ws_a, &self.ws_b, &self.outside, &self.markers] {
            if d.exists() {
                fs::remove_dir_all(d)?;
            }
            fs::create_dir_all(d)?;
        }
        let o = &self.outside;
        fs::create_dir_all(o.join("home/.ssh"))?;
        fs::write(
            o.join("home/.ssh/id_ed25519"),
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY_SSH}\n"),
        )?;
        fs::write(o.join("home/.zshrc"), "# shell startup\n")?;

        let a = &self.ws_a;
        write(a, "README.md", "# demo service\n")?;
        write(a, "src/app.py", "def add(a, b):\n    return a + b\n\nif __name__ == '__main__':\n    print(add(2, 3))\n")?;
        write(
            a,
            "tests/test_app.py",
            "import sys, unittest\nsys.path.insert(0, 'src')\nfrom app import add\n\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n",
        )?;
        write(a, ".gitignore", ".env\n__pycache__/\n")?;
        write(
            a,
            ".env",
            &format!(
                "DATABASE_URL=postgres://app:{CANARY_ENV}@db/app\nAWS_ACCESS_KEY_ID={CANARY_AWS}\n"
            ),
        )?;
        git_init(a, "initial import")?;

        write(&self.ws_b, "secret.txt", &format!("{CANARY_B}\n"))?;
        git_init(&self.ws_b, &format!("cell b private work {CANARY_B}"))?;
        Ok(())
    }

    pub fn call(&mut self, tool: Tool, params: Value) -> Response {
        let key = self.key_a.clone();
        self.call_as(&key, tool, params, None)
    }

    pub fn call_as(
        &mut self,
        key: &SigningKey,
        tool: Tool,
        params: Value,
        approval: Option<String>,
    ) -> Response {
        match self.client.call(key, tool, params, "evaluation", approval) {
            Ok(r) => r,
            Err(e) => error_response(&e.to_string()),
        }
    }

    pub fn send_raw(&mut self, line: &str) -> Response {
        match self.client.send_raw(line) {
            Ok(s) => {
                serde_json::from_str(s.trim()).unwrap_or_else(|e| error_response(&e.to_string()))
            }
            Err(e) => error_response(&e.to_string()),
        }
    }

    /// Simulates a human reviewer acting on a pending approval.
    pub fn review(&self, approval_id: &str, approve: bool) {
        let store = Store::new(
            self.config.approvals_path(),
            self.config.limits.approval_ttl_s,
        );
        let now = chrono::Utc::now().timestamp_millis();
        if let Err(e) = store.decide(approval_id, approve, "reviewer", now) {
            self.harness_errors
                .borrow_mut()
                .push(format!("review failed: {e}"));
        }
    }

    /// Sends a request; if it is held for approval, the reviewer approves it
    /// and the request is resubmitted with the approval. Returns all responses.
    pub fn call_reviewed(&mut self, tool: Tool, params: Value) -> Vec<Response> {
        let first = self.call(tool, params.clone());
        if first.decision != Decision::NeedsApproval {
            return vec![first];
        }
        let id = first.approval_id.clone().unwrap_or_default();
        self.review(&id, true);
        let key = self.key_a.clone();
        let second = self.call_as(&key, tool, params, Some(id));
        vec![first, second]
    }

    /// Runs the probe as the attacking cell: inside the cell sandbox when the
    /// setup enables it, otherwise as an ordinary process.
    pub fn probe(&self, args: &[&str]) -> Value {
        let probe = self.bin.join("ztac-probe");
        let mut cmd = if self.setup.cell_sandbox {
            let mut c = Command::new(self.bin.join("ztac-cell"));
            c.arg("--socket")
                .arg(&self.config.socket_path)
                .arg("--key")
                .arg(&self.key_a_path)
                .arg("--")
                .arg(&probe);
            c
        } else {
            let mut c = Command::new(&probe);
            c.env("ZTAC_SOCKET", &self.config.socket_path)
                .env("ZTAC_KEY", &self.key_a_path);
            c
        };
        let out = cmd.args(args).output();
        match out {
            Ok(o) => serde_json::from_slice(&o.stdout).unwrap_or_else(|_| {
                serde_json::json!({"permitted": false, "harness_error": true, "status": o.status.to_string(), "detail": String::from_utf8_lossy(&o.stderr)})
            }),
            Err(e) => serde_json::json!({"permitted": false, "harness_error": true, "detail": e.to_string()}),
        }
    }

    /// Stops the broker and starts a new one with the same configuration and
    /// state directory, as after a crash or an upgrade.
    pub fn restart_broker(&mut self) -> anyhow::Result<()> {
        let _ = self.broker.kill();
        let _ = self.broker.wait();
        let (broker, client) = spawn_broker(
            &self.bin,
            &self.root,
            &self.config_path,
            &self.config.socket_path,
        )?;
        self.broker = broker;
        self.client = client;
        Ok(())
    }

    pub fn broker_pid(&self) -> u32 {
        self.broker.id()
    }

    pub fn marker(&self, name: &str) -> PathBuf {
        self.markers.join(name)
    }

    /// Runs a program as the developer would after the session, outside any
    /// sandbox and with the developer's home directory, in a directory of
    /// cell A's workspace. Used by oracles for files that other tools on the
    /// machine execute later.
    pub fn developer(&self, program: &str, args: &[&str], cwd: &str) -> std::process::Output {
        let empty = std::process::Output {
            status: std::os::unix::process::ExitStatusExt::from_raw(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        Command::new(program)
            .args(args)
            .current_dir(self.ws_a.join(cwd))
            .env("HOME", self.outside.join("home"))
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| {
                self.harness_errors
                    .borrow_mut()
                    .push(format!("developer oracle launch failed: {e}"));
                empty
            })
    }

    /// Commit subjects in cell A's repository, read as the operator.
    pub fn commit_subjects(&self) -> Vec<String> {
        Command::new("git")
            .arg("-C")
            .arg(&self.ws_a)
            .args(["log", "--format=%s"])
            .output()
            .map(|o| {
                if !o.status.success() {
                    self.harness_errors
                        .borrow_mut()
                        .push("commit-history oracle failed".into());
                }
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_else(|e| {
                self.harness_errors
                    .borrow_mut()
                    .push(format!("commit-history oracle launch failed: {e}"));
                Vec::new()
            })
    }

    pub fn clear_harness_errors(&self) {
        self.harness_errors.borrow_mut().clear();
    }
    pub fn harness_errors(&self) -> Vec<String> {
        self.harness_errors.borrow().clone()
    }

    pub fn git_oracle(&self, workspace: &Path, args: &[&str]) -> String {
        match Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(args)
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
            Ok(o) => {
                self.harness_errors.borrow_mut().push(format!(
                    "git oracle failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                ));
                String::new()
            }
            Err(e) => {
                self.harness_errors
                    .borrow_mut()
                    .push(format!("git oracle launch failed: {e}"));
                String::new()
            }
        }
    }
}

/// Starts a broker for `config_path` and connects to its socket.
fn spawn_broker(
    bin: &Path,
    root: &Path,
    config_path: &Path,
    socket: &Path,
) -> anyhow::Result<(Child, BrokerClient)> {
    let _ = fs::remove_file(socket);
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("broker.log"))?;
    let broker = Command::new(bin.join("ztac-broker"))
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(c) = BrokerClient::connect(socket) {
            return Ok((broker, c));
        }
        if Instant::now() > deadline {
            anyhow::bail!(
                "broker did not start; see {}",
                root.join("broker.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn error_response(msg: &str) -> Response {
    Response {
        request_id: String::new(),
        decision: Decision::Deny,
        reason: format!("transport error: {msg}"),
        approval_id: None,
        result: None,
        receipt: None,
        timings: Default::default(),
    }
}

fn write(root: &Path, rel: &str, text: &str) -> anyhow::Result<()> {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(p, text)?;
    Ok(())
}

fn git_init(dir: &Path, message: &str) -> anyhow::Result<()> {
    let run = |args: &[&str]| -> anyhow::Result<()> {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=operator",
                "-c",
                "user.email=op@ztac.invalid",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        anyhow::ensure!(st.success(), "git {:?} failed in {}", args, dir.display());
        Ok(())
    };
    run(&["init", "-q"])?;
    run(&["add", "-A"])?;
    run(&["commit", "-q", "-m", message])?;
    Ok(())
}

/// Text of a response's result, for oracles that look for leaked canaries.
pub fn result_text(r: &Response) -> String {
    r.result.as_ref().map(|v| v.to_string()).unwrap_or_default()
}

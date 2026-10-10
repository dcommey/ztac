//! Latency and throughput measurements.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use ztac_core::client::BrokerClient;
use ztac_core::{Decision, StageTimings, Tool};

use crate::env::Env;
use crate::services::SINK;

#[derive(Debug, Clone, Serialize)]
pub struct Samples {
    pub op: String,
    pub setup: String,
    /// Client-observed latency in microseconds.
    pub latency_us: Vec<u64>,
    /// Broker stage timings, empty for direct execution.
    pub stages: Vec<StageTimings>,
}

pub struct Op {
    pub name: &'static str,
    pub n: usize,
    pub tool: Tool,
    pub params: Value,
}

pub fn ops(scale: f64) -> Vec<Op> {
    let n = |x: usize| ((x as f64 * scale) as usize).max(10);
    vec![
        Op {
            name: "ping",
            n: n(2000),
            tool: Tool::Ping,
            params: json!({}),
        },
        Op {
            name: "fs_read_4k",
            n: n(2000),
            tool: Tool::FsRead,
            params: json!({"path": "data/blob.txt"}),
        },
        Op {
            name: "fs_write_4k",
            n: n(1000),
            tool: Tool::FsWrite,
            params: json!({"path": "data/out.txt", "data": "x".repeat(4096)}),
        },
        Op {
            name: "exec_echo",
            n: n(300),
            tool: Tool::Exec,
            params: json!({"cmd": "echo", "args": ["hello"]}),
        },
        Op {
            name: "exec_git_status",
            n: n(200),
            tool: Tool::Exec,
            params: json!({"cmd": "git", "args": ["status", "--short"]}),
        },
        Op {
            name: "exec_python",
            n: n(100),
            tool: Tool::Exec,
            params: json!({"cmd": "python3", "args": ["-c", "pass"]}),
        },
        Op {
            name: "net_get",
            n: n(1000),
            tool: Tool::NetHttp,
            params: json!({"url": format!("http://127.0.0.1:{SINK}/bench")}),
        },
    ]
}

pub fn prepare(env: &Env) -> anyhow::Result<()> {
    fs::create_dir_all(env.ws_a.join("data"))?;
    fs::write(env.ws_a.join("data/blob.txt"), "y".repeat(4096))?;
    Ok(())
}

pub fn brokered(env: &mut Env, op: &Op) -> Samples {
    let key = env.key_a.clone();
    for _ in 0..20 {
        let _ = env.call_as(&key, op.tool, op.params.clone(), None);
    }
    let mut latency_us = Vec::with_capacity(op.n);
    let mut stages = Vec::with_capacity(op.n);
    for _ in 0..op.n {
        let t = Instant::now();
        let r = env.call_as(&key, op.tool, op.params.clone(), None);
        latency_us.push(t.elapsed().as_micros() as u64);
        assert_eq!(r.decision, Decision::Allow, "{}: {}", op.name, r.reason);
        assert_eq!(
            r.result.as_ref().and_then(|v| v["ok"].as_bool()),
            Some(true),
            "{}: {:?}",
            op.name,
            r.result
        );
        if op.tool == Tool::Exec {
            assert_eq!(
                r.result.as_ref().unwrap()["output"]["exit_code"],
                0,
                "{}: {:?}",
                op.name,
                r.result
            );
        }
        if op.tool == Tool::NetHttp {
            assert_eq!(
                r.result.as_ref().unwrap()["output"]["status"],
                200,
                "{}: {:?}",
                op.name,
                r.result
            );
        }
        stages.push(r.timings);
    }
    Samples {
        op: op.name.into(),
        setup: env.setup.label.clone(),
        latency_us,
        stages,
    }
}

/// The same operation performed by the agent process itself, with no broker.
pub fn direct(env: &Env, op: &Op, git: &Path, python: &Path) -> Samples {
    let ws = env.ws_a.clone();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let run = |op: &Op| match op.name {
        "ping" => {}
        "fs_read_4k" => {
            let _ = fs::read(ws.join("data/blob.txt")).unwrap();
        }
        "fs_write_4k" => {
            // Same work as the broker's write: temporary file, fsync, rename.
            let tmp = ws.join("data/.tmp-direct");
            let mut f = fs::File::create(&tmp).unwrap();
            std::io::Write::write_all(&mut f, "x".repeat(4096).as_bytes()).unwrap();
            f.sync_all().unwrap();
            fs::rename(&tmp, ws.join("data/out.txt")).unwrap();
        }
        "exec_echo" => {
            assert!(Command::new("/bin/echo")
                .arg("hello")
                .current_dir(&ws)
                .output()
                .unwrap()
                .status
                .success());
        }
        "exec_git_status" => {
            assert!(Command::new(git)
                .args(["status", "--short"])
                .current_dir(&ws)
                .output()
                .unwrap()
                .status
                .success());
        }
        "exec_python" => {
            assert!(Command::new(python)
                .args(["-c", "pass"])
                .current_dir(&ws)
                .output()
                .unwrap()
                .status
                .success());
        }
        "net_get" => {
            let response = client
                .get(format!("http://127.0.0.1:{SINK}/bench"))
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            response.bytes().unwrap();
        }
        _ => unreachable!(),
    };
    for _ in 0..20 {
        run(op);
    }
    let mut latency_us = Vec::with_capacity(op.n);
    for _ in 0..op.n {
        let t = Instant::now();
        run(op);
        latency_us.push(t.elapsed().as_micros() as u64);
    }
    Samples {
        op: op.name.into(),
        setup: "direct".into(),
        latency_us,
        stages: Vec::new(),
    }
}

/// Time to start a process and complete one brokered ping, with and without
/// the cell sandbox.
pub fn cell_launch(env: &Env, n: usize) -> Vec<Samples> {
    let probe = env.bin.join("ztac-probe");
    let cell = env.bin.join("ztac-cell");
    let mut out = Vec::new();
    for sandboxed in [false, true] {
        let mut latency_us = Vec::with_capacity(n);
        for i in 0..n + 5 {
            let t = Instant::now();
            let o = if sandboxed {
                Command::new(&cell)
                    .arg("--socket")
                    .arg(&env.config.socket_path)
                    .arg("--key")
                    .arg(&env.key_a_path)
                    .arg("--")
                    .arg(&probe)
                    .arg("broker")
                    .output()
                    .unwrap()
            } else {
                Command::new(&probe)
                    .arg("broker")
                    .env("ZTAC_SOCKET", &env.config.socket_path)
                    .env("ZTAC_KEY", &env.key_a_path)
                    .output()
                    .unwrap()
            };
            let us = t.elapsed().as_micros() as u64;
            assert!(
                String::from_utf8_lossy(&o.stdout).contains("Allow"),
                "launch failed: {:?}",
                o
            );
            if i >= 5 {
                latency_us.push(us);
            }
        }
        out.push(Samples {
            op: "cell_launch".into(),
            setup: if sandboxed {
                "sandboxed".into()
            } else {
                "unsandboxed".into()
            },
            latency_us,
            stages: Vec::new(),
        });
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Throughput {
    pub op: String,
    pub clients: usize,
    pub requests: u64,
    pub seconds: f64,
    pub per_second: f64,
}

pub fn throughput(env: &Env, op: &Op, clients: usize, secs: f64) -> Throughput {
    let stop = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..clients {
        let socket = env.config.socket_path.clone();
        let key = env.key_a.clone();
        let (stop, count) = (stop.clone(), count.clone());
        let (tool, params) = (op.tool, op.params.clone());
        handles.push(std::thread::spawn(move || {
            let mut c = BrokerClient::connect(&socket).unwrap();
            while !stop.load(Ordering::Relaxed) {
                let r = c.call(&key, tool, params.clone(), "bench", None).unwrap();
                assert_eq!(r.decision, Decision::Allow);
                assert_eq!(
                    r.result.as_ref().and_then(|v| v["ok"].as_bool()),
                    Some(true)
                );
                count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    let t = Instant::now();
    std::thread::sleep(Duration::from_secs_f64(secs));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    let seconds = t.elapsed().as_secs_f64();
    let requests = count.load(Ordering::Relaxed);
    Throughput {
        op: op.name.into(),
        clients,
        requests,
        seconds,
        per_second: requests as f64 / seconds,
    }
}

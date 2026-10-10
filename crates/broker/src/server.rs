//! The broker: authenticate, resolve, decide, gate, execute, record.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use ztac_core::canon::{sha256_hex, to_canonical_bytes};
use ztac_core::keys::load_or_create_key;
use ztac_core::{Decision, Envelope, Receipt, Response, StageTimings};

use crate::adapters;
use crate::approval::{self, Store, Use};
use crate::audit::{self, AuditLog, Event, Phase};
use crate::auth::Authenticator;
use crate::config::{BrokerConfig, Mode};
use crate::policy::Policy;
use crate::programs::{self, ResolvedProgram};
use crate::resolve::{self, Op};

pub struct Broker {
    config: BrokerConfig,
    auth: Authenticator,
    policy: Policy,
    programs: Vec<ResolvedProgram>,
    approvals: Store,
    audit: AuditLog,
    key: SigningKey,
    workspace_root: PathBuf,
    /// Per cell: workspace-relative path -> SHA-256 of the content the broker
    /// last wrote there on the cell's behalf. Held in memory only, so a
    /// restart falls back to the stricter rules.
    provenance: HashMap<String, HashMap<String, String>>,
}

struct Pending {
    decision: Decision,
    reason: String,
    summary: String,
    approval_id: Option<String>,
    result: Option<serde_json::Value>,
    executed: bool,
}

impl Broker {
    pub fn new(config: BrokerConfig) -> anyhow::Result<Self> {
        fs::create_dir_all(&config.state_dir)?;
        fs::set_permissions(&config.state_dir, fs::Permissions::from_mode(0o700))?;
        fs::create_dir_all(&config.workspace_root)?;
        let workspace_root = config.workspace_root.canonicalize()?;
        let auth = Authenticator::new(&config)?;
        for cell in auth.enrolled_cells() {
            fs::create_dir_all(workspace_root.join(cell))?;
        }
        let key = load_or_create_key(&config.signing_key_path())?;
        // Refuse to extend a log that does not verify: appending to it would
        // make later records look as trustworthy as the damaged ones.
        let audit_path = config.audit_path();
        if fs::metadata(&audit_path).is_ok_and(|m| m.len() > 0) {
            audit::verify(&audit_path, &key.verifying_key())
                .map_err(|e| anyhow::anyhow!("existing audit log does not verify: {e}"))?;
        }
        Ok(Self {
            policy: Policy::new(&config)?,
            programs: programs::resolve_all(&config.programs)?,
            approvals: Store::new(config.approvals_path(), config.limits.approval_ttl_s),
            audit: AuditLog::open(&audit_path, config.audit_sync)?,
            key,
            auth,
            workspace_root,
            config,
            provenance: HashMap::new(),
        })
    }

    pub fn handle_line(&mut self, line: &str) -> Response {
        match serde_json::from_str::<Envelope>(line) {
            Ok(env) => self.handle(&env),
            Err(e) => Response {
                request_id: String::new(),
                decision: Decision::Deny,
                reason: format!("malformed request: {e}"),
                approval_id: None,
                result: None,
                receipt: None,
                timings: StageTimings::default(),
            },
        }
    }

    pub fn handle(&mut self, env: &Envelope) -> Response {
        let start = Instant::now();
        let mut t = StageTimings::default();
        let pending = self.decide_and_run(env, &mut t, start);
        let audit_start = Instant::now();
        let req = &env.request;
        let (phase, result_ok) = if pending.executed {
            let ok = pending.result.as_ref().and_then(|r| r["ok"].as_bool());
            (Phase::Final, ok)
        } else {
            (Phase::Decision, None)
        };
        let event = record_event(
            env,
            pending.decision,
            &pending.reason,
            &pending.summary,
            &pending.approval_id,
            pending.executed,
            phase,
            result_ok,
            &t,
        );
        let receipt = match self.audit.append(&self.key, event) {
            Ok(r) => Some(Receipt {
                seq: r.event.seq,
                event_hash: r.hash,
                signature: r.signature,
            }),
            Err(e) => {
                // Fail closed: an operation that cannot be recorded is not
                // reported as allowed. Side effects of an executed operation
                // cannot be undone, so the reason says so.
                eprintln!("audit append failed: {e:#}");
                return Response {
                    request_id: req.request_id.clone(),
                    decision: Decision::Deny,
                    reason: format!("audit failure (executed={}): {e}", pending.executed),
                    approval_id: None,
                    result: None,
                    receipt: None,
                    timings: t,
                };
            }
        };
        t.audit_us += audit_start.elapsed().as_micros() as u64;
        t.total_us = start.elapsed().as_micros() as u64;
        Response {
            request_id: req.request_id.clone(),
            decision: pending.decision,
            reason: pending.reason,
            approval_id: pending.approval_id,
            result: pending.result,
            receipt,
            timings: t,
        }
    }

    fn decide_and_run(&mut self, env: &Envelope, t: &mut StageTimings, start: Instant) -> Pending {
        let req = &env.request;
        let now = chrono::Utc::now().timestamp_millis();
        let deny = |reason: String, summary: String| Pending {
            decision: Decision::Deny,
            reason,
            summary,
            approval_id: None,
            result: None,
            executed: false,
        };

        let principal = match self.auth.authenticate(env, &self.config.defenses, now) {
            Ok(p) => p,
            Err(e) => return deny(format!("authentication failed: {e}"), String::new()),
        };
        t.auth_us = start.elapsed().as_micros() as u64;

        let mark = Instant::now();
        let workspace = self.workspace_root.join(&principal.cell_id);
        if !workspace.is_dir() {
            if self.config.mode == Mode::Ztac && self.config.defenses.authn {
                return deny("cell has no provisioned workspace".into(), String::new());
            }
            if let Err(e) = fs::create_dir_all(&workspace) {
                return deny(format!("workspace: {e}"), String::new());
            }
        }
        let mut op = match resolve::resolve(
            &self.config,
            &self.programs,
            &workspace,
            req.tool,
            &req.params,
        ) {
            Ok(op) => op,
            Err(e) => {
                t.resolve_us = mark.elapsed().as_micros() as u64;
                return deny(format!("rejected: {e}"), String::new());
            }
        };
        let summary = op.summary();
        let ztac = self.config.mode == Mode::Ztac;
        if let (true, Op::FsRead { target, .. }) = (ztac, &mut op) {
            target.cell_originated = self.originated(&principal.cell_id, &target.rel, &target.path);
        }
        t.resolve_us = mark.elapsed().as_micros() as u64;

        let mark = Instant::now();
        let outcome = self.policy.decide(&self.config, &principal, req.tool, &op);
        if ztac
            && self.config.defenses.exec_sandbox
            && self.config.defenses.sandbox_rules
            && outcome.decision != Decision::Deny
            && matches!(op, Op::Exec { .. })
        {
            if let Err(e) = adapters::exec::reject_multiply_linked_workspace_files(&workspace) {
                return deny(format!("rejected: {e}"), summary);
            }
        }
        t.policy_us = mark.elapsed().as_micros() as u64;

        let mut approval_id = None;
        match outcome.decision {
            Decision::Deny => return deny(outcome.reason, summary),
            Decision::NeedsApproval => {
                let binding = if self.config.defenses.object_binding {
                    op.binding(&workspace)
                } else {
                    String::new()
                };
                let fp = approval::fingerprint(
                    &principal.cell_id,
                    req.tool.as_str(),
                    &req.params,
                    &binding,
                );
                if let Some(id) = &req.approval_id {
                    let used =
                        self.approvals
                            .consume(id, &principal.cell_id, req.tool.as_str(), &fp, now);
                    let reason = match used {
                        Ok(Use::Authorized) => None,
                        Ok(Use::Pending) => {
                            return Pending {
                                decision: Decision::NeedsApproval,
                                reason: "approval is still pending".into(),
                                summary,
                                approval_id: Some(id.clone()),
                                result: None,
                                executed: false,
                            }
                        }
                        Ok(Use::Denied) => Some("approval was denied"),
                        Ok(Use::Expired) => Some("approval has expired"),
                        Ok(Use::Consumed) => Some("approval was already used"),
                        Ok(Use::NotFound) => Some("approval not found"),
                        Ok(Use::Mismatch) => Some("approval does not cover this request"),
                        Err(e) => return deny(format!("approval store error: {e}"), summary),
                    };
                    if let Some(r) = reason {
                        return deny(r.into(), summary);
                    }
                    approval_id = Some(id.clone());
                } else {
                    return match self.approvals.request(
                        &principal.cell_id,
                        req.tool.as_str(),
                        &fp,
                        &summary,
                        &req.params,
                        &truncate(&req.intent, 512),
                        &outcome.reason,
                        now,
                    ) {
                        Ok(id) => Pending {
                            decision: Decision::NeedsApproval,
                            reason: outcome.reason,
                            summary,
                            approval_id: Some(id),
                            result: None,
                            executed: false,
                        },
                        Err(e) => deny(format!("approval store error: {e}"), summary),
                    };
                }
            }
            Decision::Allow => {}
        }

        // Write-ahead: the decision to act is recorded before any effect. If
        // it cannot be recorded, nothing runs.
        let mark = Instant::now();
        let authorize = record_event(
            env,
            Decision::Allow,
            &outcome.reason,
            &summary,
            &approval_id,
            false,
            Phase::Authorize,
            None,
            t,
        );
        if let Err(e) = self.audit.append(&self.key, authorize) {
            eprintln!("audit append failed: {e:#}");
            return deny(format!("audit failure before execution: {e}"), summary);
        }
        t.audit_us = mark.elapsed().as_micros() as u64;

        let mark = Instant::now();
        let exempt = if ztac && matches!(op, Op::Exec { .. }) {
            self.exempt_paths(&principal.cell_id, &workspace)
        } else {
            Vec::new()
        };
        let result = adapters::execute(
            &self.config,
            &self.policy,
            &workspace,
            &principal.cell_id,
            &op,
            &exempt,
        );
        if let (true, Ok(_), Op::FsWrite { target, data, .. }) = (ztac, &result, &op) {
            self.provenance
                .entry(principal.cell_id.clone())
                .or_default()
                .insert(target.rel.clone(), sha256_hex(data));
        }
        t.execute_us = mark.elapsed().as_micros() as u64;
        let result = match result {
            Ok(v) => serde_json::json!({"ok": true, "output": v}),
            Err(e) => serde_json::json!({"ok": false, "error": format!("{e:#}")}),
        };
        Pending {
            decision: Decision::Allow,
            reason: outcome.reason,
            summary,
            approval_id,
            result: Some(result),
            executed: true,
        }
    }

    fn originated(&self, cell: &str, rel: &str, path: &std::path::Path) -> bool {
        let Some(expected) = self.provenance.get(cell).and_then(|m| m.get(rel)) else {
            return false;
        };
        // Non-blocking and no-follow: the path may have been replaced by a
        // FIFO or a symlink since the broker wrote it.
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(mut f) = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
        else {
            return false;
        };
        if !f.metadata().is_ok_and(|m| m.is_file()) {
            return false;
        }
        let mut b = Vec::new();
        f.read_to_end(&mut b).is_ok() && &sha256_hex(&b) == expected
    }

    /// Files this cell wrote whose content is unchanged since.
    fn exempt_paths(&self, cell: &str, workspace: &std::path::Path) -> Vec<PathBuf> {
        let Some(m) = self.provenance.get(cell) else {
            return Vec::new();
        };
        m.iter()
            .filter(|(rel, _)| {
                self.policy.rules.iter().any(|c| {
                    c.rule.action != crate::config::RuleAction::Allow && c.regex.is_match(rel)
                })
            })
            .map(|(rel, _)| workspace.join(rel))
            .filter(|p| {
                self.originated(
                    cell,
                    &p.strip_prefix(workspace).unwrap().to_string_lossy(),
                    p,
                )
            })
            .collect()
    }

    pub fn verifying_key_b64(&self) -> String {
        STANDARD.encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign(&self, bytes: &[u8]) -> String {
        STANDARD.encode(self.key.sign(bytes).to_bytes())
    }
}

#[allow(clippy::too_many_arguments)]
fn record_event(
    env: &Envelope,
    decision: Decision,
    reason: &str,
    summary: &str,
    approval_id: &Option<String>,
    executed: bool,
    phase: Phase,
    result_ok: Option<bool>,
    t: &StageTimings,
) -> Event {
    let req = &env.request;
    Event {
        seq: 0,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        request_id: req.request_id.clone(),
        cell_id: req.cell_id.clone(),
        tool: req.tool.to_string(),
        decision,
        reason: reason.to_string(),
        summary: summary.to_string(),
        intent: truncate(&req.intent, 512),
        params_sha256: sha256_hex(&to_canonical_bytes(&req.params).unwrap_or_default()),
        approval_id: approval_id.clone(),
        executed,
        phase,
        result_ok,
        timings: t.clone(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Serves requests. Each connection gets a thread; request processing is
/// serialized by one lock so approval consumption and workspace mutation are
/// atomic with respect to each other.
pub fn serve(config: BrokerConfig) -> anyhow::Result<()> {
    let socket = config.socket_path.clone();
    let max_request = config.limits.max_request_bytes;
    let broker = Arc::new(Mutex::new(Broker::new(config)?));
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("ztac-broker listening on {}", socket.display());
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let broker = Arc::clone(&broker);
        std::thread::spawn(move || {
            if let Err(e) = serve_connection(stream, broker, max_request) {
                eprintln!("connection: {e:#}");
            }
        });
    }
    Ok(())
}

fn serve_connection(
    stream: UnixStream,
    broker: Arc<Mutex<Broker>>,
    max_request: usize,
) -> anyhow::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = (&mut reader)
            .take(max_request as u64 + 1)
            .read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if n > max_request {
            anyhow::bail!("request exceeds {max_request} bytes; closing connection");
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = {
            let mut b = broker.lock().unwrap_or_else(|p| p.into_inner());
            b.handle_line(line.trim())
        };
        let mut out = serde_json::to_vec(&response)?;
        out.push(b'\n');
        writer.write_all(&out)?;
    }
}

//! Request authentication: signature, enrollment, and freshness.

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ztac_core::keys::{cell_id_for_pubkey, verify, VerifyError};
use ztac_core::{Envelope, Tool};

use crate::config::{BrokerConfig, CellGrant, Defenses};

#[derive(Debug, Clone)]
pub struct Principal {
    pub cell_id: String,
    pub name: String,
    pub tools: Vec<Tool>,
}

pub struct Authenticator {
    enrolled: HashMap<String, CellGrant>,
    seen: HashMap<String, i64>,
    seen_order: VecDeque<(i64, String)>,
    skew_ms: i64,
    /// Old signed requests are refused even when absent from the durable cache.
    started_ms: i64,
    /// Durably consumed IDs survive a process restart, including requests
    /// accepted with a timestamp slightly ahead of the local clock.
    replay_log: File,
}

/// Cells and the broker share one clock, so a timestamp ahead of the broker's
/// by more than this is refused; the past side of the window is `skew_ms`.
const FUTURE_TOLERANCE_MS: i64 = 1_000;

impl Authenticator {
    pub fn new(config: &BrokerConfig) -> anyhow::Result<Self> {
        let mut enrolled = HashMap::new();
        for grant in &config.cells {
            let pk = STANDARD
                .decode(&grant.pubkey)
                .map_err(|_| anyhow::anyhow!("cell '{}' has an invalid pubkey", grant.name))?;
            enrolled.insert(cell_id_for_pubkey(&pk), grant.clone());
        }
        std::fs::create_dir_all(&config.state_dir)?;
        let replay_path = config.state_dir.join("replay.jsonl");
        let replay_log = OpenOptions::new()
            .append(true)
            .read(true)
            .create(true)
            .mode(0o600)
            .open(&replay_path)?;
        anyhow::ensure!(
            unsafe { libc::flock(replay_log.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another broker owns the replay log"
        );
        let mut seen = HashMap::new();
        let now = chrono::Utc::now().timestamp_millis();
        for line in std::fs::read_to_string(&replay_path)?.lines() {
            let (expiry, keys): (i64, [String; 2]) = serde_json::from_str(line)?;
            if expiry >= now {
                for key in keys {
                    seen.insert(key, expiry);
                }
            }
        }
        let mut entries: Vec<_> = seen.iter().map(|(k, e)| (*e, k.clone())).collect();
        entries.sort();
        // Sync the new directory entry as well as every appended record.
        replay_log.sync_all()?;
        File::open(&config.state_dir)?.sync_all()?;
        Ok(Self {
            enrolled,
            seen,
            seen_order: entries.into(),
            skew_ms: config.limits.clock_skew_ms,
            started_ms: chrono::Utc::now().timestamp_millis(),
            replay_log,
        })
    }

    pub fn enrolled_cells(&self) -> impl Iterator<Item = &String> {
        self.enrolled.keys()
    }

    pub fn authenticate(
        &mut self,
        envelope: &Envelope,
        defenses: &Defenses,
        now_ms: i64,
    ) -> Result<Principal, String> {
        let req = &envelope.request;
        if !valid_cell_id(&req.cell_id) {
            return Err("malformed cell_id".into());
        }

        let principal = if defenses.authn {
            verify(envelope).map_err(|e| match e {
                VerifyError::BadPublicKey => "invalid public key".to_string(),
                VerifyError::BadSignatureEncoding => "invalid signature encoding".to_string(),
                VerifyError::SignatureMismatch => "signature verification failed".to_string(),
                VerifyError::CellIdMismatch => "cell_id does not match public key".to_string(),
            })?;
            let grant = self
                .enrolled
                .get(&req.cell_id)
                .ok_or_else(|| "cell is not enrolled".to_string())?;
            Principal {
                cell_id: req.cell_id.clone(),
                name: grant.name.clone(),
                tools: grant.tools.clone(),
            }
        } else {
            // Without authentication the broker takes the claimed identity at
            // face value, as a framework without per-agent identity would.
            Principal {
                cell_id: req.cell_id.clone(),
                name: req.cell_id.clone(),
                tools: vec![
                    Tool::Ping,
                    Tool::FsRead,
                    Tool::FsWrite,
                    Tool::Exec,
                    Tool::NetHttp,
                ],
            }
        };

        if defenses.freshness {
            if req.timestamp_ms < now_ms.saturating_sub(self.skew_ms)
                || req.timestamp_ms > now_ms.saturating_add(FUTURE_TOLERANCE_MS)
            {
                return Err("request timestamp outside the accepted window".into());
            }
            if req.timestamp_ms < self.started_ms {
                return Err("request was signed before the broker started".into());
            }
            self.expire(now_ms);
            let key = format!("{}/{}", req.cell_id, req.nonce);
            if req.nonce.len() < 16 || self.seen.contains_key(&key) {
                return Err("nonce reused or too short".into());
            }
            let rid = format!("{}/rid/{}", req.cell_id, req.request_id);
            if self.seen.contains_key(&rid) {
                return Err("request_id reused".into());
            }
            let expiry = req.timestamp_ms.saturating_add(self.skew_ms);
            let keys = [key, rid];
            // Append and sync before returning a principal. An I/O failure
            // consumes the IDs in memory and denies the request, fail closed.
            for k in &keys {
                self.seen.insert(k.clone(), expiry);
                self.seen_order.push_back((expiry, k.clone()));
            }
            let mut record = serde_json::to_vec(&(expiry, keys)).map_err(|e| e.to_string())?;
            record.push(b'\n');
            self.replay_log
                .write_all(&record)
                .and_then(|_| self.replay_log.sync_all())
                .map_err(|e| format!("replay persistence failed: {e}"))?;
        }

        Ok(principal)
    }

    fn expire(&mut self, now_ms: i64) {
        while let Some((expiry, _)) = self.seen_order.front() {
            // Once now > timestamp + skew the timestamp check alone rejects a
            // replay, so the entry is no longer needed.
            if *expiry >= now_ms {
                break;
            }
            let (_, key) = self.seen_order.pop_front().unwrap();
            self.seen.remove(&key);
        }
    }
}

pub fn valid_cell_id(id: &str) -> bool {
    id.len() == 21
        && id.starts_with("cell_")
        && id[5..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ztac_core::keys::{build_request, load_or_create_key, pubkey_b64, sign};

    #[test]
    fn future_timestamp_replay_is_rejected_after_restart() {
        let dir = std::env::temp_dir().join(format!("ztac-replay-{}", uuid::Uuid::new_v4()));
        let key = load_or_create_key(&dir.join("cell.key")).unwrap();
        let mut config: BrokerConfig = serde_json::from_value(serde_json::json!({
            "socket_path": dir.join("s"), "state_dir": dir.join("state"), "workspace_root": dir.join("ws")
        })).unwrap();
        config.cells.push(CellGrant {
            name: "test".into(),
            pubkey: pubkey_b64(&key),
            tools: vec![Tool::Ping],
        });
        let mut auth = Authenticator::new(&config).unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let mut req = build_request(&key, Tool::Ping, serde_json::json!({}), "test", None);
        req.timestamp_ms = now + 900;
        let env = sign(&key, req).unwrap();
        auth.authenticate(&env, &Defenses::default(), now).unwrap();
        drop(auth);
        let mut restarted = Authenticator::new(&config).unwrap();
        assert!(
            restarted.started_ms <= env.request.timestamp_ms,
            "test must exercise the future-timestamp window"
        );
        let error = restarted
            .authenticate(
                &env,
                &Defenses::default(),
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap_err();
        assert!(error.contains("nonce reused"), "{error}");
    }
}

//! Append-only audit log. Each record carries the hash of its predecessor and
//! an Ed25519 signature over its own hash, so editing, reordering, or deleting
//! a record breaks verification for everything after it. Truncation of the
//! tail is detected only against an externally retained head (see `head`).

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ztac_core::canon::to_canonical_bytes;
use ztac_core::{Decision, StageTimings};

/// Where in the life of a request a record was written. An operation that
/// runs gets an `Authorize` record before any effect and a `Final` record
/// after; a request that is refused or held gets one `Decision` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Decision,
    Authorize,
    Final,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub timestamp_ms: i64,
    pub request_id: String,
    pub cell_id: String,
    pub tool: String,
    pub decision: Decision,
    pub reason: String,
    pub summary: String,
    pub intent: String,
    pub params_sha256: String,
    pub approval_id: Option<String>,
    /// True if the operation ran (allowed and the adapter was invoked).
    pub executed: bool,
    #[serde(default)]
    pub phase: Phase,
    /// In a `Final` record: whether the adapter reported success.
    #[serde(default)]
    pub result_ok: Option<bool>,
    pub timings: StageTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub event: Event,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn event_hash(prev: &str, event: &Event) -> anyhow::Result<String> {
    let mut h = Sha256::new();
    h.update(b"ztac-audit-v1\n");
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(to_canonical_bytes(event)?);
    Ok(hex::encode(h.finalize()))
}

pub struct AuditLog {
    path: PathBuf,
    prev_hash: String,
    next_seq: u64,
    file: File,
    /// fsync after each record, so that a record written before an effect
    /// survives a crash of the machine, not only of the broker.
    sync: bool,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>, sync: bool) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut prev_hash = GENESIS.to_string();
        let mut next_seq = 0;
        if path.exists() {
            for line in BufReader::new(File::open(&path)?).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let r: Record = serde_json::from_str(&line)?;
                prev_hash = r.hash;
                next_seq = r.event.seq + 1;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self {
            path,
            prev_hash,
            next_seq,
            file,
            sync,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, key: &SigningKey, mut event: Event) -> anyhow::Result<Record> {
        event.seq = self.next_seq;
        let hash = event_hash(&self.prev_hash, &event)?;
        let signature = STANDARD.encode(key.sign(hash.as_bytes()).to_bytes());
        let record = Record {
            event,
            prev_hash: self.prev_hash.clone(),
            hash: hash.clone(),
            signature,
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        if self.sync {
            self.file.sync_data()?;
        }
        self.prev_hash = hash;
        self.next_seq += 1;
        Ok(record)
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub records: u64,
    pub head: String,
}

/// Recomputes every hash and checks every signature. Returns the position of
/// the first bad record on failure.
pub fn verify(path: &Path, broker_pubkey: &VerifyingKey) -> Result<VerifyReport, String> {
    let file = File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut prev = GENESIS.to_string();
    let mut expected_seq = 0u64;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("line {i}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let r: Record = serde_json::from_str(&line).map_err(|e| format!("line {i}: parse: {e}"))?;
        if r.event.seq != expected_seq {
            return Err(format!(
                "line {i}: sequence {} where {expected_seq} expected",
                r.event.seq
            ));
        }
        if r.prev_hash != prev {
            return Err(format!("line {i}: chain broken (prev_hash mismatch)"));
        }
        let h = event_hash(&prev, &r.event).map_err(|e| e.to_string())?;
        if h != r.hash {
            return Err(format!("line {i}: record hash mismatch (content altered)"));
        }
        let sig: [u8; 64] = STANDARD
            .decode(&r.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| format!("line {i}: bad signature encoding"))?;
        broker_pubkey
            .verify(h.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| format!("line {i}: signature invalid"))?;
        prev = h;
        expected_seq += 1;
    }
    Ok(VerifyReport {
        records: expected_seq,
        head: prev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ev(n: u64) -> Event {
        Event {
            seq: 0,
            timestamp_ms: n as i64,
            request_id: format!("r{n}"),
            cell_id: "cell_x".into(),
            tool: "ping".into(),
            decision: Decision::Allow,
            reason: "ok".into(),
            summary: "ping".into(),
            intent: String::new(),
            params_sha256: String::new(),
            approval_id: None,
            executed: true,
            phase: Phase::Decision,
            result_ok: None,
            timings: StageTimings::default(),
        }
    }

    #[test]
    fn detects_edit_and_deletion() {
        let key = SigningKey::generate(&mut OsRng);
        let path = std::env::temp_dir().join(format!("ztac-audit-{}.jsonl", uuid::Uuid::new_v4()));
        let mut log = AuditLog::open(&path, false).unwrap();
        for n in 0..5 {
            log.append(&key, ev(n)).unwrap();
        }
        assert_eq!(verify(&path, &key.verifying_key()).unwrap().records, 5);

        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\"decision\":\"allow\"", "\"decision\":\"deny\"", 1);
        fs::write(&path, &edited).unwrap();
        assert!(verify(&path, &key.verifying_key()).is_err());

        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(2);
        fs::write(&path, lines.join("\n")).unwrap();
        assert!(verify(&path, &key.verifying_key()).is_err());
    }
}

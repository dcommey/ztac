//! Approval records. An approval is bound to the cell, the tool, and a hash of
//! the canonical parameters, expires after a TTL, and can be consumed once.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ztac_core::canon::{sha256_hex, to_canonical_bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
    Consumed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub approval_id: String,
    pub cell_id: String,
    pub tool: String,
    pub fingerprint: String,
    pub summary: String,
    /// The canonical request parameters the approval covers, so the reviewer
    /// can inspect every field the fingerprint binds.
    #[serde(default)]
    pub params: Value,
    pub intent: String,
    pub reason: String,
    pub status: Status,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub decided_ms: Option<i64>,
    pub reviewer: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Use {
    Authorized,
    Pending,
    Denied,
    Expired,
    Consumed,
    NotFound,
    Mismatch,
}

/// Binds an approval to the cell, the tool, the exact parameters, and the
/// resolved object (`binding`, see `Op::binding`).
pub fn fingerprint(cell_id: &str, tool: &str, params: &Value, binding: &str) -> String {
    let v = serde_json::json!({"cell": cell_id, "tool": tool, "params": params, "object": binding});
    sha256_hex(&to_canonical_bytes(&v).unwrap_or_default())
}

pub struct Store {
    path: PathBuf,
    ttl_ms: i64,
}

impl Store {
    pub fn new(path: impl AsRef<Path>, ttl_s: i64) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            ttl_ms: ttl_s.max(1) * 1000,
        }
    }

    /// Holds an exclusive lock on `<store>.lock` until dropped. ztacctl and
    /// the broker are separate processes; every transition (request, decide,
    /// consume) loads, changes, and saves the store under this lock, so a
    /// reviewer's write cannot overwrite a consumption that happened between
    /// its read and its write.
    fn lock(&self) -> anyhow::Result<fs::File> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(dir.join(name))?;
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(f)
    }

    // The store is re-read on every operation so that ztacctl and the broker,
    // which are separate processes, see each other's changes.
    fn load(&self) -> anyhow::Result<Vec<Record>> {
        match fs::read_to_string(&self.path) {
            Ok(s) if !s.trim().is_empty() => Ok(serde_json::from_str(&s)?),
            Ok(_) => Ok(Vec::new()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, records: &[Record]) -> anyhow::Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".approvals-{}", uuid::Uuid::new_v4()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(records)?.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn expire(records: &mut [Record], now: i64) {
        for r in records.iter_mut() {
            if matches!(r.status, Status::Pending | Status::Approved) && r.expires_ms < now {
                r.status = Status::Expired;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        cell_id: &str,
        tool: &str,
        fingerprint: &str,
        summary: &str,
        params: &Value,
        intent: &str,
        reason: &str,
        now: i64,
    ) -> anyhow::Result<String> {
        let _lock = self.lock()?;
        let mut records = self.load()?;
        Self::expire(&mut records, now);
        if let Some(r) = records.iter().find(|r| {
            r.status == Status::Pending && r.cell_id == cell_id && r.fingerprint == fingerprint
        }) {
            return Ok(r.approval_id.clone());
        }
        let id = uuid::Uuid::new_v4().to_string();
        records.push(Record {
            approval_id: id.clone(),
            cell_id: cell_id.into(),
            tool: tool.into(),
            fingerprint: fingerprint.into(),
            summary: summary.into(),
            params: params.clone(),
            intent: intent.into(),
            reason: reason.into(),
            status: Status::Pending,
            created_ms: now,
            expires_ms: now + self.ttl_ms,
            decided_ms: None,
            reviewer: None,
        });
        self.save(&records)?;
        Ok(id)
    }

    pub fn consume(
        &self,
        approval_id: &str,
        cell_id: &str,
        tool: &str,
        fingerprint: &str,
        now: i64,
    ) -> anyhow::Result<Use> {
        let _lock = self.lock()?;
        let mut records = self.load()?;
        Self::expire(&mut records, now);
        let result = match records.iter_mut().find(|r| r.approval_id == approval_id) {
            None => Use::NotFound,
            Some(r) if r.cell_id != cell_id || r.tool != tool || r.fingerprint != fingerprint => {
                Use::Mismatch
            }
            Some(r) => match r.status {
                Status::Pending => Use::Pending,
                Status::Denied => Use::Denied,
                Status::Expired => Use::Expired,
                Status::Consumed => Use::Consumed,
                Status::Approved => {
                    r.status = Status::Consumed;
                    Use::Authorized
                }
            },
        };
        self.save(&records)?;
        Ok(result)
    }

    pub fn list(&self, now: i64) -> anyhow::Result<Vec<Record>> {
        let _lock = self.lock()?;
        let mut records = self.load()?;
        Self::expire(&mut records, now);
        Ok(records)
    }

    /// Approves or denies a pending record. Records that are not pending
    /// cannot be decided again, so a consumed approval cannot be revived.
    pub fn decide(
        &self,
        approval_id: &str,
        approve: bool,
        reviewer: &str,
        now: i64,
    ) -> anyhow::Result<Record> {
        let _lock = self.lock()?;
        let mut records = self.load()?;
        Self::expire(&mut records, now);
        let r = records
            .iter_mut()
            .find(|r| r.approval_id == approval_id)
            .ok_or_else(|| anyhow::anyhow!("approval {approval_id} not found"))?;
        if r.status != Status::Pending {
            anyhow::bail!("approval {approval_id} is {:?}, not pending", r.status);
        }
        r.status = if approve {
            Status::Approved
        } else {
            Status::Denied
        };
        r.decided_ms = Some(now);
        r.expires_ms = now + self.ttl_ms;
        r.reviewer = Some(reviewer.to_string());
        let out = r.clone();
        self.save(&records)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_and_scope() {
        let dir = std::env::temp_dir().join(format!("ztac-appr-{}", uuid::Uuid::new_v4()));
        let s = Store::new(dir.join("a.json"), 60);
        let fp = fingerprint(
            "cell_a",
            "exec",
            &serde_json::json!({"cmd": "git", "args": ["commit"]}),
            "",
        );
        let id = s
            .request(
                "cell_a",
                "exec",
                &fp,
                "git commit",
                &serde_json::Value::Null,
                "",
                "r",
                0,
            )
            .unwrap();
        assert_eq!(
            s.consume(&id, "cell_a", "exec", &fp, 1).unwrap(),
            Use::Pending
        );
        s.decide(&id, true, "rev", 2).unwrap();
        assert_eq!(
            s.consume(&id, "cell_b", "exec", &fp, 3).unwrap(),
            Use::Mismatch
        );
        assert_eq!(
            s.consume(&id, "cell_a", "exec", "other", 3).unwrap(),
            Use::Mismatch
        );
        assert_eq!(
            s.consume(&id, "cell_a", "exec", &fp, 3).unwrap(),
            Use::Authorized
        );
        assert_eq!(
            s.consume(&id, "cell_a", "exec", &fp, 4).unwrap(),
            Use::Consumed
        );
        assert!(s.decide(&id, true, "rev", 5).is_err());
        let p = serde_json::json!({"path": "cert.txt"});
        assert_ne!(
            fingerprint("c", "fs_read", &p, "certs/dev.pem#1:2"),
            fingerprint("c", "fs_read", &p, ".env#1:3")
        );
    }

    #[test]
    fn consumption_survives_concurrent_review() {
        // A reviewer process approving other records must never write back a
        // stale copy in which a consumed approval is approved again.
        let dir = std::env::temp_dir().join(format!("ztac-appr-{}", uuid::Uuid::new_v4()));
        let path = dir.join("a.json");
        let s = Store::new(&path, 600);
        let null = serde_json::Value::Null;
        for round in 0..20 {
            let a = s
                .request("c", "exec", &format!("a{round}"), "", &null, "", "", 0)
                .unwrap();
            s.decide(&a, true, "rev", 0).unwrap();
            let others: Vec<String> = (0..20)
                .map(|i| {
                    s.request("c", "exec", &format!("b{round}-{i}"), "", &null, "", "", 0)
                        .unwrap()
                })
                .collect();
            let p2 = path.clone();
            let reviewer = std::thread::spawn(move || {
                let s = Store::new(&p2, 600);
                for id in others {
                    s.decide(&id, true, "rev", 1).unwrap();
                }
            });
            assert_eq!(
                s.consume(&a, "c", "exec", &format!("a{round}"), 1).unwrap(),
                Use::Authorized
            );
            reviewer.join().unwrap();
            assert_eq!(
                s.consume(&a, "c", "exec", &format!("a{round}"), 2).unwrap(),
                Use::Consumed
            );
        }
    }

    #[test]
    fn expiry() {
        let dir = std::env::temp_dir().join(format!("ztac-appr-{}", uuid::Uuid::new_v4()));
        let s = Store::new(dir.join("a.json"), 1);
        let id = s
            .request("c", "exec", "fp", "", &serde_json::Value::Null, "", "", 0)
            .unwrap();
        s.decide(&id, true, "rev", 0).unwrap();
        assert_eq!(
            s.consume(&id, "c", "exec", "fp", 5000).unwrap(),
            Use::Expired
        );
    }
}

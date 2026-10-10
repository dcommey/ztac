//! Wire protocol between a cell and the broker. Messages are newline-delimited
//! JSON over a Unix domain socket.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tool {
    Ping,
    FsRead,
    FsWrite,
    Exec,
    NetHttp,
}

impl Tool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tool::Ping => "ping",
            Tool::FsRead => "fs_read",
            Tool::FsWrite => "fs_write",
            Tool::Exec => "exec",
            Tool::NetHttp => "net_http",
        }
    }

    pub fn parse(s: &str) -> Option<Tool> {
        Some(match s {
            "ping" => Tool::Ping,
            "fs_read" => Tool::FsRead,
            "fs_write" => Tool::FsWrite,
            "exec" => Tool::Exec,
            "net_http" => Tool::NetHttp,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Tool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    NeedsApproval,
}

/// The signed portion of a request. Every field is covered by the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub request_id: String,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub cell_id: String,
    pub cell_pubkey: String,
    pub tool: Tool,
    pub params: Value,
    /// Free-text justification from the agent. Shown to reviewers and logged;
    /// never used for authorization.
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub request: Request,
    pub signature: String,
}

/// Per-stage broker timings in microseconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTimings {
    pub auth_us: u64,
    pub resolve_us: u64,
    pub policy_us: u64,
    pub execute_us: u64,
    pub audit_us: u64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub request_id: String,
    pub decision: Decision,
    pub reason: String,
    #[serde(default)]
    pub approval_id: Option<String>,
    #[serde(default)]
    pub result: Option<Value>,
    /// Hash of the audit record for this decision, signed by the broker.
    #[serde(default)]
    pub receipt: Option<Receipt>,
    #[serde(default)]
    pub timings: StageTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub event_hash: String,
    pub signature: String,
}

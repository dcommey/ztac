use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ztac_core::Tool;

/// How the broker mediates requests. `Ztac` is the system described in the
/// paper; the other two modes exist only as evaluation baselines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Ztac,
    /// Tool-level allowlist with lexical argument checks and no approval tier.
    Allowlist,
    /// The allowlist plus a workspace-write sandbox for spawned programs,
    /// modeled on the default sandbox modes of deployed coding agents:
    /// programs may read anywhere and write only the workspace and a
    /// temporary directory, with no network. The agent itself is unconfined.
    CommandSandbox,
    /// Executes every request as given (an agent with direct tool access).
    Permissive,
}

/// Individually switchable defenses, used for the ablation study. All are on
/// by default; the paper describes each one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Defenses {
    /// Verify signatures and require the cell key to be enrolled.
    pub authn: bool,
    /// Reject stale timestamps and reused nonces.
    pub freshness: bool,
    /// Classify the resolved target path rather than the requested string.
    pub resolved_classification: bool,
    /// Protect repository metadata and run git with a pinned configuration.
    pub vcs_guard: bool,
    /// Run every spawned program inside a Seatbelt profile derived from policy.
    pub exec_sandbox: bool,
    /// Bind network endpoints to host and port and refuse redirects.
    pub net_strict: bool,
    /// Scan URL and headers for secrets, not only the body.
    pub dlp_full: bool,
    /// Hold requests classified as high risk for human approval.
    pub approvals: bool,
    /// Bind approvals to the resolved object and repository state, not only
    /// to the request parameters.
    pub object_binding: bool,
    /// File adapters walk the resolved path with openat(O_NOFOLLOW) and check
    /// the identity of the object they reach; without it they open the path.
    pub fd_walk: bool,
    /// Spawned programs cannot create processes.
    pub no_fork: bool,
    /// Compile the path rules into the exec sandbox; without it the sandbox
    /// confines programs to the workspace but knows no rules inside it.
    pub sandbox_rules: bool,
}

impl Default for Defenses {
    fn default() -> Self {
        Defenses {
            authn: true,
            freshness: true,
            resolved_classification: true,
            vcs_guard: true,
            exec_sandbox: true,
            net_strict: true,
            dlp_full: true,
            approvals: true,
            object_binding: true,
            fd_walk: true,
            no_fork: true,
            sandbox_rules: true,
        }
    }
}

impl Defenses {
    pub fn none() -> Self {
        Defenses {
            authn: false,
            freshness: false,
            resolved_classification: false,
            vcs_guard: false,
            exec_sandbox: false,
            net_strict: false,
            dlp_full: false,
            approvals: false,
            object_binding: false,
            fd_walk: false,
            no_fork: false,
            sandbox_rules: false,
        }
    }

    pub fn set(&mut self, name: &str, value: bool) -> bool {
        let slot = match name {
            "authn" => &mut self.authn,
            "freshness" => &mut self.freshness,
            "resolved_classification" => &mut self.resolved_classification,
            "vcs_guard" => &mut self.vcs_guard,
            "exec_sandbox" => &mut self.exec_sandbox,
            "net_strict" => &mut self.net_strict,
            "dlp_full" => &mut self.dlp_full,
            "approvals" => &mut self.approvals,
            "object_binding" => &mut self.object_binding,
            "fd_walk" => &mut self.fd_walk,
            "no_fork" => &mut self.no_fork,
            "sandbox_rules" => &mut self.sandbox_rules,
            _ => return false,
        };
        *slot = value;
        true
    }

    pub const NAMES: [&'static str; 12] = [
        "authn",
        "freshness",
        "resolved_classification",
        "vcs_guard",
        "exec_sandbox",
        "net_strict",
        "dlp_full",
        "approvals",
        "object_binding",
        "fd_walk",
        "no_fork",
        "sandbox_rules",
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellGrant {
    pub name: String,
    /// Base64 Ed25519 public key.
    pub pubkey: String,
    #[serde(default = "all_tools")]
    pub tools: Vec<Tool>,
}

fn all_tools() -> Vec<Tool> {
    vec![
        Tool::Ping,
        Tool::FsRead,
        Tool::FsWrite,
        Tool::Exec,
        Tool::NetHttp,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Approve,
    Deny,
}

/// A path rule. `pattern` is a glob over the workspace-relative path
/// (`*` within a component, `**` across components). First match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsRule {
    pub pattern: String,
    pub access: Access,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramKind {
    /// git, with subcommand tiers and (under vcs_guard) a pinned configuration.
    Git,
    /// A program with no code-loading behavior, such as echo.
    Plain,
    /// A general interpreter. Allowed only inside the exec sandbox.
    Interpreter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    /// Name the cell uses in `cmd`.
    pub name: String,
    /// Absolute path, or a bare name resolved with `xcrun --find` then PATH.
    pub program: String,
    pub kind: ProgramKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEndpoint {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    /// Allowed without approval when true; otherwise approval is required.
    #[serde(default)]
    pub auto: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub fs_max_read_bytes: usize,
    pub fs_max_write_bytes: usize,
    pub exec_timeout_ms: u64,
    pub exec_max_output_bytes: usize,
    pub exec_max_args: usize,
    pub exec_max_arg_len: usize,
    pub net_timeout_ms: u64,
    pub net_max_request_bytes: usize,
    pub net_max_response_bytes: usize,
    pub max_request_bytes: usize,
    pub clock_skew_ms: i64,
    pub approval_ttl_s: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fs_max_read_bytes: 1 << 20,
            fs_max_write_bytes: 1 << 20,
            exec_timeout_ms: 10_000,
            exec_max_output_bytes: 1 << 20,
            exec_max_args: 64,
            exec_max_arg_len: 4096,
            net_timeout_ms: 5_000,
            net_max_request_bytes: 1 << 20,
            net_max_response_bytes: 1 << 20,
            max_request_bytes: 4 << 20,
            clock_skew_ms: 30_000,
            approval_ttl_s: 600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerConfig {
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub workspace_root: PathBuf,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub defenses: Defenses,
    #[serde(default)]
    pub cells: Vec<CellGrant>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "default_fs_rules")]
    pub fs_rules: Vec<FsRule>,
    #[serde(default = "default_programs")]
    pub programs: Vec<Program>,
    #[serde(default)]
    pub net: Vec<NetEndpoint>,
    #[serde(default = "default_dlp_patterns")]
    pub dlp_patterns: Vec<String>,
    /// fsync every audit record before acting on it.
    #[serde(default)]
    pub audit_sync: bool,
}

impl BrokerConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path.as_ref())?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn audit_path(&self) -> PathBuf {
        self.state_dir.join("audit.jsonl")
    }
    pub fn approvals_path(&self) -> PathBuf {
        self.state_dir.join("approvals.json")
    }
    pub fn signing_key_path(&self) -> PathBuf {
        self.state_dir.join("broker.key")
    }
}

fn rule(pattern: &str, access: Access, action: RuleAction) -> FsRule {
    FsRule {
        pattern: pattern.to_string(),
        access,
        action,
    }
}

pub fn default_fs_rules() -> Vec<FsRule> {
    use Access::*;
    use RuleAction::*;
    vec![
        rule("**/*.example", Any, Allow),
        rule("**/*.sample", Any, Allow),
        rule("**/.env", Any, Approve),
        rule("**/.env.*", Any, Approve),
        rule("**/*.pem", Any, Approve),
        rule("**/*.key", Any, Approve),
        rule("**/*.p12", Any, Approve),
        rule("**/id_rsa*", Any, Approve),
        rule("**/id_ed25519*", Any, Approve),
        rule("**/id_ecdsa*", Any, Approve),
        rule("**/.netrc", Any, Approve),
        rule("**/.npmrc", Any, Approve),
        rule("**/.pypirc", Any, Approve),
        rule("**/credentials*", Any, Approve),
        rule("**/*.sh", Write, Approve),
        rule("**/.envrc", Write, Approve),
        rule("**/.github/**", Write, Approve),
        rule("**/.gitattributes", Write, Approve),
        rule("**/.gitmodules", Write, Approve),
        // Files that other tools on the developer's machine execute or obey
        // after the session: editor and agent configuration that defines
        // tasks or hooks, the HEAD file that makes any directory a git
        // repository, and the interpreter and marker of a virtual environment,
        // which editors discover by content rather than directory name.
        rule("**/.vscode/**", Write, Approve),
        rule("**/.idea/**", Write, Approve),
        rule("**/.cursor/**", Write, Approve),
        rule("**/.claude/**", Write, Approve),
        rule("**/HEAD", Write, Approve),
        rule("**/pyvenv.cfg", Write, Approve),
        rule("**/bin/python*", Write, Approve),
    ]
}

pub fn default_programs() -> Vec<Program> {
    vec![
        Program {
            name: "git".into(),
            program: "git".into(),
            kind: ProgramKind::Git,
        },
        Program {
            name: "echo".into(),
            program: "/bin/echo".into(),
            kind: ProgramKind::Plain,
        },
        Program {
            name: "python3".into(),
            program: "python3".into(),
            kind: ProgramKind::Interpreter,
        },
    ]
}

pub fn default_dlp_patterns() -> Vec<String> {
    [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"AKIA[0-9A-Z]{16}",
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        r"sk-[A-Za-z0-9_-]{20,}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

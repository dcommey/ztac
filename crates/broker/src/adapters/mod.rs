pub mod exec;
pub mod fs;
pub mod net;

use serde_json::Value;

use crate::config::BrokerConfig;
use crate::policy::Policy;
use crate::resolve::Op;

/// `exempt` lists workspace files whose content this cell wrote; spawned
/// programs may read them even when a path rule would otherwise deny it.
pub fn execute(
    config: &BrokerConfig,
    policy: &Policy,
    workspace: &std::path::Path,
    cell_id: &str,
    op: &Op,
    exempt: &[std::path::PathBuf],
) -> anyhow::Result<Value> {
    match op {
        Op::Ping => Ok(serde_json::json!({"pong": true})),
        Op::FsRead { target, max_bytes } => fs::read(config, workspace, target, *max_bytes),
        Op::FsWrite {
            target,
            data,
            create_dirs,
        } => fs::write(config, workspace, target, data, *create_dirs),
        Op::Exec {
            program,
            args,
            cwd,
            timeout_ms,
        } => exec::run(
            config,
            policy,
            workspace,
            cell_id,
            program,
            args,
            cwd,
            *timeout_ms,
            exempt,
        ),
        Op::Net {
            url,
            method,
            headers,
            body,
            timeout_ms,
        } => net::send(config, url, method, headers, body.as_deref(), *timeout_ms),
    }
}

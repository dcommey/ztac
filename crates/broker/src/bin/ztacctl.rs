//! Operator CLI: key generation, approval review, and audit verification.

use std::path::PathBuf;

use ztac_broker::approval::{Status, Store};
use ztac_broker::audit;
use ztac_broker::config::BrokerConfig;
use ztac_core::keys::{cell_id_for_key, load_key, load_or_create_key, pubkey_b64};

const USAGE: &str = "\
ztacctl keygen <path>                         create a cell key, print cell_id and pubkey
ztacctl [--config C] approvals list [--status S]
ztacctl [--config C] approvals show <id>          full canonical parameters
ztacctl [--config C] approvals approve <id> [--by NAME]
ztacctl [--config C] approvals deny <id> [--by NAME]
ztacctl [--config C] audit verify";

fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config_path = PathBuf::from("config/broker.json");
    if args.len() >= 2 && args[0] == "--config" {
        config_path = PathBuf::from(&args[1]);
        args.drain(..2);
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let now = chrono::Utc::now().timestamp_millis();

    match a.as_slice() {
        ["keygen", path] => {
            let key = load_or_create_key(&PathBuf::from(path))?;
            println!("cell_id {}", cell_id_for_key(&key));
            println!("pubkey  {}", pubkey_b64(&key));
        }
        ["approvals", rest @ ..] => {
            let config = BrokerConfig::load(&config_path)?;
            let store = Store::new(config.approvals_path(), config.limits.approval_ttl_s);
            match rest {
                ["list"] | ["list", "--status", _] => {
                    let filter = rest.get(2).copied();
                    for r in store.list(now)? {
                        let status = format!("{:?}", r.status).to_lowercase();
                        if filter.is_some_and(|f| f != status) {
                            continue;
                        }
                        println!(
                            "{}  {:9}  {}  {}  [{}]  intent: {}",
                            r.approval_id, status, r.cell_id, r.summary, r.reason, r.intent
                        );
                    }
                }
                ["show", id] => {
                    let r = store
                        .list(now)?
                        .into_iter()
                        .find(|r| r.approval_id == *id)
                        .ok_or_else(|| anyhow::anyhow!("approval {id} not found"))?;
                    println!("{}", serde_json::to_string_pretty(&r)?);
                }
                ["approve", id, tail @ ..] | ["deny", id, tail @ ..] => {
                    let approve = rest[0] == "approve";
                    let by = match tail {
                        ["--by", name] => *name,
                        [] => "operator",
                        _ => anyhow::bail!("{USAGE}"),
                    };
                    let r = store.decide(id, approve, by, now)?;
                    let verb = if r.status == Status::Approved {
                        "approved"
                    } else {
                        "denied"
                    };
                    println!("{verb} {} ({})", r.approval_id, r.summary);
                }
                _ => anyhow::bail!("{USAGE}"),
            }
        }
        ["audit", "verify"] => {
            let config = BrokerConfig::load(&config_path)?;
            let key = load_key(&config.signing_key_path())?;
            match audit::verify(&config.audit_path(), &key.verifying_key()) {
                Ok(r) => println!("ok: {} records, head {}", r.records, r.head),
                Err(e) => {
                    println!("FAILED: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
    Ok(())
}

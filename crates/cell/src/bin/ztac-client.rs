//! Sends one signed request and prints the broker's response as JSON.
//!
//! usage: ztac-client [--socket S] [--key K] --tool T [--params JSON]
//!                    [--intent TEXT] [--approval ID]
//! Socket and key default to $ZTAC_SOCKET and $ZTAC_KEY.

use std::path::PathBuf;

use ztac_core::client::BrokerClient;
use ztac_core::keys::load_key;
use ztac_core::Tool;

fn main() -> anyhow::Result<()> {
    let mut socket = std::env::var("ZTAC_SOCKET").ok();
    let mut key = std::env::var("ZTAC_KEY").ok();
    let (mut tool, mut params, mut intent, mut approval) =
        (None, "{}".to_string(), String::new(), None);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next(),
            "--key" => key = args.next(),
            "--tool" => tool = args.next(),
            "--params" => params = args.next().unwrap_or_default(),
            "--intent" => intent = args.next().unwrap_or_default(),
            "--approval" => approval = args.next(),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let socket = PathBuf::from(socket.ok_or_else(|| anyhow::anyhow!("no socket"))?);
    let key = load_key(&PathBuf::from(
        key.ok_or_else(|| anyhow::anyhow!("no key"))?,
    ))?;
    let tool = tool.as_deref().and_then(Tool::parse).ok_or_else(|| {
        anyhow::anyhow!("--tool must be one of ping, fs_read, fs_write, exec, net_http")
    })?;
    let params: serde_json::Value = serde_json::from_str(&params)?;
    let mut client = BrokerClient::connect(&socket)?;
    let resp = client.call(&key, tool, params, &intent, approval)?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

use ztac_broker::config::BrokerConfig;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut config_path = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next(),
            "-h" | "--help" => {
                eprintln!("usage: ztac-broker --config <broker.json>");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    let path = config_path.ok_or_else(|| anyhow::anyhow!("--config is required"))?;
    let config = BrokerConfig::load(&path)?;
    ztac_broker::server::serve(config)
}

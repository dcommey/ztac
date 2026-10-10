use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::Method;
use serde_json::Value;
use url::Url;

use crate::config::{BrokerConfig, Mode};

pub fn send(
    config: &BrokerConfig,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    timeout_ms: u64,
) -> anyhow::Result<Value> {
    // A redirect sends the request to a destination the policy never saw, so
    // under net_strict every hop must itself be an endpoint the cell could
    // reach without approval.
    let redirects = if config.mode == Mode::Ztac && config.defenses.net_strict {
        let cfg = config.clone();
        RedirectPolicy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            match crate::policy::endpoint_for(&cfg, attempt.url()) {
                Some(e) if e.auto => attempt.follow(),
                _ => attempt.stop(),
            }
        })
    } else {
        RedirectPolicy::limited(10)
    };
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(redirects)
        .no_proxy()
        .build()?;
    let mut req = client.request(Method::from_bytes(method.as_bytes())?, url.clone());
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = body {
        req = req.body(b.to_string());
    }
    let resp = req.send()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let mut buf = Vec::new();
    resp.take(config.limits.net_max_response_bytes as u64)
        .read_to_end(&mut buf)?;
    Ok(serde_json::json!({
        "status": status,
        "final_url": final_url,
        "body": String::from_utf8_lossy(&buf),
    }))
}

//! Broker client over a persistent Unix-socket connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::Context;
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::keys::{build_request, sign};
use crate::proto::{Envelope, Response, Tool};

pub struct BrokerClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl BrokerClient {
    pub fn connect(socket: &Path) -> anyhow::Result<Self> {
        let stream = UnixStream::connect(socket)
            .with_context(|| format!("connecting to broker at {}", socket.display()))?;
        Ok(Self {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        })
    }

    /// Sends a raw line and returns the raw reply line. Used by the evaluation
    /// to submit malformed or replayed envelopes.
    pub fn send_raw(&mut self, line: &str) -> anyhow::Result<String> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        let mut reply = String::new();
        self.reader.read_line(&mut reply)?;
        if reply.is_empty() {
            anyhow::bail!("broker closed the connection");
        }
        Ok(reply)
    }

    pub fn send_envelope(&mut self, envelope: &Envelope) -> anyhow::Result<Response> {
        let reply = self.send_raw(&serde_json::to_string(envelope)?)?;
        serde_json::from_str(reply.trim()).with_context(|| format!("bad broker reply: {reply}"))
    }

    pub fn call(
        &mut self,
        key: &SigningKey,
        tool: Tool,
        params: Value,
        intent: &str,
        approval_id: Option<String>,
    ) -> anyhow::Result<Response> {
        let envelope = sign(key, build_request(key, tool, params, intent, approval_id))?;
        self.send_envelope(&envelope)
    }
}

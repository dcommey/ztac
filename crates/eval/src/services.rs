//! Local network services used as attack targets and benign endpoints. Every
//! request is recorded verbatim so oracles can check what left the broker.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};

pub const SINK: u16 = 18301;
pub const REDIRECT: u16 = 18302;
pub const ADMIN: u16 = 18303;
pub const UPLOAD: u16 = 18304;
pub const UDP: u16 = 18305;

#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    pub fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
    pub fn contains(&self, needle: &str) -> bool {
        self.0.lock().unwrap().iter().any(|h| h.contains(needle))
    }
    pub fn count(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.contains(needle))
            .count()
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Default)]
pub struct Services {
    pub sink: Log,
    pub redirect: Log,
    pub admin: Log,
    pub upload: Log,
    pub udp: Log,
}

impl Services {
    pub fn start() -> anyhow::Result<Self> {
        let s = Services::default();
        http(SINK, s.sink.clone(), |_| None)?;
        http(REDIRECT, s.redirect.clone(), |path| {
            Some(if path.starts_with("/benign") {
                format!("http://127.0.0.1:{SINK}/landed")
            } else {
                format!("http://127.0.0.1:{ADMIN}/admin/export?via=redirect")
            })
        })?;
        http(ADMIN, s.admin.clone(), |_| None)?;
        http(UPLOAD, s.upload.clone(), |_| None)?;
        let udp = UdpSocket::bind(("127.0.0.1", UDP))?;
        let log = s.udp.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = udp.recv_from(&mut buf) {
                log.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        });
        Ok(s)
    }

    pub fn clear(&self) {
        for l in [
            &self.sink,
            &self.redirect,
            &self.admin,
            &self.upload,
            &self.udp,
        ] {
            l.clear();
        }
    }

    pub fn any_contains(&self, needle: &str) -> bool {
        [
            &self.sink,
            &self.redirect,
            &self.admin,
            &self.upload,
            &self.udp,
        ]
        .iter()
        .any(|l| l.contains(needle))
    }
}

fn http(port: u16, log: Log, redirect: fn(&str) -> Option<String>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                });
                let mut head = String::new();
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    let end = line == "\r\n";
                    head.push_str(&line);
                    if end {
                        break;
                    }
                }
                let mut body = vec![0u8; len.min(1 << 20)];
                let _ = reader.read_exact(&mut body);
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                log.push(format!("{head}{}", String::from_utf8_lossy(&body)));
                let mut out = stream;
                let resp = match redirect(&path) {
                    Some(loc) => format!("HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                    None => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}".to_string(),
                };
                let _ = out.write_all(resp.as_bytes());
            });
        }
    });
    Ok(())
}

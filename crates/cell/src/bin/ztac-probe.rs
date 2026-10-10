//! Attempts one direct operating-system action, bypassing the broker, and
//! reports whether the kernel permitted it. The evaluation runs this inside
//! and outside a cell to test the enforcement boundary.
//!
//! usage: ztac-probe <action> [args...]
//!   read <path>                 print the file's contents
//!   list <dir>                  print directory entries
//!   write <path> <text>         create or overwrite a file
//!   append <path> <text>        append to a file
//!   tcp <host:port> <text>      HTTP POST text to a TCP endpoint
//!   udp <host:port> <text>      send one datagram
//!   exec <path> [args...]       spawn a program
//!   signal <pid>                send SIGCONT (harmless) to a process
//!   broker                      send a signed ping through the broker

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

fn run(args: &[String]) -> Result<String, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["read", path] => std::fs::read(path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .map_err(|e| e.to_string()),
        ["list", dir] => std::fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .map(|e| {
                e.map(|e| e.file_name().to_string_lossy().into_owned())
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|v| v.join("\n")),
        ["write", path, text] => std::fs::write(path, text)
            .map(|_| "written".into())
            .map_err(|e| e.to_string()),
        ["append", path, text] => std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .map(|_| "appended".into())
            .map_err(|e| e.to_string()),
        ["tcp", addr, text] => {
            let mut s = TcpStream::connect_timeout(
                &addr.parse().map_err(|e| format!("{e}"))?,
                Duration::from_secs(2),
            )
            .map_err(|e| e.to_string())?;
            let req = format!(
                "POST /probe HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
            s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
            let mut reply = String::new();
            let _ = s.read_to_string(&mut reply);
            Ok(reply.lines().next().unwrap_or("").to_string())
        }
        ["udp", addr, text] => {
            let s = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            s.send_to(text.as_bytes(), addr)
                .map(|n| format!("sent {n}"))
                .map_err(|e| e.to_string())
        }
        ["exec", path, rest @ ..] => std::process::Command::new(path)
            .args(rest)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .map_err(|e| e.to_string()),
        ["signal", pid] => {
            let pid: i32 = pid.parse().map_err(|_| "bad pid".to_string())?;
            // SAFETY: kill(2) with a valid signal number has no memory effects.
            let rc = unsafe { libc::kill(pid, libc::SIGCONT) };
            if rc == 0 {
                Ok("signalled".into())
            } else {
                Err(std::io::Error::last_os_error().to_string())
            }
        }
        ["broker"] => {
            let socket = PathBuf::from(std::env::var("ZTAC_SOCKET").map_err(|_| "no ZTAC_SOCKET")?);
            let key = ztac_core::keys::load_key(&PathBuf::from(
                std::env::var("ZTAC_KEY").map_err(|_| "no ZTAC_KEY")?,
            ))
            .map_err(|e| e.to_string())?;
            let mut c =
                ztac_core::client::BrokerClient::connect(&socket).map_err(|e| e.to_string())?;
            let r = c
                .call(
                    &key,
                    ztac_core::Tool::Ping,
                    serde_json::json!({}),
                    "probe",
                    None,
                )
                .map_err(|e| e.to_string())?;
            Ok(format!("{:?}", r.decision))
        }
        _ => Err("unknown probe".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match run(&args) {
        Ok(detail) => serde_json::json!({"permitted": true, "detail": detail}),
        Err(e) => serde_json::json!({"permitted": false, "detail": e}),
    };
    println!("{out}");
}

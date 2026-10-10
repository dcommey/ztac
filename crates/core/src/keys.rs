//! Cell key handling and request signing.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::canon::to_canonical_bytes;
use crate::proto::{Envelope, Request, Tool};

pub fn load_key(path: &Path) -> anyhow::Result<SigningKey> {
    let raw = fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file {} must hold 32 bytes", path.display()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Loads a key, or creates one with mode 0600 if the file does not exist.
pub fn load_or_create_key(path: &Path) -> anyhow::Result<SigningKey> {
    if path.exists() {
        return load_key(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key = SigningKey::generate(&mut OsRng);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating key {}", path.display()))?;
    file.write_all(&key.to_bytes())?;
    Ok(key)
}

pub fn pubkey_b64(key: &SigningKey) -> String {
    STANDARD.encode(key.verifying_key().to_bytes())
}

/// A cell identifier is derived from its public key, so a cell cannot claim
/// an identifier without holding the matching private key.
pub fn cell_id_for_pubkey(pubkey: &[u8]) -> String {
    let digest = Sha256::digest(pubkey);
    format!("cell_{}", &hex::encode(digest)[..16])
}

pub fn cell_id_for_key(key: &SigningKey) -> String {
    cell_id_for_pubkey(&key.verifying_key().to_bytes())
}

pub fn signing_payload(request: &Request) -> serde_json::Result<Vec<u8>> {
    let mut bytes = b"ztac-request-v1\n".to_vec();
    bytes.extend(to_canonical_bytes(request)?);
    Ok(bytes)
}

pub fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn build_request(
    key: &SigningKey,
    tool: Tool,
    params: Value,
    intent: &str,
    approval_id: Option<String>,
) -> Request {
    Request {
        request_id: uuid::Uuid::new_v4().to_string(),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
        nonce: random_token(16),
        cell_id: cell_id_for_key(key),
        cell_pubkey: pubkey_b64(key),
        tool,
        params,
        intent: intent.to_string(),
        approval_id,
    }
}

pub fn sign(key: &SigningKey, request: Request) -> anyhow::Result<Envelope> {
    let payload = signing_payload(&request)?;
    let signature = STANDARD.encode(key.sign(&payload).to_bytes());
    Ok(Envelope { request, signature })
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadPublicKey,
    BadSignatureEncoding,
    SignatureMismatch,
    CellIdMismatch,
}

/// Checks the signature and that `cell_id` is the one derived from the key.
pub fn verify(envelope: &Envelope) -> Result<[u8; 32], VerifyError> {
    let req = &envelope.request;
    let pk: [u8; 32] = STANDARD
        .decode(&req.cell_pubkey)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::BadPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::BadPublicKey)?;
    let sig: [u8; 64] = STANDARD
        .decode(&envelope.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::BadSignatureEncoding)?;
    let payload = signing_payload(req).map_err(|_| VerifyError::SignatureMismatch)?;
    vk.verify_strict(&payload, &Signature::from_bytes(&sig))
        .map_err(|_| VerifyError::SignatureMismatch)?;
    if cell_id_for_pubkey(&pk) != req.cell_id {
        return Err(VerifyError::CellIdMismatch);
    }
    Ok(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trip_and_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let req = build_request(&key, Tool::Ping, serde_json::json!({}), "t", None);
        let env = sign(&key, req).unwrap();
        assert!(verify(&env).is_ok());

        let mut tampered = env.clone();
        tampered.request.params = serde_json::json!({"x": 1});
        assert_eq!(verify(&tampered), Err(VerifyError::SignatureMismatch));

        let other = SigningKey::generate(&mut OsRng);
        let mut spoofed = env;
        spoofed.request.cell_id = cell_id_for_key(&other);
        assert_eq!(verify(&spoofed), Err(VerifyError::SignatureMismatch));
    }
}

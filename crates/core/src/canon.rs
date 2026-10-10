//! Canonical JSON encoding used for signatures, approval fingerprints, and
//! audit hashes. Object keys are sorted recursively and the output carries no
//! insignificant whitespace, so two parties that hold the same logical value
//! always hash the same bytes.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let mut map = Map::with_capacity(obj.len());
            for key in keys {
                map.insert(key.clone(), canonicalize(&obj[key]));
            }
            Value::Object(map)
        }
        _ => value.clone(),
    }
}

pub fn to_canonical_bytes<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize(&value))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_order_does_not_change_encoding() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":[{"k":1,"j":2}]}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":[{"j":2,"k":1}],"y":2},"b":1}"#).unwrap();
        assert_eq!(
            to_canonical_bytes(&a).unwrap(),
            to_canonical_bytes(&b).unwrap()
        );
    }
}

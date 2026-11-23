//! HS256 JWTs for scoped tool execution.
//!
//! A tool token says *which* tools an agent may call, *for whom*, and *until when*.
//! `verify` checks signature, `exp`/`nbf` (with clock skew), audience and one required scope.

use crate::{b64, field, str_field, u64_field};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

pub const SKEW_SECS: u64 = 30;

fn sign(secret: &[u8], msg: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("any key size works");
    mac.update(msg.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn encode(claims: &Value, secret: &str) -> Result<String, String> {
    if secret.len() < 32 {
        return Err("secret must be at least 32 bytes for HS256".into());
    }
    let head = b64::encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let body = b64::encode(claims.to_string().as_bytes());
    let msg = format!("{head}.{body}");
    let sig = b64::encode(&sign(secret.as_bytes(), &msg));
    Ok(format!("{msg}.{sig}"))
}

/// Decode and check the signature only (no time / scope checks).
pub fn decode(token: &str, secret: &str) -> Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("token must have 3 parts".into());
    }
    let header: Value =
        serde_json::from_slice(&b64::decode(parts[0])?).map_err(|_| "bad header")?;
    if header["alg"] != "HS256" {
        // Refuse `none` and algorithm-confusion tricks.
        return Err(format!("alg {} not allowed", header["alg"]));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    mac.verify_slice(&b64::decode(parts[2])?)
        .map_err(|_| "bad signature".to_string())?; // constant-time compare
    serde_json::from_slice(&b64::decode(parts[1])?).map_err(|_| "bad claims".to_string())
}

pub fn scopes(claims: &Value) -> Vec<String> {
    claims["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect()
}

/// Full check: signature, time window, audience, one required scope.
pub fn verify(
    token: &str,
    secret: &str,
    aud: &str,
    scope: &str,
    now: u64,
) -> Result<Value, String> {
    let c = decode(token, secret)?;
    let exp = c["exp"].as_u64().ok_or("missing exp")?;
    if now > exp + SKEW_SECS {
        return Err("token expired".into());
    }
    if let Some(nbf) = c["nbf"].as_u64() {
        if now + SKEW_SECS < nbf {
            return Err("token not yet valid".into());
        }
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == aud,
        Value::Array(a) => a.iter().any(|x| x == aud),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("audience mismatch (want {aud})"));
    }
    if !scopes(&c).iter().any(|s| s == scope) {
        return Err(format!("missing scope `{scope}`"));
    }
    Ok(c)
}

pub fn issue_op(i: &Value) -> Result<Value, String> {
    let now = u64_field(i, "now")?;
    let ttl = i["ttl_secs"].as_u64().unwrap_or(300);
    if ttl > 3600 {
        return Err("ttl_secs over 3600: tool tokens must be short-lived".into());
    }
    let scopes: Vec<&str> = field(i, "scopes")?
        .as_array()
        .ok_or("`scopes` must be a list")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if scopes.is_empty() {
        return Err("at least one scope is required".into());
    }
    let mut claims = Map::new();
    claims.insert(
        "iss".into(),
        json!(i["iss"].as_str().unwrap_or("fde-agent-rbac")),
    );
    claims.insert("sub".into(), json!(str_field(i, "sub")?));
    claims.insert("aud".into(), json!(str_field(i, "aud")?));
    claims.insert("iat".into(), json!(now));
    claims.insert("nbf".into(), json!(now));
    claims.insert("exp".into(), json!(now + ttl));
    claims.insert("scope".into(), json!(scopes.join(" ")));
    if let Some(extra) = i["claims"].as_object() {
        for (k, v) in extra {
            claims.entry(k.clone()).or_insert(v.clone());
        }
    }
    let claims = Value::Object(claims);
    let token = encode(&claims, str_field(i, "secret")?)?;
    Ok(json!({"token": token, "claims": claims}))
}

pub fn verify_op(i: &Value) -> Result<Value, String> {
    match verify(
        str_field(i, "token")?,
        str_field(i, "secret")?,
        str_field(i, "aud")?,
        str_field(i, "required_scope")?,
        u64_field(i, "now")?,
    ) {
        Ok(c) => Ok(json!({"allowed": true, "claims": c})),
        Err(e) => Ok(json!({"allowed": false, "reason": e})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: &str = "0123456789abcdef0123456789abcdef";

    fn tok(now: u64) -> String {
        let r = issue_op(&json!({"now": now, "sub": "agent-7", "aud": "crm-tools",
            "scopes": ["crm.read", "crm.note.write"], "secret": K, "ttl_secs": 60}))
        .unwrap();
        r["token"].as_str().unwrap().to_string()
    }

    #[test]
    fn valid_token_with_scope_passes() {
        assert!(verify(&tok(1000), K, "crm-tools", "crm.read", 1010).is_ok());
    }
    #[test]
    fn missing_scope_fails() {
        let e = verify(&tok(1000), K, "crm-tools", "crm.delete", 1010).unwrap_err();
        assert!(e.contains("missing scope"));
    }
    #[test]
    fn expired_fails_after_skew() {
        assert!(verify(&tok(1000), K, "crm-tools", "crm.read", 1060 + SKEW_SECS).is_ok());
        assert!(verify(&tok(1000), K, "crm-tools", "crm.read", 1061 + SKEW_SECS).is_err());
    }
    #[test]
    fn wrong_audience_fails() {
        assert!(verify(&tok(1000), K, "billing", "crm.read", 1010).is_err());
    }
    #[test]
    fn tampered_payload_fails() {
        let t = tok(1000);
        let p: Vec<&str> = t.split('.').collect();
        let forged = b64::encode(
            br#"{"sub":"admin","aud":"crm-tools","exp":99999999,"scope":"crm.delete"}"#,
        );
        let bad = format!("{}.{}.{}", p[0], forged, p[2]);
        assert_eq!(decode(&bad, K).unwrap_err(), "bad signature");
    }
    #[test]
    fn alg_none_refused() {
        let head = b64::encode(br#"{"alg":"none"}"#);
        let body = b64::encode(br#"{"exp":1}"#);
        assert!(decode(&format!("{head}.{body}."), K)
            .unwrap_err()
            .contains("not allowed"));
    }
    #[test]
    fn short_secret_refused() {
        assert!(encode(&json!({}), "short").is_err());
    }
    #[test]
    fn long_ttl_refused() {
        let r = issue_op(
            &json!({"now": 1, "sub": "a", "aud": "b", "scopes": ["x"], "secret": K, "ttl_secs": 86400}),
        );
        assert!(r.is_err());
    }
}

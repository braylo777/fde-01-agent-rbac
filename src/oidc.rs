//! OIDC ID-token claim validation (OpenID Connect Core §3.1.3.7).
//!
//! Signature checks need the IdP's JWKS (RS256/ES256) and are out of scope here; this module
//! does the claim checks that teams most often get wrong after the signature passes.

use crate::{field, str_field, u64_field};
use serde_json::{json, Value};

pub fn validate(
    claims: &Value,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
    now: u64,
) -> Vec<String> {
    let mut errs = Vec::new();
    if claims["iss"] != issuer {
        errs.push(format!("iss must equal {issuer}"));
    }
    let aud_ok = match &claims["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(a) => {
            let has = a.iter().any(|x| x == client_id);
            if has && a.len() > 1 && claims["azp"] != client_id {
                errs.push("multiple audiences: azp must equal client_id".into());
            }
            has
        }
        _ => false,
    };
    if !aud_ok {
        errs.push("aud must contain client_id".into());
    }
    match claims["exp"].as_u64() {
        Some(exp) if now <= exp + 60 => {}
        Some(_) => errs.push("token expired".into()),
        None => errs.push("exp missing".into()),
    }
    match claims["iat"].as_u64() {
        Some(iat) if iat <= now + 60 => {}
        Some(_) => errs.push("iat is in the future".into()),
        None => errs.push("iat missing".into()),
    }
    if let Some(n) = nonce {
        if claims["nonce"] != n {
            errs.push("nonce mismatch (possible replay)".into());
        }
    }
    if claims["sub"].as_str().map(str::is_empty).unwrap_or(true) {
        errs.push("sub missing".into());
    }
    errs
}

pub fn validate_op(i: &Value) -> Result<Value, String> {
    let errs = validate(
        field(i, "claims")?,
        str_field(i, "issuer")?,
        str_field(i, "client_id")?,
        i["nonce"].as_str(),
        u64_field(i, "now")?,
    );
    Ok(json!({"valid": errs.is_empty(), "errors": errs}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Value {
        json!({"iss": "https://idp.example", "aud": "app", "sub": "123", "exp": 2000, "iat": 1000, "nonce": "n1"})
    }
    #[test]
    fn good_token_passes() {
        assert!(validate(&good(), "https://idp.example", "app", Some("n1"), 1500).is_empty());
    }
    #[test]
    fn nonce_replay_caught() {
        assert!(!validate(&good(), "https://idp.example", "app", Some("n2"), 1500).is_empty());
    }
    #[test]
    fn multi_aud_needs_azp() {
        let mut c = good();
        c["aud"] = json!(["app", "other"]);
        assert_eq!(
            validate(&c, "https://idp.example", "app", None, 1500).len(),
            1
        );
        c["azp"] = json!("app");
        assert!(validate(&c, "https://idp.example", "app", None, 1500).is_empty());
    }
    #[test]
    fn wrong_issuer_and_expired() {
        assert_eq!(
            validate(&good(), "https://evil", "app", None, 5000).len(),
            2
        );
    }
}

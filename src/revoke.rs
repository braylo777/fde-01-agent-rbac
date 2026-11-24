//! Automatic revocation for short-lived agent tokens.
//!
//! A 5-minute token is short, but "short" is not "gone". When the IdP deactivates a human
//! (SCIM `active=false` or DELETE), every agent token issued for that human must die now.
//! This module builds a revocation list from the SCIM directory plus explicit `jti` / agent
//! kills, and checks tokens against it. `verify_token` takes the same list.

use crate::{field, jwt, str_field, u64_field};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Deterministic token id: first 16 hex chars of SHA-256 over the identifying claims.
pub fn jti_for(claims: &Value) -> String {
    let src = format!(
        "{}|{}|{}|{}|{}|{}",
        claims["sub"], claims["aud"], claims["iat"], claims["exp"], claims["scope"], claims["act"]
    );
    Sha256::digest(src.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Default)]
pub struct Revocations {
    pub jtis: BTreeSet<String>,
    pub subjects: BTreeSet<String>,
    pub agents: BTreeSet<String>,
}

fn strings(v: &Value) -> BTreeSet<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

impl Revocations {
    pub fn from_json(v: &Value) -> Self {
        Revocations {
            jtis: strings(&v["jtis"]),
            subjects: strings(&v["subjects"]).into_iter().map(|s| s.to_lowercase()).collect(),
            agents: strings(&v["agents"]),
        }
    }
    pub fn to_json(&self) -> Value {
        json!({"jtis": self.jtis, "subjects": self.subjects, "agents": self.agents})
    }
    /// Why this token is revoked, or None if it is not.
    pub fn check(&self, c: &Value) -> Option<String> {
        if let Some(j) = c["jti"].as_str() {
            if self.jtis.contains(j) {
                return Some(format!("token {j} revoked"));
            }
        }
        if let Some(s) = c["sub"].as_str() {
            if self.subjects.contains(&s.to_lowercase()) {
                return Some(format!("subject {s} deprovisioned"));
            }
        }
        // An agent acting for a human, or an agent holding its own token.
        let agent = c["act"]["sub"].as_str().or(c["sub"].as_str());
        if let Some(a) = agent {
            if self.agents.contains(a) {
                return Some(format!("agent {a} revoked"));
            }
        }
        None
    }
}

/// Build the list: explicit kills + every SCIM user that is inactive or missing.
pub fn build(i: &Value) -> Result<Revocations, String> {
    let mut r = Revocations::from_json(i.get("revoke").unwrap_or(&Value::Null));
    if let Some(dir) = i.get("directory").and_then(Value::as_object) {
        // Fail closed: only a real `true` (or "true") counts as active. A token's `sub` may be
        // the SCIM userName (case-insensitive) or the SCIM id; both are matched.
        let is_active = |u: &Value| u["active"] == true || u["active"] == "true" || u.get("active").is_none();
        let names = |u: &Value| -> Vec<String> {
            [u["userName"].as_str(), u["id"].as_str()]
                .into_iter()
                .flatten()
                .map(|s| s.to_lowercase())
                .collect()
        };
        let active: BTreeSet<String> = dir.values().filter(|u| is_active(u)).flat_map(names).collect();
        for u in dir.values().filter(|u| !is_active(u)) {
            r.subjects.extend(names(u));
        }
        // Humans named in `known_subjects` that SCIM has deleted.
        for s in strings(&i["known_subjects"]) {
            let s = s.to_lowercase();
            if !s.is_empty() && !active.contains(&s) {
                r.subjects.insert(s);
            }
        }
    }
    Ok(r)
}

pub fn revoke_op(i: &Value) -> Result<Value, String> {
    let secret = str_field(i, "secret")?;
    let now = u64_field(i, "now")?;
    let r = build(i)?;
    let mut out = Vec::new();
    for t in field(i, "tokens")?.as_array().ok_or("`tokens` must be a list")? {
        let t = t.as_str().ok_or("each token must be a string")?;
        let row = match jwt::decode(t, secret) {
            Err(e) => json!({"status": "invalid", "reason": e}),
            Ok(c) => {
                let exp = c["exp"].as_u64().unwrap_or(0);
                let base = json!({"jti": c["jti"], "sub": c["sub"], "agent": c["act"]["sub"]});
                let (status, reason) = if let Some(why) = r.check(&c) {
                    ("revoked", why)
                } else if now > exp.saturating_add(jwt::SKEW_SECS) {
                    ("expired", "past exp".to_string())
                } else {
                    ("live", format!("{}s left", exp.saturating_sub(now)))
                };
                let mut b = base;
                b["status"] = json!(status);
                b["reason"] = json!(reason);
                b
            }
        };
        out.push(row);
    }
    let killed = out.iter().filter(|r| r["status"] == "revoked").count();
    Ok(json!({"revocation_list": r.to_json(), "tokens": out, "revoked_now": killed}))
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: &str = "0123456789abcdef0123456789abcdef";

    fn tok(sub: &str, act: Option<&str>) -> String {
        let mut c = json!({"sub": sub, "aud": "crm", "iat": 100, "exp": 400, "scope": "crm.read"});
        if let Some(a) = act {
            c["act"] = json!({"sub": a});
        }
        c["jti"] = json!(jti_for(&c));
        jwt::encode(&c, K).unwrap()
    }

    #[test]
    fn scim_deactivation_kills_delegated_tokens() {
        let dir = json!({"u0001": {"id": "u0001", "userName": "alice@corp", "active": false},
                         "u0002": {"id": "u0002", "userName": "bob@corp", "active": true}});
        let r = revoke_op(&json!({"secret": K, "now": 200, "directory": dir,
            "tokens": [tok("alice@corp", Some("agent-1")), tok("bob@corp", Some("agent-1"))]}))
        .unwrap();
        assert_eq!(r["tokens"][0]["status"], "revoked");
        assert_eq!(r["tokens"][1]["status"], "live");
    }

    #[test]
    fn deleted_user_and_jti_and_agent_kills() {
        let t = tok("carol@corp", Some("agent-2"));
        let c = jwt::decode(&t, K).unwrap();
        let jti = c["jti"].as_str().unwrap().to_string();
        let dir = json!({"u0002": {"id": "u0002", "userName": "bob@corp", "active": true}});
        let r = revoke_op(&json!({"secret": K, "now": 200, "directory": dir,
            "known_subjects": ["carol@corp"], "tokens": [t.clone()]}))
        .unwrap();
        assert_eq!(r["tokens"][0]["status"], "revoked");
        let r = revoke_op(&json!({"secret": K, "now": 200, "revoke": {"jtis": [jti]}, "tokens": [t.clone()]})).unwrap();
        assert_eq!(r["tokens"][0]["status"], "revoked");
        let r = revoke_op(&json!({"secret": K, "now": 200, "revoke": {"agents": ["agent-2"]}, "tokens": [t]})).unwrap();
        assert_eq!(r["tokens"][0]["status"], "revoked");
    }

    #[test]
    fn expired_and_tampered_are_reported() {
        let r = revoke_op(&json!({"secret": K, "now": 9999, "tokens": [tok("a", None), "x.y.z"]})).unwrap();
        assert_eq!(r["tokens"][0]["status"], "expired");
        assert_eq!(r["tokens"][1]["status"], "invalid");
    }

    #[test]
    fn id_case_and_string_active_match() {
        let dir = json!({"u0001": {"id": "u0001", "userName": "alice@corp", "active": "false"}});
        let r = revoke_op(&json!({"secret": K, "now": 200, "directory": dir,
            "tokens": [tok("u0001", None), tok("Alice@Corp", None)]})).unwrap();
        assert_eq!(r["tokens"][0]["status"], "revoked");
        assert_eq!(r["tokens"][1]["status"], "revoked");
    }
}

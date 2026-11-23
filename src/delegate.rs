//! Agent-to-human delegated tokens (modelled on OAuth 2.0 Token Exchange, RFC 8693).
//!
//! The agent presents the human's token (the *subject token*). The issuer mints a new token:
//! * `sub` stays the human, `act.sub` is the agent — audit logs show both.
//! * scopes = requested ∩ human's scopes ∩ agent's allow-list (never wider than either).
//! * lifetime = min(requested, human token's remaining life, 15 min).

use crate::{field, jwt, str_field, u64_field};
use serde_json::{json, Value};

pub const MAX_DELEGATED_TTL: u64 = 900;

pub fn exchange_op(i: &Value) -> Result<Value, String> {
    let secret = str_field(i, "secret")?;
    let now = u64_field(i, "now")?;
    let human = jwt::decode(str_field(i, "subject_token")?, secret)?;
    let h_exp = human["exp"].as_u64().ok_or("subject token has no exp")?;
    if now > h_exp {
        return Err("subject token expired".into());
    }
    let list = |k: &str| -> Result<Vec<String>, String> {
        Ok(field(i, k)?
            .as_array()
            .ok_or(format!("`{k}` must be a list"))?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
    };
    let requested = list("requested_scopes")?;
    let agent_allowed = list("agent_allowed_scopes")?;
    let human_scopes = jwt::scopes(&human);
    let mut granted = Vec::new();
    let mut denied = Vec::new();
    for s in &requested {
        if human_scopes.contains(s) && agent_allowed.contains(s) {
            granted.push(s.clone());
        } else {
            let why = if !human_scopes.contains(s) {
                "human lacks it"
            } else {
                "agent not allowed"
            };
            denied.push(json!({"scope": s, "why": why}));
        }
    }
    if granted.is_empty() {
        return Ok(json!({"issued": false, "denied": denied}));
    }
    let want = i["ttl_secs"].as_u64().unwrap_or(MAX_DELEGATED_TTL);
    let ttl = want.min(MAX_DELEGATED_TTL).min(h_exp - now);
    let claims = json!({
        "iss": "fde-agent-rbac",
        "sub": human["sub"],
        "aud": str_field(i, "audience")?,
        "iat": now, "nbf": now, "exp": now + ttl,
        "scope": granted.join(" "),
        "act": {"sub": str_field(i, "agent_id")?},
        "delegated": true
    });
    Ok(
        json!({"issued": true, "token": jwt::encode(&claims, secret)?, "claims": claims, "denied": denied}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const K: &str = "0123456789abcdef0123456789abcdef";

    fn human(now: u64, ttl: u64) -> String {
        let c = json!({"sub": "alice@corp", "aud": "idp", "exp": now + ttl, "scope": "crm.read crm.write email.send"});
        jwt::encode(&c, K).unwrap()
    }

    #[test]
    fn scopes_are_intersected_and_actor_recorded() {
        let r = exchange_op(
            &json!({"secret": K, "now": 100, "subject_token": human(100, 3600),
            "agent_id": "agent-sales", "audience": "crm-tools",
            "requested_scopes": ["crm.read", "email.send", "hr.read"],
            "agent_allowed_scopes": ["crm.read", "hr.read"]}),
        )
        .unwrap();
        assert_eq!(r["claims"]["scope"], "crm.read");
        assert_eq!(r["claims"]["sub"], "alice@corp");
        assert_eq!(r["claims"]["act"]["sub"], "agent-sales");
        assert_eq!(r["denied"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ttl_never_outlives_human_token() {
        let r = exchange_op(
            &json!({"secret": K, "now": 100, "subject_token": human(100, 60),
            "agent_id": "a", "audience": "x", "requested_scopes": ["crm.read"],
            "agent_allowed_scopes": ["crm.read"]}),
        )
        .unwrap();
        assert_eq!(r["claims"]["exp"], 160);
    }

    #[test]
    fn nothing_granted_means_no_token() {
        let r = exchange_op(
            &json!({"secret": K, "now": 100, "subject_token": human(100, 600),
            "agent_id": "a", "audience": "x", "requested_scopes": ["hr.read"],
            "agent_allowed_scopes": ["crm.read"]}),
        )
        .unwrap();
        assert_eq!(r["issued"], false);
    }

    #[test]
    fn expired_human_token_refused() {
        let r = exchange_op(
            &json!({"secret": K, "now": 1000, "subject_token": human(100, 60),
            "agent_id": "a", "audience": "x", "requested_scopes": ["crm.read"], "agent_allowed_scopes": ["crm.read"]}),
        );
        assert!(r.is_err());
    }
}

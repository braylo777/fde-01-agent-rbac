//! Stage 1 — Enterprise Identity & Agent RBAC.
//!
//! * `jwt`   — HS256 JSON Web Tokens with scopes, audience and expiry (scoped tool tokens).
//! * `delegate` — RFC 8693-style token exchange: a human token becomes a narrower agent token
//!   with an `act` (actor) claim, so every tool call can be traced to the human.
//! * `scim`  — SCIM 2.0 user create / PatchOp / deactivate against an in-memory directory,
//!   with group → role mapping.
//! * `rls`   — row-level security: policies that filter rows by claims of the caller.
//! * `oidc`  — OIDC ID-token claim checks (iss, aud, exp, nonce, iat skew).
//! * `revoke` — automatic revocation: SCIM deactivation, jti and agent kills.
//!
//! Time is always passed in as `now` (unix seconds) so results are reproducible.

mod api;
pub mod b64;
pub mod delegate;
pub mod jwt;
pub mod oidc;
pub mod revoke;
pub mod rls;
pub mod scim;

pub use api::dispatch;
use serde_json::Value;

pub const OPS: &[&str] = &[
    "issue_token",
    "verify_token",
    "delegate",
    "scim_apply",
    "rls_filter",
    "oidc_validate",
    "revoke",
];

pub(crate) fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
    v.get(k).ok_or_else(|| format!("missing field `{k}`"))
}
pub(crate) fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    field(v, k)?.as_str().ok_or_else(|| format!("`{k}` must be a string"))
}
pub(crate) fn u64_field(v: &Value, k: &str) -> Result<u64, String> {
    field(v, k)?.as_u64().ok_or_else(|| format!("`{k}` must be a whole number"))
}

pub fn handle(op: &str, input: &Value) -> Result<Value, String> {
    match op {
        "issue_token" => jwt::issue_op(input),
        "verify_token" => jwt::verify_op(input),
        "delegate" => delegate::exchange_op(input),
        "scim_apply" => scim::apply_op(input),
        "rls_filter" => rls::filter_op(input),
        "oidc_validate" => oidc::validate_op(input),
        "revoke" => revoke::revoke_op(input),
        _ => Err(format!("unknown op `{op}`; known: {}", OPS.join(", "))),
    }
}

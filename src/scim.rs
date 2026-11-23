//! SCIM 2.0 provisioning (RFC 7644) against an in-memory directory.
//!
//! Supports: POST /Users (create), PATCH /Users/{id} with `replace` / `add` / `remove`
//! operations on `active`, `displayName`, `emails` and `groups`, and DELETE (deprovision).
//! After each request the user's roles are recomputed from a group → role map, so a
//! deactivated or removed user loses every agent permission at once.

use crate::{field, str_field};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName", default)]
    pub display_name: String,
    #[serde(default = "yes")]
    pub active: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}
fn yes() -> bool {
    true
}

pub type Directory = BTreeMap<String, User>;

pub fn roles_for(u: &User, map: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    if !u.active {
        return vec![];
    }
    let mut r: Vec<String> = u
        .groups
        .iter()
        .flat_map(|g| map.get(g).cloned().unwrap_or_default())
        .collect();
    r.sort();
    r.dedup();
    r
}

fn list_of_strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| {
                x.as_str()
                    .map(String::from)
                    .or_else(|| x["value"].as_str().map(String::from))
            })
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

pub fn apply(dir: &mut Directory, req: &Value) -> Result<String, String> {
    let method = str_field(req, "method")?.to_ascii_uppercase();
    match method.as_str() {
        "POST" => {
            let body = field(req, "body")?;
            let user_name = str_field(body, "userName")?.to_string();
            if dir.values().any(|u| u.user_name == user_name) {
                return Err(format!("409 uniqueness: userName {user_name} exists"));
            }
            let id = format!("u{:04}", dir.len() + 1);
            dir.insert(
                id.clone(),
                User {
                    id: id.clone(),
                    user_name,
                    display_name: body["displayName"].as_str().unwrap_or("").into(),
                    active: body["active"].as_bool().unwrap_or(true),
                    groups: list_of_strings(&body["groups"]),
                    roles: vec![],
                },
            );
            Ok(format!("201 created {id}"))
        }
        "PATCH" => {
            let id = str_field(req, "id")?;
            let u = dir.get_mut(id).ok_or(format!("404 no user {id}"))?;
            let ops = field(req, "body")?["Operations"]
                .as_array()
                .ok_or("PATCH needs Operations")?;
            for op in ops {
                let kind = str_field(op, "op")?.to_ascii_lowercase();
                let path = op["path"].as_str().unwrap_or("");
                let val = &op["value"];
                match (kind.as_str(), path) {
                    ("replace", "active") => {
                        u.active = val.as_bool().ok_or("active must be bool")?
                    }
                    ("replace", "displayName") => {
                        u.display_name = val.as_str().unwrap_or("").into()
                    }
                    ("add", "groups") => {
                        for g in list_of_strings(val) {
                            if !u.groups.contains(&g) {
                                u.groups.push(g);
                            }
                        }
                    }
                    ("remove", "groups") => {
                        let rm = list_of_strings(val);
                        u.groups.retain(|g| !rm.contains(g));
                    }
                    ("replace", "groups") => u.groups = list_of_strings(val),
                    // Path-less replace: Okta / Entra send {"op":"replace","value":{"active":false}}
                    ("replace", "") => {
                        if let Some(a) = val["active"].as_bool() {
                            u.active = a;
                        }
                        if let Some(d) = val["displayName"].as_str() {
                            u.display_name = d.into();
                        }
                    }
                    _ => return Err(format!("400 unsupported op {kind} {path}")),
                }
            }
            Ok(format!("200 patched {id}"))
        }
        "DELETE" => {
            let id = str_field(req, "id")?;
            dir.remove(id).ok_or(format!("404 no user {id}"))?;
            Ok(format!("204 deleted {id}"))
        }
        m => Err(format!("405 method {m} not supported")),
    }
}

pub fn apply_op(i: &Value) -> Result<Value, String> {
    let mut dir: Directory = match i.get("directory") {
        Some(Value::Object(_)) => {
            serde_json::from_value(i["directory"].clone()).map_err(|e| e.to_string())?
        }
        _ => Directory::new(),
    };
    let map: BTreeMap<String, Vec<String>> =
        serde_json::from_value(i.get("group_roles").cloned().unwrap_or(json!({})))
            .map_err(|e| e.to_string())?;
    let mut log = Vec::new();
    for req in field(i, "requests")?
        .as_array()
        .ok_or("`requests` must be a list")?
    {
        log.push(match apply(&mut dir, req) {
            Ok(s) => s,
            Err(e) => format!("error: {e}"),
        });
    }
    for u in dir.values_mut() {
        u.roles = roles_for(u, &map);
    }
    Ok(json!({"log": log, "directory": dir}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(reqs: Value) -> Value {
        apply_op(&json!({"group_roles": {"Finance": ["invoice.read"], "Sales": ["crm.read", "crm.write"]},
            "requests": reqs}))
        .unwrap()
    }

    #[test]
    fn create_then_roles_from_groups() {
        let r = run(
            json!([{"method": "POST", "body": {"userName": "bo@x.com", "groups": [{"value": "Sales"}]}}]),
        );
        assert_eq!(
            r["directory"]["u0001"]["roles"],
            json!(["crm.read", "crm.write"])
        );
    }

    #[test]
    fn deactivate_removes_all_roles() {
        let r = run(json!([
            {"method": "POST", "body": {"userName": "bo@x.com", "groups": ["Sales"]}},
            {"method": "PATCH", "id": "u0001", "body": {"Operations": [{"op": "replace", "value": {"active": false}}]}}
        ]));
        assert_eq!(r["directory"]["u0001"]["roles"], json!([]));
    }

    #[test]
    fn duplicate_user_rejected() {
        let r = run(json!([
            {"method": "POST", "body": {"userName": "a"}},
            {"method": "POST", "body": {"userName": "a"}}
        ]));
        assert!(r["log"][1].as_str().unwrap().contains("409"));
    }

    #[test]
    fn group_add_and_remove() {
        let r = run(json!([
            {"method": "POST", "body": {"userName": "a", "groups": ["Sales"]}},
            {"method": "PATCH", "id": "u0001", "body": {"Operations": [
                {"op": "add", "path": "groups", "value": ["Finance"]},
                {"op": "remove", "path": "groups", "value": ["Sales"]}]}}
        ]));
        assert_eq!(r["directory"]["u0001"]["roles"], json!(["invoice.read"]));
    }

    #[test]
    fn delete_deprovisions() {
        let r = run(
            json!([{"method": "POST", "body": {"userName": "a"}}, {"method": "DELETE", "id": "u0001"}]),
        );
        assert!(r["directory"].as_object().unwrap().is_empty());
    }
}

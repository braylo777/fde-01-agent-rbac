//! Row-level security (RLS) for agent data access.
//!
//! A policy grants a role access to a table, optionally only to rows where a column
//! equals a claim of the caller (e.g. `dept == caller.dept`) or is in a fixed list.
//! Deny by default: a row is visible only if at least one policy matches it.
//! Columns listed in `mask_columns` are replaced with "***" unless the policy says `unmask`.

use crate::{field, str_field};
use serde_json::{json, Map, Value};

fn policy_matches_row(p: &Value, row: &Value, caller: &Value) -> bool {
    let Some(cond) = p.get("where") else {
        return true;
    };
    let col = cond["column"].as_str().unwrap_or("");
    let cell = &row[col];
    if let Some(claim) = cond["equals_claim"].as_str() {
        let c = &caller[claim];
        return !c.is_null() && c == cell;
    }
    if let Some(list) = cond["in"].as_array() {
        return list.contains(cell);
    }
    false
}

pub fn filter_op(i: &Value) -> Result<Value, String> {
    let table = str_field(i, "table")?;
    let caller = field(i, "caller")?;
    let roles: Vec<&str> = caller["roles"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let policies: Vec<&Value> = field(i, "policies")?
        .as_array()
        .ok_or("`policies` must be a list")?
        .iter()
        .filter(|p| p["table"] == table && roles.contains(&p["role"].as_str().unwrap_or("")))
        .collect();
    let mask: Vec<&str> = i["mask_columns"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut visible = Vec::new();
    let mut hidden = 0;
    for row in field(i, "rows")?
        .as_array()
        .ok_or("`rows` must be a list")?
    {
        let matched: Vec<&&Value> = policies
            .iter()
            .filter(|p| policy_matches_row(p, row, caller))
            .collect();
        if matched.is_empty() {
            hidden += 1;
            continue;
        }
        let unmask = matched.iter().any(|p| p["unmask"] == true);
        let mut out = Map::new();
        for (k, v) in row.as_object().ok_or("rows must be objects")? {
            let masked = !unmask && mask.contains(&k.as_str());
            out.insert(k.clone(), if masked { json!("***") } else { v.clone() });
        }
        visible.push(Value::Object(out));
    }
    Ok(json!({"visible": visible, "hidden_count": hidden, "policies_applied": policies.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(caller: Value) -> Value {
        filter_op(&json!({
            "table": "invoices", "caller": caller, "mask_columns": ["iban"],
            "policies": [
                {"table": "invoices", "role": "finance-agent", "where": {"column": "dept", "equals_claim": "dept"}},
                {"table": "invoices", "role": "cfo", "unmask": true}
            ],
            "rows": [
                {"id": 1, "dept": "sales", "iban": "DE89..."},
                {"id": 2, "dept": "ops", "iban": "FR76..."}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn agent_sees_only_own_dept_masked() {
        let r = data(json!({"sub": "agent", "roles": ["finance-agent"], "dept": "sales"}));
        assert_eq!(
            r["visible"],
            json!([{"id": 1, "dept": "sales", "iban": "***"}])
        );
        assert_eq!(r["hidden_count"], 1);
    }
    #[test]
    fn no_role_no_rows() {
        let r = data(json!({"roles": ["intern"], "dept": "sales"}));
        assert_eq!(r["visible"], json!([]));
    }
    #[test]
    fn missing_claim_never_matches() {
        let r = data(json!({"roles": ["finance-agent"]}));
        assert_eq!(r["hidden_count"], 2);
    }
    #[test]
    fn cfo_sees_all_unmasked() {
        let r = data(json!({"roles": ["cfo"]}));
        assert_eq!(r["visible"][1]["iban"], "FR76...");
    }
}

# fde-01-agent-rbac

**Forward Deployed Engineering — Stage 1 of 12: Enterprise Identity & Agent RBAC**

Scoped tool tokens, delegated agent auth, SCIM provisioning and row-level security, so an AI agent can only touch what its human is allowed to touch.

**Also built as Project 1 of 12, "Enterprise SSO & Agent Delegation Broker",** from the companion [12 FDE projects post](https://x.com/suraj_sharma14/status/2125197762752806998).

**Live demo:** https://fde-01-agent-rbac.braylo777.workers.dev — the Rust core runs in your browser as WebAssembly. No server, no tracking.

## Why this matters

When an AI agent acts inside a company, the first question from security is: who is it acting for, and what can it touch? This repo answers that with the same building blocks enterprises already use (SSO claims, SCIM, scoped tokens, row-level security), wired so the agent can never hold more access than the human it works for, and so access is removed the moment the IdP deactivates that human.

## What it does

- HS256 scoped JWTs for tool calls: audience, expiry, clock skew, alg=none and tamper refusal
- Agent-to-human delegation (RFC 8693 style): scopes narrowed, act claim, TTL capped
- Automatic revocation: a SCIM deactivate or delete kills every live agent token for that human; kill by jti or agent id too; verify_token honours the list
- SCIM 2.0 create / PATCH / deactivate / delete with group-to-role mapping
- Row-level security: deny by default, claim-matched rows, column masking
- OIDC ID-token claim checks: iss, aud/azp, exp, iat, nonce

## What it does not do (yet)

- SAML assertion parsing and XML signature checks
- RS256/ES256 signatures and JWKS key fetch (HS256 only here)
- A real IdP (Okta / Entra) and a real Postgres RLS policy; the logic is the same, the wiring is not

## Operations

Every operation takes JSON in and gives JSON out. The CLI, the tests and the demo page all use the same entry point.

| Operation | What it does |
|---|---|
| `issue_token` | Mint a 5-minute token that lets one agent call two CRM tools. Scopes are the allow-list. |
| `verify_token` | The tool server checks the token before it runs. Change required_scope to crm.delete to see a refusal, or move now past expiry. |
| `delegate` | Alice's token is exchanged for a narrower agent token. Scopes = requested AND Alice's AND the agent's allow-list. The act claim records the agent. |
| `scim_apply` | The IdP creates a user, adds a group, then deactivates them. Roles are recomputed after each request: a deactivated user has none. |
| `rls_filter` | A finance agent asks for invoices. It sees only its own department's rows, with the IBAN masked. |
| `oidc_validate` | Claim checks after the signature passes. This token has a wrong nonce (replay) and two audiences without azp. |
| `revoke` | Alice is deactivated in the IdP. Her agent's 5-minute token dies at once; Bob's agent keeps working. Also kills by jti or by agent id. |

## Run it

You need Rust (stable). No Node, no npm.

```bash
git clone https://github.com/braylo777/fde-01-agent-rbac
cd fde-01-agent-rbac
cargo test
cargo run -- ops
```

Try the first demo example from the command line:

```bash
python3 -c 'import json;print(json.dumps(json.load(open("web/examples.json"))["ops"][0]["input"]))' | cargo run -q -- issue_token
```

## Build and deploy the demo

```bash
./build.sh    # tests, then compiles the core to web/app.wasm
./deploy.sh   # serves web/ as a Cloudflare Workers static-assets site (needs a Cloudflare login)
```

`web/` is a plain static site (`index.html`, `app.js`, `app.wasm`). It has no build step, so any static host works.

## Layout

```
src/lib.rs        operation list and router
src/api.rs        JSON entry point + the 3 WASM exports (alloc, dealloc, run)
src/main.rs       CLI
src/*.rs          one module per capability, each with unit tests
tests/            integration tests (every demo example must pass)
web/              demo page; examples.json drives both the page and this README
```

## Design choices

- **Rust, few dependencies.** Only `serde`, `serde_json`, `sha2` and `hmac`, pinned to exact versions with a committed `Cargo.lock`.
- **Deterministic.** Time, randomness and keys are inputs, so every result can be replayed in a test or an audit.
- **Fail closed.** Unknown input, missing fields or an unmatched policy gives an error or a denial, never a silent pass.

## Part of a series

This is one of 12 repos that work through a public Forward Deployed Engineering roadmap ([12 stages](https://x.com/suraj_sharma14/status/2124827808535048566), [12 projects](https://x.com/suraj_sharma14/status/2125197762752806998)). All 12: [github.com/braylo777?q=fde-](https://github.com/braylo777?tab=repositories&q=fde-).

## License

MIT — see [LICENSE](LICENSE). Built by [Braylo SI](https://braylo.si).

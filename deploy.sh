#!/bin/sh
# Deploy the demo page to Cloudflare Pages project "fde-01-agent-rbac".
# Needs wrangler (pinned) and a Cloudflare login. Set WRANGLER to override.
set -eu
cd "$(dirname "$0")"
WRANGLER="${WRANGLER:-$HOME/bin/wrangler}"
./build.sh
"$WRANGLER" pages project create fde-01-agent-rbac --production-branch main 2>/dev/null || true
"$WRANGLER" pages deploy web --project-name fde-01-agent-rbac --branch main --commit-dirty=true

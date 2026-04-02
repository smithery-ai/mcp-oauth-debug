# mcp-oauth-debug

MCP OAuth compliance simulator. Walks the exact path a real MCP client would -- unauthenticated probe, 401 challenge parsing, metadata discovery, client registration, authorization, token exchange, authenticated MCP calls -- and reports spec compliance at each step.

## Install

```bash
npx skills add smithery-ai/mcp-oauth-debug
```

Then use `/mcp-oauth-debug` in Claude Code (you might need to restart Claude Code).

### Prerequisites

- [Bun](https://bun.sh) runtime

## How it works

```
  POST /initialize (no auth)
         |
         v
  401 + WWW-Authenticate: Bearer resource_metadata="..."   <-- Phase 1
         |
         v
  GET resource_metadata URL (or .well-known fallback)       <-- Phase 2
         |
         v
  GET /.well-known/oauth-authorization-server               <-- Phase 3
         |
         v
  POST registration_endpoint (DCR)                          <-- Phase 4
         |
         v
  Browser auth + code exchange + PKCE                       <-- Phase 5
         |
         v
  POST /initialize + /tools/list (with token)               <-- Phase 6
         |
         v
  COMPLIANCE SUMMARY
  [+] Pass: 16  [x] Fail: 3  [!] Warn: 2  [-] Skip: 0
```

Each step reports pass/fail/warn with RFC references. The summary at the end shows exactly where the server deviates from spec.

## Docs

- [SKILL.md](SKILL.md) -- full specification, phase details, and failure pattern reference
- [scripts/oauth-debug.ts](scripts/oauth-debug.ts) -- the compliance probe script

## Contributing

Found a bug or have an idea? [Open an issue](https://github.com/smithery-ai/mcp-oauth-debug/issues) or submit a pull request.

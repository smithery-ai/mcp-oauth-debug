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
  1. POST /initialize (no auth) --> 401 + WWW-Authenticate
  2. GET resource_metadata (challenge hint or .well-known)
  3. GET /.well-known/oauth-authorization-server
  4. POST registration_endpoint (DCR)
  5. Browser auth + code exchange + PKCE
  6. POST /initialize + /tools/list (with token)
     --> COMPLIANCE SUMMARY
```

Each step reports pass/fail/warn with RFC references. The summary at the end shows exactly where the server deviates from spec.

## Docs

- [SKILL.md](SKILL.md) -- full specification, phase details, and failure pattern reference
- [scripts/oauth-debug.ts](scripts/oauth-debug.ts) -- the compliance probe script
- [references/](references/) -- RFC excerpts and MCP spec snippets:
  - [RFC 9728](references/rfc-9728-protected-resource-metadata.md) -- Protected Resource Metadata
  - [RFC 8414](references/rfc-8414-authorization-server-metadata.md) -- Authorization Server Metadata
  - [RFC 7591](references/rfc-7591-dynamic-client-registration.md) -- Dynamic Client Registration
  - [RFC 6750](references/rfc-6750-bearer-token.md) -- Bearer Token / WWW-Authenticate
  - [RFC 7636](references/rfc-7636-pkce.md) -- PKCE
  - [MCP Spec](references/mcp-spec-authorization.md) -- MCP Authorization (2025-03-26)

## Contributing

Found a bug or have an idea? [Open an issue](https://github.com/smithery-ai/mcp-oauth-debug/issues) or submit a pull request.

# MCP Specification -- Authorization (2025-03-26)

https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/authorization/

## Flow

1. Client sends an MCP request to the server
2. Server responds HTTP 401 Unauthorized (the trigger)
3. Client discovers server metadata via `GET /.well-known/oauth-authorization-server`
4. If DCR is supported, client registers via `POST /register`
5. Client generates PKCE parameters (code_verifier + code_challenge)
6. Client opens browser to the authorization URL with code_challenge
7. User authorizes; server redirects back with authorization code
8. Client exchanges code + code_verifier for tokens
9. Client makes MCP requests with `Authorization: Bearer <token>` on every HTTP request

## Server MUSTs

- Respond with HTTP 401 when authorization is required and not yet proven
- Return HTTP 401 for invalid or expired tokens
- Validate access tokens per OAuth 2.1 Section 5.2
- Serve all authorization endpoints over HTTPS
- Validate redirect URIs to prevent open redirect vulnerabilities
- Require redirect URIs to be either localhost URLs or HTTPS URLs
- Follow fallback URL schema if not supporting RFC 8414 metadata discovery

## Server SHOULDs

- Support RFC 8414 metadata discovery
- Support OAuth 2.0 Dynamic Client Registration (RFC 7591)
- Enforce token expiration and rotation

## Client MUSTs

- Implement RFC 8414 metadata discovery
- Use the `Authorization: Bearer` header (not URI query string)
- Include authorization in every HTTP request, even within the same logical session
- Use PKCE for all clients (REQUIRED)
- Attempt metadata discovery before falling back to default paths

## Client SHOULDs

- Include `MCP-Protocol-Version` header during metadata discovery

## Discovery

Authorization base URL is determined by discarding the path component of the MCP server URL.

For `https://api.example.com/v1/mcp`, the metadata endpoint MUST be at:
```
https://api.example.com/.well-known/oauth-authorization-server
```

## Fallback Endpoints

When metadata discovery returns 404, clients use these defaults relative to the authorization base URL:

| Endpoint | Default Path |
|---|---|
| Authorization | `/authorize` |
| Token | `/token` |
| Registration | `/register` |

Clients MUST first attempt metadata discovery before falling back.

## Grant Types

- **Authorization Code** -- client acts on behalf of a human user
- **Client Credentials** -- client is another application, no human impersonation

## Third-Party Authorization

MCP servers can delegate to an external auth server, acting as both:
- An OAuth client (to the third-party IdP)
- An OAuth authorization server (to the MCP client)

When doing so, the server MUST:
- Maintain secure mapping between third-party tokens and issued MCP tokens
- Validate third-party token status before honoring MCP tokens
- Handle third-party token expiration and renewal

# RFC 8414 -- OAuth 2.0 Authorization Server Metadata

https://www.rfc-editor.org/rfc/rfc8414

## Section 2: Metadata Fields

| Field | Status | Description |
|---|---|---|
| `issuer` | REQUIRED | Authorization server's issuer identifier (HTTPS URL, no query/fragment) |
| `authorization_endpoint` | REQUIRED | URL of the authorization endpoint |
| `token_endpoint` | REQUIRED | URL of the token endpoint |
| `registration_endpoint` | OPTIONAL | URL of the Dynamic Client Registration endpoint (RFC 7591) |
| `jwks_uri` | OPTIONAL | URL of the JWK Set document |
| `scopes_supported` | RECOMMENDED | JSON array of supported scope values |
| `response_types_supported` | REQUIRED | JSON array of supported response_type values |
| `grant_types_supported` | OPTIONAL | JSON array of grant types (default: `["authorization_code", "implicit"]`) |
| `token_endpoint_auth_methods_supported` | OPTIONAL | Client auth methods for token endpoint (default: `client_secret_basic`) |
| `code_challenge_methods_supported` | OPTIONAL | PKCE methods (RFC 7636). If omitted, server does not support PKCE |
| `introspection_endpoint` | OPTIONAL | URL of introspection endpoint (RFC 7662) |
| `revocation_endpoint` | OPTIONAL | URL of revocation endpoint (RFC 7009) |

## Section 3: Obtaining Metadata

### Well-Known URI Construction

Insert `/.well-known/oauth-authorization-server` between the host and path components of the issuer identifier.

```
Issuer: https://example.com
  --> GET https://example.com/.well-known/oauth-authorization-server

Issuer: https://example.com/issuer1
  --> GET https://example.com/.well-known/oauth-authorization-server/issuer1
```

### Section 3.3: Issuer Validation (critical)

> The "issuer" value returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI string was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used.

This is the anti-mix-up rule: the `issuer` claim in the discovery response must exactly match the issuer you derived the well-known URL from. A mismatch means the response is untrusted and must be rejected.

## Example Response

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/authorize",
  "token_endpoint": "https://example.com/token",
  "registration_endpoint": "https://example.com/register",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"]
}
```

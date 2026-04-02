# RFC 9728 -- OAuth 2.0 Protected Resource Metadata

https://www.rfc-editor.org/rfc/rfc9728

## Section 2: Metadata Fields

The metadata document is a JSON object with these parameters:

| Field | Status | Description |
|---|---|---|
| `resource` | REQUIRED | The protected resource's identifier (HTTPS URL, no fragment) |
| `authorization_servers` | OPTIONAL | JSON array of OAuth authorization server issuer identifiers |
| `scopes_supported` | RECOMMENDED | JSON array of OAuth 2.0 scope values the resource uses |
| `bearer_methods_supported` | OPTIONAL | Supported bearer token delivery methods: `"header"`, `"body"`, `"query"` |
| `resource_name` | OPTIONAL | Human-readable name |
| `resource_documentation` | OPTIONAL | URL to developer docs |

## Section 3.1: WWW-Authenticate Challenge Discovery

When a client makes an unauthenticated request and receives a 401, the `WWW-Authenticate` header can include a `resource_metadata` parameter pointing to the metadata URL:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"
```

This is the primary discovery entry point: probe the resource, get a 401, follow the `resource_metadata` link.

## Section 3.3: Well-Known URI Construction

The well-known path `/.well-known/oauth-protected-resource` is inserted between the host and path components of the resource identifier.

**No path:**

```
Resource: https://resource.example.com
Metadata: https://resource.example.com/.well-known/oauth-protected-resource
```

**With path:**

```
Resource: https://resource.example.com/resource1
Metadata: https://resource.example.com/.well-known/oauth-protected-resource/resource1
```

## Validation Rules

1. The `resource` value in the response MUST exactly match the resource identifier used to construct the metadata URL. Mismatch = discard the response.
2. When discovered via `WWW-Authenticate`, the `resource` value must match the original request URL.

## Example Response

```json
{
  "resource": "https://resource.example.com",
  "authorization_servers": [
    "https://as1.example.com"
  ],
  "scopes_supported": ["profile", "email"],
  "resource_name": "Example API"
}
```

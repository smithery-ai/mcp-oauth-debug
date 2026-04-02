# RFC 6750 -- OAuth 2.0 Bearer Token Usage

https://www.rfc-editor.org/rfc/rfc6750

## Section 3: The WWW-Authenticate Response Header Field

If the protected resource request does not include authentication credentials or does not contain an access token that enables access, the resource server MUST include the HTTP `WWW-Authenticate` response header field.

All challenges MUST use the auth-scheme value `Bearer`.

### No credentials present (unauthenticated request)

The server SHOULD NOT include an error code -- bare challenge only:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example"
```

### Token present but invalid

Include `error`, optionally `error_description`:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  error="invalid_token",
                  error_description="The access token expired"
```

### Error Codes (Section 3.1)

| Error | HTTP Status | Description |
|---|---|---|
| `invalid_request` | 400 | Missing required parameter, unsupported parameter, malformed request |
| `invalid_token` | 401 | Token is expired, revoked, malformed, or invalid. Client MAY request a new token and retry |
| `insufficient_scope` | 403 | Request requires higher privileges. Server MAY include `scope` attribute with required scope |

### Challenge Parameters

| Parameter | Description |
|---|---|
| `realm` | Scope of protection (OPTIONAL, at most once) |
| `scope` | Space-delimited list of required scope values (OPTIONAL, at most once) |
| `error` | Error code (OPTIONAL, at most once) |
| `error_description` | Human-readable explanation (OPTIONAL, at most once) |
| `error_uri` | URL to human-readable error page (OPTIONAL, at most once) |
| `resource_metadata` | URL to protected resource metadata (RFC 9728 extension) |

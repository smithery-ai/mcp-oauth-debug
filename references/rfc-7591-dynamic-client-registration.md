# RFC 7591 -- OAuth 2.0 Dynamic Client Registration Protocol

https://www.rfc-editor.org/rfc/rfc7591

## Section 2: Client Metadata

Metadata fields sent in the registration request:

| Field | Description |
|---|---|
| `redirect_uris` | Array of redirection URIs (REQUIRED for authorization_code grant) |
| `token_endpoint_auth_method` | Auth method for the token endpoint (e.g., `"none"`, `"client_secret_basic"`, `"client_secret_post"`) |
| `grant_types` | Array of grant types the client will use (e.g., `["authorization_code", "refresh_token"]`) |
| `response_types` | Array of response types (e.g., `["code"]`) |
| `client_name` | Human-readable name for the client |
| `client_uri` | URL of the client's home page |
| `scope` | Space-separated list of scopes the client can request |
| `application_type` | `"web"` or `"native"` |

## Section 3.1: Client Registration Request

POST to the `registration_endpoint` with `Content-Type: application/json`:

```http
POST /register HTTP/1.1
Host: server.example.com
Content-Type: application/json

{
  "client_name": "My Application",
  "redirect_uris": ["http://localhost:9877/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "native"
}
```

## Section 3.2: Client Registration Response

Successful response (201 Created) returns a JSON object with all registered metadata plus:

| Field | Description |
|---|---|
| `client_id` | REQUIRED. Unique client identifier issued by the server |
| `client_secret` | OPTIONAL. Client secret (if token_endpoint_auth_method requires one) |
| `client_id_issued_at` | OPTIONAL. Time at which the client_id was issued (Unix timestamp) |
| `client_secret_expires_at` | REQUIRED if client_secret is issued. 0 = does not expire |

```json
{
  "client_id": "s6BhdRkqt3",
  "client_id_issued_at": 1577858400,
  "client_name": "My Application",
  "redirect_uris": ["http://localhost:9877/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

## Error Response

If registration fails, the server returns an error response with `Content-Type: application/json`:

```json
{
  "error": "invalid_client_metadata",
  "error_description": "The redirect_uri is not valid"
}
```

Error codes: `invalid_redirect_uri`, `invalid_client_metadata`, `invalid_software_statement`, `unapproved_software_statement`.

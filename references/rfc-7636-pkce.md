# RFC 7636 -- Proof Key for Code Exchange (PKCE)

https://www.rfc-editor.org/rfc/rfc7636

## Section 4: Protocol

### 4.1: Client Creates a Code Verifier

Generate a high-entropy cryptographic random string using unreserved characters `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`, minimum 43 characters, maximum 128 characters.

Recommended: generate 32 random bytes, then base64url-encode to produce a 43-character string.

### 4.2: Client Creates the Code Challenge

**S256 (mandatory to implement):**
```
code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
```

**plain (fallback only):**
```
code_challenge = code_verifier
```

If the client supports S256, it MUST use S256. `plain` is only permitted if S256 is technically impossible and the server is known to support it.

### 4.3: Authorization Request Parameters

| Parameter | Status | Description |
|---|---|---|
| `code_challenge` | REQUIRED | The computed code challenge |
| `code_challenge_method` | OPTIONAL | `"S256"` or `"plain"` (defaults to `"plain"` if omitted) |

### 4.5: Token Request Parameters

| Parameter | Status | Description |
|---|---|---|
| `code_verifier` | REQUIRED | The original code verifier |

### 4.6: Server Verification

Server recomputes the challenge from the verifier using the stored method:

- S256: `BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge`
- plain: `code_verifier == code_challenge`

If values match, proceed normally. If not, return `invalid_grant` error.

### Error Responses

- Missing `code_challenge` when server requires PKCE: `invalid_request`
- Unsupported `code_challenge_method`: `invalid_request`
- `code_verifier` doesn't match `code_challenge`: `invalid_grant`

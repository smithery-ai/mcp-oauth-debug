#!/usr/bin/env bun
/**
 * MCP OAuth Compliance Simulator
 *
 * Walks the exact path a real MCP client would — unauthenticated probe,
 * 401 challenge parsing, discovery, registration, authorization, token
 * exchange, MCP calls — and reports spec compliance at each step.
 *
 * Usage: bun run scripts/oauth-debug.ts <mcp-url> [--no-pkce] [--scopes "s1 s2"] [--port 9877]
 */

import { createServer } from "node:http"
import { randomBytes, createHash } from "node:crypto"

// ── Types ────────────────────────────────────────────────────────
interface StepResult {
  step: string
  status: "pass" | "fail" | "warn" | "skip"
  detail: string
  spec?: string // RFC or spec section reference
}

const results: StepResult[] = []

function record(step: string, status: StepResult["status"], detail: string, spec?: string) {
  results.push({ step, status, detail, spec })
  const icon = { pass: "[+]", fail: "[x]", warn: "[!]", skip: "[-]" }[status]
  console.log(`  ${icon} ${step}: ${detail}`)
  if (spec) console.log(`      > ${spec}`)
}

// ── Args ─────────────────────────────────────────────────────────
const mcpUrl = process.argv[2]
if (!mcpUrl) {
  console.error("Usage: bun run oauth-debug.ts <mcp-url> [--no-pkce] [--scopes 's1 s2'] [--port 9877]")
  process.exit(1)
}
const noPkce = process.argv.includes("--no-pkce")
const scopesIdx = process.argv.indexOf("--scopes")
const scopeOverride = scopesIdx !== -1 ? process.argv[scopesIdx + 1] : undefined
const portIdx = process.argv.indexOf("--port")
const CALLBACK_PORT = portIdx !== -1 ? parseInt(process.argv[portIdx + 1], 10) : 9877
const CALLBACK_URL = `http://localhost:${CALLBACK_PORT}/callback`

// ── Correlation IDs ─────────────────────────────────────────────
// Threaded through every leg so the full waterfall — script-driven
// fetches AND browser-driven redirects — is recoverable from one query
// against the server's tracing backend.
//
//   probeId       — short id baked into DCR client_name and OAuth `state`.
//                   Survives browser redirects (state is mandatory and echoed).
//                   Lands in any URL-logging span as a substring.
//   clientTraceId — W3C traceparent traceId, set on every script fetch.
//                   Spec-compliant tracing infra (e.g. @microlabs/otel-cf-workers)
//                   continues this trace on the server, so all script→server
//                   spans share one TraceId.
const probeId = randomBytes(4).toString("hex")
const clientTraceId = randomBytes(16).toString("hex")
const clientSpanId = randomBytes(8).toString("hex")
const traceparent = `00-${clientTraceId}-${clientSpanId}-01`

console.log(`\n  probe_id:       ${probeId}`)
console.log(`  client_traceId: ${clientTraceId}`)
console.log(`  traceparent:    ${traceparent}`)

// ── Helpers ──────────────────────────────────────────────────────
function log(label: string, data: unknown) {
  console.log(`\n── ${label} ──`)
  console.log(typeof data === "string" ? data : JSON.stringify(data, null, 2))
}

function parseWwwAuthenticate(header: string): Record<string, string> {
  const params: Record<string, string> = {}
  // Extract scheme
  const schemeMatch = header.match(/^(\S+)\s+/)
  if (schemeMatch) params._scheme = schemeMatch[1].toLowerCase()

  // Extract key="value" pairs
  const paramRegex = /(\w+)="([^"]*?)"/g
  let match: RegExpExecArray | null
  while ((match = paramRegex.exec(header)) !== null) {
    params[match[1]] = match[2]
  }
  // Also extract unquoted params like error=invalid_token
  const unquotedRegex = /(\w+)=([^\s,]+)/g
  while ((match = unquotedRegex.exec(header)) !== null) {
    if (!params[match[1]]) params[match[1]] = match[2]
  }
  return params
}

// ══════════════════════════════════════════════════════════════════
// PHASE 1: Unauthenticated Probe
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 1: Unauthenticated Probe against ${mcpUrl}\n`)

const probeBody = JSON.stringify({
  jsonrpc: "2.0",
  method: "initialize",
  params: {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "oauth-compliance-probe", version: "1.0" },
  },
  id: 1,
})

let probeStatus: number
let probeWwwAuth: string | null = null
let challengeResourceMetadata: string | null = null
let challengeScopes: string | null = null

try {
  const probe = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      traceparent,
    },
    body: probeBody,
  })
  probeStatus = probe.status
  probeWwwAuth = probe.headers.get("www-authenticate")

  if (probeStatus === 401) {
    record("Unauthenticated 401", "pass", `Server returned 401 as expected`, "MCP spec: servers MUST return 401 when auth is required")

    if (probeWwwAuth) {
      const parsed = parseWwwAuthenticate(probeWwwAuth)
      log("WWW-Authenticate header", probeWwwAuth)
      log("Parsed challenge", parsed)

      if (parsed._scheme === "bearer") {
        record("Bearer challenge", "pass", `WWW-Authenticate uses Bearer scheme`, "RFC 6750 §3")
      } else {
        record("Bearer challenge", "warn", `Scheme is "${parsed._scheme ?? "missing"}", expected Bearer`, "RFC 6750 §3")
      }

      if (parsed.resource_metadata) {
        challengeResourceMetadata = parsed.resource_metadata
        record("Challenge resource_metadata", "pass", `Hint: ${parsed.resource_metadata}`, "RFC 9728 §3.1")
      } else {
        record("Challenge resource_metadata", "warn", `No resource_metadata in challenge — clients must fall back to .well-known`, "RFC 9728 §3.1")
      }

      if (parsed.scope) {
        challengeScopes = parsed.scope
        record("Challenge scope hint", "pass", `Scopes: ${parsed.scope}`)
      }
    } else {
      record("WWW-Authenticate header", "fail", `401 without WWW-Authenticate header — clients can't discover auth server`, "RFC 6750 §3: MUST include WWW-Authenticate on 401")
    }
  } else if (probeStatus === 200) {
    record("Unauthenticated 401", "warn", `Server returned 200 without auth — may accept unauthenticated initialize but require auth on tools/call`, "MCP spec: non-compliant but common")

    // Check if there's JSON-RPC content
    try {
      const body = await probe.text()
      const parsed = JSON.parse(body)
      if (parsed.result?.serverInfo) {
        record("Unauthenticated initialize", "warn", `Server accepted initialize: ${JSON.stringify(parsed.result.serverInfo)}`)
      }
    } catch { /* ignore */ }
  } else {
    record("Unauthenticated 401", "fail", `Unexpected status ${probeStatus} — expected 401 or 200`, "MCP spec")
  }
} catch (err) {
  probeStatus = 0
  record("Unauthenticated probe", "fail", `Network error: ${err instanceof Error ? err.message : String(err)}`)
}

// ══════════════════════════════════════════════════════════════════
// PHASE 2: Protected Resource Metadata Discovery (RFC 9728)
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 2: Protected Resource Metadata Discovery\n`)

const base = new URL(mcpUrl)
const path = base.pathname === "/" ? "" : base.pathname.replace(/\/$/, "")

// Discovery order:
// 1. Challenge hint (from phase 1) — most authoritative
// 2. Path-inserted .well-known (RFC 9728 §3.3)
// 3. Root .well-known (fallback)

let prm: Record<string, unknown> | null = null

// Attempt 1: Challenge-provided resource_metadata URL
if (challengeResourceMetadata) {
  console.log(`  Trying challenge hint: ${challengeResourceMetadata}`)
  try {
    const res = await fetch(challengeResourceMetadata, { headers: { Accept: "application/json", traceparent } })
    if (res.ok) {
      prm = await res.json() as Record<string, unknown>
      record("Discovery via challenge hint", "pass", `Found metadata at ${challengeResourceMetadata}`, "RFC 9728 §3.1")
    } else {
      record("Discovery via challenge hint", "fail", `Challenge URL returned ${res.status}`, "RFC 9728 §3.1")
    }
  } catch (err) {
    record("Discovery via challenge hint", "fail", `Fetch error: ${err instanceof Error ? err.message : String(err)}`)
  }
}

// Attempt 2: Path-inserted .well-known
if (!prm && path) {
  const pathInserted = `${base.origin}/.well-known/oauth-protected-resource${path}`
  console.log(`  Trying path-inserted: ${pathInserted}`)
  try {
    const res = await fetch(pathInserted, { headers: { Accept: "application/json", traceparent } })
    if (res.ok) {
      prm = await res.json() as Record<string, unknown>
      record("Discovery via path-inserted .well-known", "pass", `Found at ${pathInserted}`, "RFC 9728 §3.3")
    } else if (res.status >= 400 && res.status < 500) {
      record("Discovery via path-inserted .well-known", "skip", `${res.status} — trying root`, "RFC 9728 §3.3")
    } else {
      record("Discovery via path-inserted .well-known", "fail", `Server error ${res.status}`, "RFC 9728 §3.3")
    }
  } catch (err) {
    record("Discovery via path-inserted .well-known", "fail", `Fetch error: ${err instanceof Error ? err.message : String(err)}`)
  }
}

// Attempt 3: Root .well-known
if (!prm) {
  const rootUrl = `${base.origin}/.well-known/oauth-protected-resource`
  console.log(`  Trying root: ${rootUrl}`)
  try {
    const res = await fetch(rootUrl, { headers: { Accept: "application/json", traceparent } })
    if (res.ok) {
      prm = await res.json() as Record<string, unknown>
      record("Discovery via root .well-known", "pass", `Found at ${rootUrl}`, "RFC 9728 §3.3")
    } else {
      record("Discovery via root .well-known", "fail", `${res.status}`, "RFC 9728 §3.3")
    }
  } catch (err) {
    record("Discovery via root .well-known", "fail", `Fetch error: ${err instanceof Error ? err.message : String(err)}`)
  }
}

if (!prm) {
  record("Protected resource metadata", "fail", `No metadata found via any discovery method`)
  if (probeStatus === 401) {
    console.log(`\n  Note: Server returns 401 but doesn't advertise OAuth metadata.`)
    console.log(`        Real clients won't know how to authenticate.`)
  }
  printSummary()
  process.exit(1)
}

if (!Array.isArray(prm.authorization_servers) || prm.authorization_servers.length === 0) {
  record("authorization_servers", "fail", `Missing or empty authorization_servers array`, "RFC 9728 §3.3")
  printSummary()
  process.exit(1)
}
record("authorization_servers", "pass", `Found: ${(prm.authorization_servers as string[]).join(", ")}`)

// Validate resource field matches
if (prm.resource) {
  const resourceMatch = prm.resource === mcpUrl || prm.resource === base.origin + base.pathname
  if (resourceMatch) {
    record("Resource field match", "pass", `resource="${prm.resource}" matches MCP URL`)
  } else {
    record("Resource field match", "warn", `resource="${prm.resource}" differs from MCP URL "${mcpUrl}"`, "RFC 9728 §3.3: resource SHOULD match")
  }
} else {
  record("Resource field", "warn", `No resource field in metadata`, "RFC 9728 §3.3")
}

log("Protected Resource Metadata", prm)

// ══════════════════════════════════════════════════════════════════
// PHASE 3: Authorization Server Metadata (RFC 8414)
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 3: Authorization Server Metadata Discovery\n`)

const issuer = (prm.authorization_servers as string[])[0]
const issuerUrl = new URL(issuer)
const issuerPath = issuerUrl.pathname === "/" ? "" : issuerUrl.pathname.replace(/\/$/, "")

// Discovery attempts in spec-prescribed order
const asmAttempts: Array<{ label: string; url: string; spec: string }> = [
  {
    label: "OAuth2 path-inserted",
    url: `${issuerUrl.origin}/.well-known/oauth-authorization-server${issuerPath}`,
    spec: "RFC 8414 §3.1",
  },
]

if (issuerPath) {
  asmAttempts.push({
    label: "OIDC path-inserted",
    url: `${issuerUrl.origin}/.well-known/openid-configuration${issuerPath}`,
    spec: "OIDC Discovery §4.1",
  })
  asmAttempts.push({
    label: "OIDC path-suffixed",
    url: `${issuerUrl.origin}${issuerPath}/.well-known/openid-configuration`,
    spec: "OIDC Discovery §4.1 (alternate)",
  })
} else {
  asmAttempts.push({
    label: "OIDC root",
    url: `${issuerUrl.origin}/.well-known/openid-configuration`,
    spec: "OIDC Discovery §4.1",
  })
}

let asm: Record<string, unknown> | null = null

for (const attempt of asmAttempts) {
  console.log(`  Trying ${attempt.label}: ${attempt.url}`)
  try {
    const res = await fetch(attempt.url, { headers: { Accept: "application/json", traceparent } })
    if (res.ok) {
      asm = await res.json() as Record<string, unknown>
      record(`AS metadata (${attempt.label})`, "pass", `Found at ${attempt.url}`, attempt.spec)
      break
    } else if (res.status >= 400 && res.status < 500) {
      record(`AS metadata (${attempt.label})`, "skip", `${res.status} — trying next`, attempt.spec)
    } else {
      record(`AS metadata (${attempt.label})`, "fail", `Server error ${res.status}`, attempt.spec)
      break // 5xx = stop, don't try alternatives
    }
  } catch (err) {
    record(`AS metadata (${attempt.label})`, "fail", `Fetch error: ${err instanceof Error ? err.message : String(err)}`)
    break
  }
}

if (!asm) {
  record("Authorization server metadata", "fail", `No metadata found at any well-known path for issuer ${issuer}`)
  printSummary()
  process.exit(1)
}

log("Authorization Server Metadata", asm)

// Validate issuer match
if (asm.issuer) {
  if (asm.issuer === issuer) {
    record("Issuer consistency", "pass", `Metadata issuer matches: ${asm.issuer}`, "RFC 8414 §3.2")
  } else {
    record("Issuer consistency", "fail", `Metadata issuer="${asm.issuer}" != PRM issuer="${issuer}"`, "RFC 8414 §3.2: issuer MUST match")
  }
}

const authEndpoint = asm.authorization_endpoint as string | undefined
const tokenEndpoint = asm.token_endpoint as string | undefined
const registrationEndpoint = asm.registration_endpoint as string | undefined
const scopesSupported = (asm.scopes_supported as string[] | undefined) ?? []

if (!authEndpoint) record("authorization_endpoint", "fail", "Missing", "RFC 8414 §2")
if (!tokenEndpoint) record("token_endpoint", "fail", "Missing", "RFC 8414 §2")

if (!authEndpoint || !tokenEndpoint) {
  printSummary()
  process.exit(1)
}

record("Required endpoints", "pass", `authorize: ${authEndpoint}, token: ${tokenEndpoint}`)

if (registrationEndpoint) {
  record("registration_endpoint", "pass", `DCR supported: ${registrationEndpoint}`, "RFC 7591")
} else {
  record("registration_endpoint", "warn", `No DCR — MCP spec recommends dynamic client registration`, "RFC 7591 / MCP spec")
}

// Check PKCE support
const codeChallengeMethodsSupported = asm.code_challenge_methods_supported as string[] | undefined
if (codeChallengeMethodsSupported) {
  if (codeChallengeMethodsSupported.includes("S256")) {
    record("PKCE S256", "pass", `Server advertises S256 support`, "RFC 7636")
  } else {
    record("PKCE S256", "warn", `Server supports ${codeChallengeMethodsSupported.join(", ")} but not S256`, "RFC 7636: S256 SHOULD be supported")
  }
} else {
  record("PKCE support", "warn", `No code_challenge_methods_supported advertised`, "RFC 7636")
}

// ══════════════════════════════════════════════════════════════════
// PHASE 4: Dynamic Client Registration (RFC 7591)
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 4: Dynamic Client Registration\n`)

let clientId: string
let clientSecret: string | undefined

if (registrationEndpoint) {
  console.log(`  Registering at ${registrationEndpoint}...`)
  try {
    const regRes = await fetch(registrationEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", traceparent },
      body: JSON.stringify({
        client_name: `mcp-oauth-debug:${probeId}`,
        redirect_uris: [CALLBACK_URL],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        application_type: "native",
      }),
    })

    if (!regRes.ok) {
      const body = await regRes.text()
      record("Client registration", "fail", `${regRes.status}: ${body.slice(0, 200)}`, "RFC 7591")
      printSummary()
      process.exit(1)
    }

    const regData = await regRes.json() as Record<string, unknown>
    log("Registration Response", regData)
    clientId = regData.client_id as string
    clientSecret = regData.client_secret as string | undefined

    if (!clientId) {
      record("Client registration", "fail", `Response missing client_id`, "RFC 7591 §3.2.1")
      printSummary()
      process.exit(1)
    }

    record("Client registration", "pass", `client_id: ${clientId}`)
  } catch (err) {
    record("Client registration", "fail", `Error: ${err instanceof Error ? err.message : String(err)}`)
    printSummary()
    process.exit(1)
  }
} else {
  record("Client registration", "skip", `No registration_endpoint — cannot proceed without pre-registered credentials`)
  printSummary()
  process.exit(1)
}

// ══════════════════════════════════════════════════════════════════
// PHASE 5: Authorization + Token Exchange
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 5: Authorization Code Flow\n`)

const codeVerifier = randomBytes(32).toString("base64url")
const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url")
// State carries the probe_id so the value lands in any URL-logging span
// (apps/auth's /authorize, /callback, redirect 302). RFC 6749 §10.12 requires
// the AS echo state verbatim, so it survives every redirect including browser hops.
const state = `probe-${probeId}-${randomBytes(8).toString("hex")}`
const scopes = scopeOverride ?? challengeScopes ?? scopesSupported.join(" ")

const authUrl = new URL(authEndpoint)
authUrl.searchParams.set("client_id", clientId)
authUrl.searchParams.set("redirect_uri", CALLBACK_URL)
authUrl.searchParams.set("response_type", "code")
authUrl.searchParams.set("state", state)
if (scopes) authUrl.searchParams.set("scope", scopes)
authUrl.searchParams.set("resource", mcpUrl)
if (!noPkce) {
  authUrl.searchParams.set("code_challenge", codeChallenge)
  authUrl.searchParams.set("code_challenge_method", "S256")
}

log("Authorization URL", authUrl.toString())
if (scopes) console.log(`  Scopes: ${scopes}`)

// Local callback server
const { code } = await new Promise<{ code: string }>((resolve, reject) => {
  let settled = false
  const settle = (fn: () => void) => { if (!settled) { settled = true; fn() } }

  const server = createServer((req, res) => {
    // Log every inbound — gives instant feedback that the redirect landed,
    // even if the response flush stalls behind a keep-alive socket.
    console.log(`  ← ${req.method} ${req.url}`)

    const url = new URL(req.url!, `http://localhost:${CALLBACK_PORT}`)
    if (url.pathname !== "/callback") {
      res.writeHead(404)
      res.end("Not found")
      return
    }

    const error = url.searchParams.get("error")
    const errorDesc = url.searchParams.get("error_description")
    if (error) {
      // Resolve/reject the promise FIRST, then write the response. The
      // browser-facing HTML is decorative; the script's progress shouldn't
      // wait on socket flush callbacks.
      settle(() => {
        record("Authorization", "fail", `${error}: ${errorDesc ?? "no description"}`)
        reject(new Error(`OAuth error: ${error} - ${errorDesc}`))
      })
      res.writeHead(200, { "Content-Type": "text/html" })
      res.end(`<h2>Authorization failed</h2><p>${error}: ${errorDesc ?? ""}</p>`)
      server.close()
      return
    }

    if (url.searchParams.get("state") !== state) {
      settle(() => {
        record("State validation", "fail", `Returned state doesn't match sent state`)
        reject(new Error("State mismatch"))
      })
      res.writeHead(200, { "Content-Type": "text/html" })
      res.end("<h2>State mismatch</h2>")
      server.close()
      return
    }

    settle(() => resolve({ code: url.searchParams.get("code")! }))
    res.writeHead(200, { "Content-Type": "text/html" })
    res.end("<h2>Authorization successful</h2><p>You can close this tab.</p>")
    server.close()
  })

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      settle(() => reject(new Error(`Port ${CALLBACK_PORT} in use — try --port <other>`)))
    } else {
      settle(() => reject(err))
    }
  })

  server.listen(CALLBACK_PORT, () => {
    console.log(`\n  Callback on http://localhost:${CALLBACK_PORT}`)
    console.log(`  Opening browser... (waiting for authorization, 2min timeout)\n`)
    const { execSync } = require("node:child_process")
    try {
      execSync(`open "${authUrl.toString()}"`)
    } catch {
      console.log(`  Open manually: ${authUrl.toString()}`)
    }
  })

  setTimeout(() => {
    server.close()
    settle(() => reject(new Error("Timed out (2 min)")))
  }, 120_000)
})

record("Authorization code", "pass", `Received code: ${code.slice(0, 20)}...`)

// Token exchange
console.log(`\n  Exchanging code at ${tokenEndpoint}...`)

const tokenParams = new URLSearchParams({
  grant_type: "authorization_code",
  code,
  redirect_uri: CALLBACK_URL,
  client_id: clientId,
  resource: mcpUrl,
  ...(!noPkce ? { code_verifier: codeVerifier } : {}),
})
if (clientSecret) tokenParams.set("client_secret", clientSecret)

const tokenRes = await fetch(tokenEndpoint, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json", traceparent },
  body: tokenParams.toString(),
})

const tokenRaw = await tokenRes.text()
log(`Token Response (${tokenRes.status})`, tokenRaw)

if (!tokenRes.ok) {
  record("Token exchange", "fail", `Status ${tokenRes.status}: ${tokenRaw.slice(0, 200)}`)
  printSummary()
  process.exit(1)
}

let tokenData: Record<string, unknown>
try {
  tokenData = JSON.parse(tokenRaw)
} catch {
  record("Token exchange", "fail", `Response is not valid JSON`)
  printSummary()
  process.exit(1)
}

const accessToken = tokenData.access_token as string
if (!accessToken) {
  record("Token exchange", "fail", `No access_token in response`)
  printSummary()
  process.exit(1)
}

record("Token exchange", "pass", `access_token received (${accessToken.length} chars)`)

if (tokenData.refresh_token) record("Refresh token", "pass", `Present`)
else record("Refresh token", "warn", `Not provided — clients can't renew silently`)

if (tokenData.expires_in) record("Token expiry", "pass", `expires_in: ${tokenData.expires_in}s`)
if (tokenData.scope) record("Token scope", "pass", `scope: ${tokenData.scope}`)

// Decode access_token if JWT
const atParts = accessToken.split(".")
if (atParts.length === 3) {
  try {
    const atClaims = JSON.parse(Buffer.from(atParts[1], "base64url").toString())
    log("access_token claims", atClaims)

    const aud = Array.isArray(atClaims.aud) ? atClaims.aud : [atClaims.aud]
    if (atClaims.aud && !aud.includes(clientId)) {
      record("Token audience", "warn",
        `aud=${JSON.stringify(atClaims.aud)} doesn't include client_id=${clientId} — server may ignore DCR client_id`,
        "RFC 9068 §2.2")
    } else if (atClaims.aud) {
      record("Token audience", "pass", `aud includes client_id`)
    }

    if (atClaims.iss && asm.issuer && atClaims.iss !== asm.issuer) {
      record("Token issuer", "fail",
        `access_token iss="${atClaims.iss}" != metadata issuer="${asm.issuer}"`,
        "RFC 8414 §3.2: issuer MUST match")
    } else if (atClaims.iss) {
      record("Token issuer", "pass", `iss matches metadata issuer`)
    }
  } catch {
    record("Token format", "warn", `JWT but claims couldn't be decoded`)
  }
} else {
  record("Token format", "pass", `Opaque token (not JWT) — can't inspect claims locally`)
}

// Decode id_token if present
if (tokenData.id_token) {
  const idToken = tokenData.id_token as string
  const [, payload] = idToken.split(".")
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString())
    log("id_token claims", claims)
    if (claims.iss && asm.issuer && claims.iss !== asm.issuer) {
      record("id_token issuer", "warn",
        `id_token iss="${claims.iss}" != metadata issuer="${asm.issuer}"`,
        "OIDC Core §2: iss MUST match")
    } else if (claims.iss) {
      record("id_token issuer", "pass", `iss matches`)
    }
  } catch {
    record("id_token", "warn", `Couldn't decode id_token claims`)
  }
}

// ══════════════════════════════════════════════════════════════════
// PHASE 6: MCP Calls with Token
// ══════════════════════════════════════════════════════════════════
console.log(`\n== Phase 6: Authenticated MCP Calls\n`)

async function mcpCall(method: string, params: Record<string, unknown> = {}, id = 1) {
  const res = await fetch(mcpUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Streamable-HTTP MCP transport requires both content types in Accept;
      // sending only application/json triggers 406 on spec-compliant servers.
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${accessToken}`,
      traceparent,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id }),
  })
  const text = await res.text()
  return {
    status: res.status,
    headers: Object.fromEntries(res.headers.entries()),
    body: text,
  }
}

// initialize
const initRes = await mcpCall("initialize", {
  protocolVersion: "2025-03-26",
  capabilities: {},
  clientInfo: { name: "oauth-compliance-probe", version: "1.0" },
})
log(`initialize (${initRes.status})`, initRes.body)

if (initRes.status === 200) {
  record("Authenticated initialize", "pass", `200 OK`)
  try {
    const parsed = JSON.parse(initRes.body)
    if (parsed.result?.serverInfo) {
      record("Server info", "pass", `${JSON.stringify(parsed.result.serverInfo)}`)
    }
    if (parsed.error) {
      record("Initialize JSON-RPC", "fail", `Error: ${parsed.error.message ?? JSON.stringify(parsed.error)}`)
    }
  } catch { /* ignore */ }
} else if (initRes.status === 401) {
  record("Authenticated initialize", "fail", `401 — token rejected on initialize`)
  const wwwAuth = initRes.headers["www-authenticate"]
  if (wwwAuth) log("WWW-Authenticate on 401", wwwAuth)
} else {
  record("Authenticated initialize", "warn", `Unexpected status ${initRes.status}`)
}

// tools/list
const listRes = await mcpCall("tools/list", {}, 2)
log(`tools/list (${listRes.status})`, listRes.body.slice(0, 500) + (listRes.body.length > 500 ? "..." : ""))

if (listRes.status === 200) {
  record("Authenticated tools/list", "pass", `200 OK`)
} else if (listRes.status === 401) {
  record("Authenticated tools/list", "fail", `401 — token rejected on tools/list`)
} else {
  record("Authenticated tools/list", "warn", `Status ${listRes.status}`)
}

// Note: tools/call intentionally skipped — calling tools with empty
// arguments against a real server could trigger side effects.

// ══════════════════════════════════════════════════════════════════
// SUMMARY
// ══════════════════════════════════════════════════════════════════
printTraceLookup()
printSummary()

function printTraceLookup() {
  // The probe threaded `probeId` into the OAuth `state` (and DCR `client_name`)
  // and a W3C `traceparent` into every script-driven fetch. Either one is
  // enough to pull the full waterfall — `state` covers the browser-driven
  // legs, `traceparent` covers the script-driven legs.
  console.log(`\n${"═".repeat(60)}`)
  console.log(`  CH trace lookup`)
  console.log(`${"═".repeat(60)}`)
  console.log(`  probe_id:        ${probeId}`)
  console.log(`  client_traceId:  ${clientTraceId}`)
  console.log(`\n  -- Paste into ClickHouse:`)
  console.log(`  SELECT Timestamp, ServiceName, SpanName,`)
  console.log(`         Duration / 1e6 AS ms, StatusCode,`)
  console.log(`         SpanAttributes['http.url'] AS url`)
  console.log(`  FROM otel.otel_traces`)
  console.log(`  WHERE Timestamp > now() - INTERVAL 30 MINUTE`)
  console.log(`    AND (`)
  console.log(`      SpanAttributes['http.url'] LIKE '%probe-${probeId}%'`)
  console.log(`      OR TraceId = '${clientTraceId}'`)
  console.log(`    )`)
  console.log(`  ORDER BY Timestamp ASC`)
}

function printSummary() {
  const passes = results.filter(r => r.status === "pass").length
  const fails = results.filter(r => r.status === "fail").length
  const warns = results.filter(r => r.status === "warn").length
  const skips = results.filter(r => r.status === "skip").length

  console.log(`\n${"═".repeat(60)}`)
  console.log(`  COMPLIANCE SUMMARY`)
  console.log(`${"═".repeat(60)}`)
  console.log(`  [+] Pass: ${passes}  [x] Fail: ${fails}  [!] Warn: ${warns}  [-] Skip: ${skips}`)
  console.log(`${"─".repeat(60)}`)

  for (const r of results) {
    if (r.status === "fail" || r.status === "warn") {
      const icon = r.status === "fail" ? "[x]" : "[!]"
      console.log(`  ${icon} ${r.step}: ${r.detail}`)
      if (r.spec) console.log(`      > ${r.spec}`)
    }
  }

  if (fails === 0 && warns === 0) {
    console.log(`\n  Server is fully compliant across all tested checks.`)
  } else if (fails === 0) {
    console.log(`\n  No hard failures. Warnings indicate non-critical spec deviations.`)
  } else {
    console.log(`\n  ${fails} compliance failure(s) found. See details above.`)
  }

  console.log(`${"═".repeat(60)}\n`)
}

import { createHash } from "node:crypto"
import assert from "node:assert/strict"
import { createLabFetchHandler, type LabRuntimeEnvironment, type McpLabEngine } from "../src/index.js"

export interface WireResponse {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly text: string
  json<T = Record<string, unknown>>(): T
}

export interface LabWire {
  readonly origin: string
  request(path: string, init?: { method?: string; headers?: Record<string, string>; body?: string }): Promise<WireResponse>
}

function toWireResponse(status: number, headers: Record<string, string>, text: string): WireResponse {
  return {
    status,
    headers,
    text,
    json<T>(): T {
      return JSON.parse(text) as T
    },
  }
}

/** Drives the engine through the Fetch adapter without any network. */
export function fetchWire(engine: McpLabEngine, origin = "https://lab.test"): LabWire {
  const handler = createLabFetchHandler(engine)
  return {
    origin,
    async request(path, init = {}) {
      const response = await handler(
        new Request(`${origin}${path}`, {
          method: init.method ?? "GET",
          headers: init.headers ?? {},
          ...(init.body === undefined ? {} : { body: init.body }),
        }),
      )
      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
      })
      return toWireResponse(response.status, headers, await response.text())
    },
  }
}

/** Drives a running lab Node server over real loopback HTTP. */
export function nodeWire(baseUrl: string): LabWire {
  return {
    origin: baseUrl,
    async request(path, init = {}) {
      const response = await fetch(`${baseUrl}${path}`, {
        method: init.method ?? "GET",
        headers: init.headers ?? {},
        ...(init.body === undefined ? {} : { body: init.body }),
        redirect: "manual",
      })
      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
      })
      return toWireResponse(response.status, headers, await response.text())
    },
  }
}

export interface DeterministicRuntime extends LabRuntimeEnvironment {
  advance(ms: number): void
  setNow(ms: number): void
}

export function deterministicRuntime(startMs = 1_752_400_000_000): DeterministicRuntime {
  let nowMs = startMs
  let counter = 0
  return {
    now: () => nowMs,
    randomId: () => `trace-${(++counter).toString(36).padStart(8, "0")}`,
    opaqueValue: (prefix) => `${prefix}-${(++counter).toString(36).padStart(10, "0")}`,
    advance(ms: number) {
      nowMs += ms
    },
    setNow(ms: number) {
      nowMs = ms
    },
  }
}

export function pkcePair(seed = "lab-test-pkce-verifier-with-plenty-of-entropy-0000000001"): {
  verifier: string
  challenge: string
} {
  assert.ok(/^[A-Za-z0-9._~-]{43,128}$/.test(seed))
  return { verifier: seed, challenge: createHash("sha256").update(seed).digest("base64url") }
}

export function labPath(environmentId: string, suffix: string): string {
  return `/lab/${environmentId}${suffix}`
}

export function consentFields(html: string): { requestId: string; state: string | null } {
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1]
  assert.ok(requestId, "consent screen must embed the request id")
  const state = /name="state" value="([^"]*)"/.exec(html)?.[1] ?? null
  return { requestId, state }
}

export interface AuthorizeOptions {
  readonly wire: LabWire
  readonly environmentId: string
  readonly issuerPath: string
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: readonly string[]
  readonly challenge: string
  readonly state?: string
  readonly resource?: string
  readonly decision?: "approve" | "deny"
  readonly automationToken?: string
}

export interface AuthorizationOutcome {
  readonly redirect: URL
  readonly code: string | null
  readonly state: string | null
  readonly iss: string | null
  readonly error: string | null
}

/** GET /authorize, parse the consent screen, POST the decision, return the redirect. */
export async function authorizeWithConsent(options: AuthorizeOptions): Promise<AuthorizationOutcome> {
  const { wire, environmentId, issuerPath } = options
  const resource = options.resource ?? `${wire.origin}/lab/${environmentId}/mcp`
  const parameters = new URLSearchParams({
    response_type: "code",
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scopes.join(" "),
    code_challenge: options.challenge,
    code_challenge_method: "S256",
    resource,
  })
  if (options.state !== undefined) parameters.set("state", options.state)
  const authorize = await wire.request(labPath(environmentId, `${issuerPath}/authorize?${parameters.toString()}`))
  assert.equal(authorize.status, 200, `authorize should render consent, got ${authorize.status}: ${authorize.text}`)
  const fields = consentFields(authorize.text)
  const form = new URLSearchParams({ request_id: fields.requestId, decision: options.decision ?? "approve" })
  if (fields.state !== null) form.set("state", fields.state)
  if (options.automationToken !== undefined) form.set("automation_token", options.automationToken)
  const consent = await wire.request(labPath(environmentId, `${issuerPath}/consent`), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  })
  assert.equal(consent.status, 302, `consent should redirect, got ${consent.status}: ${consent.text}`)
  const location = consent.headers.location
  assert.ok(location)
  const redirect = new URL(location)
  return {
    redirect,
    code: redirect.searchParams.get("code"),
    state: redirect.searchParams.get("state"),
    iss: redirect.searchParams.get("iss"),
    error: redirect.searchParams.get("error"),
  }
}

export interface TokenExchangeOptions {
  readonly wire: LabWire
  readonly environmentId: string
  readonly issuerPath: string
  readonly clientId: string
  readonly clientSecret?: string
  readonly secretTransport?: "post" | "basic"
  readonly grant:
    | { readonly type: "authorization_code"; readonly code: string; readonly verifier: string; readonly redirectUri: string; readonly resource?: string }
    | { readonly type: "refresh_token"; readonly refreshToken: string; readonly resource?: string }
}

export async function exchangeToken(options: TokenExchangeOptions): Promise<WireResponse> {
  const { wire, environmentId, issuerPath } = options
  const resource = options.grant.resource ?? `${wire.origin}/lab/${environmentId}/mcp`
  const form = new URLSearchParams()
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" }
  if (options.clientSecret !== undefined && options.secretTransport === "basic") {
    headers.authorization = `Basic ${Buffer.from(`${options.clientId}:${options.clientSecret}`).toString("base64")}`
  } else {
    form.set("client_id", options.clientId)
    if (options.clientSecret !== undefined) form.set("client_secret", options.clientSecret)
  }
  if (options.grant.type === "authorization_code") {
    form.set("grant_type", "authorization_code")
    form.set("code", options.grant.code)
    form.set("code_verifier", options.grant.verifier)
    form.set("redirect_uri", options.grant.redirectUri)
    form.set("resource", resource)
  } else {
    form.set("grant_type", "refresh_token")
    form.set("refresh_token", options.grant.refreshToken)
    if (options.grant.resource !== undefined) form.set("resource", options.grant.resource)
  }
  return wire.request(labPath(environmentId, `${issuerPath}/token`), {
    method: "POST",
    headers,
    body: form.toString(),
  })
}

export interface DcrOptions {
  readonly wire: LabWire
  readonly environmentId: string
  readonly issuerPath: string
  readonly redirectUris: readonly string[]
  readonly applicationType?: "web" | "native"
  readonly tokenEndpointAuthMethod?: string
  readonly grantTypes?: readonly string[]
  readonly responseTypes?: readonly string[]
  readonly scope?: string
  readonly clientName?: string
}

export async function registerDynamicClient(options: DcrOptions): Promise<WireResponse> {
  return options.wire.request(labPath(options.environmentId, `${options.issuerPath}/register`), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...(options.applicationType === undefined ? {} : { application_type: options.applicationType }),
      redirect_uris: options.redirectUris,
      ...(options.grantTypes === undefined ? {} : { grant_types: options.grantTypes }),
      ...(options.responseTypes === undefined ? {} : { response_types: options.responseTypes }),
      token_endpoint_auth_method: options.tokenEndpointAuthMethod ?? "none",
      ...(options.scope === undefined ? {} : { scope: options.scope }),
      client_name: options.clientName ?? "Lab test client",
    }),
  })
}

export function mcpHeaders(accessToken: string | null, extra?: Record<string, string>): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...(accessToken === null ? {} : { authorization: `Bearer ${accessToken}` }),
    ...extra,
  }
}

export function parseRpcBody<T = Record<string, unknown>>(response: WireResponse): T {
  const contentType = response.headers["content-type"] ?? ""
  if (contentType.startsWith("text/event-stream")) {
    const match = /^data: (.*)$/m.exec(response.text)
    assert.ok(match?.[1], "SSE body must carry one data frame")
    return JSON.parse(match[1]) as T
  }
  return response.json<T>()
}

export interface McpSession {
  readonly sessionId: string
  readonly protocolVersion: string
}

export async function initializeStableSession(
  wire: LabWire,
  environmentId: string,
  accessToken: string | null,
  requestedVersion: string,
  options: { sendInitialized?: boolean } = {},
): Promise<McpSession> {
  const initialize = await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: requestedVersion,
        capabilities: {},
        clientInfo: { name: "lab-test-client", version: "1.0.0" },
      },
    }),
  })
  assert.equal(initialize.status, 200, `initialize failed: ${initialize.status} ${initialize.text}`)
  const body = parseRpcBody<{ result: { protocolVersion: string } }>(initialize)
  const sessionId = initialize.headers["mcp-session-id"]
  assert.ok(sessionId)
  const protocolVersion = body.result.protocolVersion
  if (options.sendInitialized ?? true) {
    const initialized = await wire.request(labPath(environmentId, "/mcp"), {
      method: "POST",
      headers: mcpHeaders(accessToken, { "mcp-session-id": sessionId, "mcp-protocol-version": protocolVersion }),
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    })
    assert.equal(initialized.status, 202, `initialized notification failed: ${initialized.status} ${initialized.text}`)
  }
  return { sessionId, protocolVersion }
}

export async function callStableRpc(
  wire: LabWire,
  environmentId: string,
  accessToken: string | null,
  session: McpSession,
  payload: Record<string, unknown>,
): Promise<WireResponse> {
  return wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, {
      "mcp-session-id": session.sessionId,
      "mcp-protocol-version": session.protocolVersion,
    }),
    body: JSON.stringify({ jsonrpc: "2.0", ...payload }),
  })
}

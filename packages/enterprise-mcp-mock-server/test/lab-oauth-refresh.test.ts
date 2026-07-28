import assert from "node:assert/strict"
import test from "node:test"
import {
  createMcpLabEngine,
  getLabScenarioPreset,
  InMemoryMcpLabStore,
  labAccessTokenLifetimeSeconds,
  type LabScenarioPresetId,
  type McpLabEngine,
} from "../src/index.js"
import {
  authorizeWithConsent,
  callStableRpc,
  deterministicRuntime,
  exchangeToken,
  fetchWire,
  initializeStableSession,
  labPath,
  mcpHeaders,
  parseRpcBody,
  pkcePair,
  registerDynamicClient,
  type DeterministicRuntime,
  type LabWire,
} from "./lab-wire.js"

interface Harness {
  readonly engine: McpLabEngine
  readonly wire: LabWire
  readonly runtime: DeterministicRuntime
}

function harness(): Harness {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const engine = createMcpLabEngine({ store, runtime })
  return { engine, wire: fetchWire(engine), runtime }
}

const webCallback = "https://client.example/oauth/callback"

interface EstablishedGrant {
  readonly environmentId: string
  readonly clientId: string
  readonly accessToken: string
  readonly refreshToken: string | null
}

async function establishGrant(
  h: Harness,
  presetId: LabScenarioPresetId,
  options: { scopes?: readonly string[]; verifierSeed?: string } = {},
): Promise<EstablishedGrant> {
  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset(presetId).scenario)) as Record<string, unknown>
  const created = await h.engine.createEnvironment(scenario)
  const environmentId = created.environment.id
  const registration = await registerDynamicClient({ wire: h.wire, environmentId, issuerPath: "/oauth", redirectUris: [webCallback] })
  assert.equal(registration.status, 201, registration.text)
  const clientId = registration.json<{ client_id: string }>().client_id
  const { verifier, challenge } = pkcePair(options.verifierSeed ?? "lab-test-pkce-verifier-with-plenty-of-entropy-0000000001")
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: options.scopes ?? ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)
  const token = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(token.status, 200, token.text)
  const body = token.json<{ access_token: string; refresh_token?: string }>()
  return { environmentId, clientId, accessToken: body.access_token, refreshToken: body.refresh_token ?? null }
}

test("refresh rotation returns a new token and replaying the old one revokes the family", async () => {
  const h = harness()
  const grant = await establishGrant(h, "refresh-rotation")
  assert.ok(grant.refreshToken)

  const refreshed = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(refreshed.status, 200, refreshed.text)
  const refreshedBody = refreshed.json<{ access_token: string; refresh_token?: string }>()
  assert.ok(refreshedBody.refresh_token, "rotation must return a replacement refresh token")
  assert.notEqual(refreshedBody.refresh_token, grant.refreshToken)

  const replay = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(replay.status, 400)
  assert.equal(replay.json().error, "invalid_grant")

  // Reuse detection revokes the whole family, including the replacement.
  const afterReplay = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: refreshedBody.refresh_token },
  })
  assert.equal(afterReplay.status, 400)

  const mcp = await h.wire.request(labPath(grant.environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(refreshedBody.access_token),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(mcp.status, 401, "family revocation must invalidate issued access tokens")
})

test("refresh omission keeps the existing refresh token valid across refreshes", async () => {
  const h = harness()
  const grant = await establishGrant(h, "refresh-omission")
  assert.ok(grant.refreshToken)

  const first = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(first.status, 200, first.text)
  const firstBody = first.json<{ access_token: string; refresh_token?: string }>()
  assert.equal(firstBody.refresh_token, undefined, "omission preset must not return a replacement")

  const second = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(second.status, 200, "the original refresh token must remain valid")
})

test("expired access tokens refresh without a browser round trip", async () => {
  const h = harness()
  const grant = await establishGrant(h, "refresh-rotation")
  assert.ok(grant.refreshToken)

  h.runtime.advance((labAccessTokenLifetimeSeconds + 5) * 1_000)
  const expired = await h.wire.request(labPath(grant.environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(grant.accessToken),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(expired.status, 401)

  const refreshed = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(refreshed.status, 200, refreshed.text)
  const refreshedBody = refreshed.json<{ access_token: string }>()
  const session = await initializeStableSession(h.wire, grant.environmentId, refreshedBody.access_token, "2025-11-25")
  assert.ok(session.sessionId)
})

test("refresh tokens are bound to their client and issuer", async () => {
  const h = harness()
  const grant = await establishGrant(h, "refresh-rotation")
  assert.ok(grant.refreshToken)
  const otherRegistration = await registerDynamicClient({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
  })
  const otherClientId = otherRegistration.json<{ client_id: string }>().client_id
  const crossClient = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: otherClientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(crossClient.status, 400)
  assert.equal(crossClient.json().error, "invalid_grant")
})

test("revocation kills the whole token family", async () => {
  const h = harness()
  const grant = await establishGrant(h, "refresh-rotation")
  assert.ok(grant.refreshToken)
  const revoke = await h.wire.request(labPath(grant.environmentId, "/oauth/revoke"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: grant.clientId, token: grant.refreshToken }).toString(),
  })
  assert.equal(revoke.status, 200)

  const refreshAfterRevoke = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "refresh_token", refreshToken: grant.refreshToken },
  })
  assert.equal(refreshAfterRevoke.status, 400)

  const mcp = await h.wire.request(labPath(grant.environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(grant.accessToken),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(mcp.status, 401)
})

test("incremental scope: elevated tools challenge with insufficient_scope until user-approved step-up", async () => {
  const h = harness()
  const grant = await establishGrant(h, "incremental-scope")
  const session = await initializeStableSession(h.wire, grant.environmentId, grant.accessToken, "2025-11-25")

  const denied = await callStableRpc(h.wire, grant.environmentId, grant.accessToken, session, {
    id: 5,
    method: "tools/call",
    params: { name: "export_audit_report", arguments: {} },
  })
  assert.equal(denied.status, 403)
  const challengeHeader = denied.headers["www-authenticate"] ?? ""
  assert.match(challengeHeader, /insufficient_scope/)
  assert.match(challengeHeader, /mcp:admin/)

  // Step up through a fresh user-approved authorization including the elevated scope.
  const { verifier, challenge } = pkcePair("lab-test-pkce-verifier-with-plenty-of-entropy-0000000003")
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools", "mcp:admin"],
    challenge,
  })
  assert.ok(outcome.code)
  const stepUpToken = await exchangeToken({
    wire: h.wire,
    environmentId: grant.environmentId,
    issuerPath: "/oauth",
    clientId: grant.clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(stepUpToken.status, 200)
  const elevated = stepUpToken.json<{ access_token: string; scope: string }>()
  assert.match(elevated.scope, /mcp:admin/)

  const elevatedSession = await initializeStableSession(h.wire, grant.environmentId, elevated.access_token, "2025-11-25")
  const allowed = await callStableRpc(h.wire, grant.environmentId, elevated.access_token, elevatedSession, {
    id: 6,
    method: "tools/call",
    params: { name: "export_audit_report", arguments: {} },
  })
  assert.equal(allowed.status, 200, allowed.text)
  const allowedBody = parseRpcBody<{ result: { isError: boolean } }>(allowed)
  assert.equal(allowedBody.result.isError, false)
})

test("tokens, codes, and sessions never cross lab environments", async () => {
  const h = harness()
  const first = await establishGrant(h, "stable-healthy-dcr")
  const second = await establishGrant(h, "stable-healthy-dcr", {
    verifierSeed: "lab-test-pkce-verifier-with-plenty-of-entropy-0000000004",
  })
  assert.notEqual(first.environmentId, second.environmentId)

  const crossEnvironment = await h.wire.request(labPath(second.environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(first.accessToken),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(crossEnvironment.status, 401)

  assert.ok(first.refreshToken)
  const crossRefresh = await exchangeToken({
    wire: h.wire,
    environmentId: second.environmentId,
    issuerPath: "/oauth",
    clientId: second.clientId,
    grant: { type: "refresh_token", refreshToken: first.refreshToken },
  })
  assert.equal(crossRefresh.status, 400)
})

test("stopped environments go away and deleted environments return 404", async () => {
  const h = harness()
  const created = await h.engine.createEnvironment(
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>,
  )
  const environmentId = created.environment.id
  await h.engine.stopEnvironment(environmentId, 1)
  const stopped = await h.wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`)
  assert.equal(stopped.status, 410)
  await h.engine.deleteEnvironment(environmentId)
  const deleted = await h.wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`)
  assert.equal(deleted.status, 404)
})

test("environments expire by lifetime and disappear from the wire", async () => {
  const h = harness()
  const created = await h.engine.createEnvironment(
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>,
  )
  const environmentId = created.environment.id
  h.runtime.advance(3_601_000)
  const expired = await h.wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`)
  assert.equal(expired.status, 404)
  assert.equal(expired.json().error, "lab_environment_expired")
})

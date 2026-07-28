import assert from "node:assert/strict"
import test from "node:test"
import {
  createMcpLabEngine,
  getLabScenarioPreset,
  InMemoryMcpLabStore,
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

const webCallback = "https://client.example/oauth/callback"

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

async function oauthAccessToken(
  h: Harness,
  presetId: LabScenarioPresetId,
  patch?: (scenario: Record<string, any>) => void,
): Promise<{ environmentId: string; accessToken: string; clientId: string }> {
  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset(presetId).scenario)) as Record<string, any>
  patch?.(scenario)
  const created = await h.engine.createEnvironment(scenario)
  const environmentId = created.environment.id
  const registration = await registerDynamicClient({ wire: h.wire, environmentId, issuerPath: "/oauth", redirectUris: [webCallback] })
  assert.equal(registration.status, 201, registration.text)
  const clientId = registration.json<{ client_id: string }>().client_id
  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
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
  return { environmentId, accessToken: token.json<{ access_token: string }>().access_token, clientId }
}

test("version negotiation echoes supported versions and downgrades unsupported ones", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr")
  const session1 = await initializeStableSession(h.wire, environmentId, accessToken, "2025-06-18")
  assert.equal(session1.protocolVersion, "2025-06-18")
  const session2 = await initializeStableSession(h.wire, environmentId, accessToken, "1999-01-01")
  assert.equal(session2.protocolVersion, "2025-11-25", "unsupported requests negotiate the server's preferred version")
})

test("a 2025-11-25 client downgrades against a 2025-06-18 server", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-downgrade")
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")
  assert.equal(session.protocolVersion, "2025-06-18")
})

test("strict lifecycle requires initialized notification and the protocol version header", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr")
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25", { sendInitialized: false })

  const early = await callStableRpc(h.wire, environmentId, accessToken, session, { id: 2, method: "tools/list", params: {} })
  assert.equal(early.status, 200)
  const earlyBody = parseRpcBody<{ error?: { code: number } }>(early)
  assert.equal(earlyBody.error?.code, -32002)

  const missingVersionHeader = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, { "mcp-session-id": session.sessionId }),
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  })
  assert.equal(missingVersionHeader.status, 400)
  assert.equal(missingVersionHeader.json().error, "mcp_protocol_version_header_required")

  const wrongVersionHeader = await callStableRpc(h.wire, environmentId, accessToken, { ...session, protocolVersion: "2025-06-18" }, {
    id: 3,
    method: "tools/list",
    params: {},
  })
  assert.equal(wrongVersionHeader.status, 400)
  assert.equal(wrongVersionHeader.json().error, "mcp_protocol_version_mismatch")
})

test("2025-03-26 sessions do not require the protocol version header", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr", (scenario) => {
    scenario.protocol.versions = ["2025-03-26"]
  })
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-03-26", { sendInitialized: false })
  const initialized = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, { "mcp-session-id": session.sessionId }),
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  })
  assert.equal(initialized.status, 202, initialized.text)
})

test("session expiry fault returns 404 exactly once and recovery succeeds", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "session-expiry")
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25", { sendInitialized: false })
  const expired = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, { "mcp-session-id": session.sessionId, "mcp-protocol-version": session.protocolVersion }),
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  })
  assert.equal(expired.status, 404)
  assert.equal(expired.json().error, "mcp_session_expired")

  const recovered = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")
  const list = await callStableRpc(h.wire, environmentId, accessToken, recovered, { id: 4, method: "tools/list", params: {} })
  assert.equal(list.status, 200)
  const body = parseRpcBody<{ result?: { tools: unknown[] } }>(list)
  assert.ok(body.result?.tools)
})

test("DELETE terminates the session and stale session ids stay 404", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr")
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")
  const terminated = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "DELETE",
    headers: mcpHeaders(accessToken, { "mcp-session-id": session.sessionId, "mcp-protocol-version": session.protocolVersion }),
  })
  assert.equal(terminated.status, 204)
  const afterDelete = await callStableRpc(h.wire, environmentId, accessToken, session, { id: 5, method: "tools/list", params: {} })
  assert.equal(afterDelete.status, 404)

  const getResponse = await h.wire.request(labPath(environmentId, "/mcp"), { headers: mcpHeaders(accessToken) })
  assert.equal(getResponse.status, 405)
  assert.equal(getResponse.headers.allow, "POST, DELETE")
})

test("tools/list paginates with the configured page size and rejects bad cursors", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr")
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")

  const pageOne = await callStableRpc(h.wire, environmentId, accessToken, session, { id: 6, method: "tools/list", params: {} })
  const pageOneBody = parseRpcBody<{ result: { tools: Array<{ name: string }>; nextCursor?: string } }>(pageOne)
  assert.equal(pageOneBody.result.tools.length, 3)
  assert.equal(pageOneBody.result.nextCursor, "page:3")

  const pageTwo = await callStableRpc(h.wire, environmentId, accessToken, session, {
    id: 7,
    method: "tools/list",
    params: { cursor: "page:3" },
  })
  const pageTwoBody = parseRpcBody<{ result: { tools: Array<{ name: string }>; nextCursor?: string } }>(pageTwo)
  assert.equal(pageTwoBody.result.tools.length, 1)
  assert.equal(pageTwoBody.result.nextCursor, undefined)
  const names = [...pageOneBody.result.tools, ...pageTwoBody.result.tools].map((tool) => tool.name)
  assert.equal(new Set(names).size, names.length, "pages must not repeat tools")

  const badCursor = await callStableRpc(h.wire, environmentId, accessToken, session, {
    id: 8,
    method: "tools/list",
    params: { cursor: "definitely-not-a-cursor" },
  })
  const badCursorBody = parseRpcBody<{ error?: { code: number } }>(badCursor)
  assert.equal(badCursorBody.error?.code, -32602)
})

test("SSE response mode wraps every response in one event-stream message", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr", (scenario) => {
    scenario.protocol.responseMode = "sse"
  })
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")
  const list = await callStableRpc(h.wire, environmentId, accessToken, session, { id: 9, method: "tools/list", params: {} })
  assert.equal(list.status, 200)
  assert.match(list.headers["content-type"] ?? "", /text\/event-stream/)
  const body = parseRpcBody<{ result: { tools: unknown[] } }>(list)
  assert.ok(body.result.tools.length > 0)
})

test("POST requires the dual Accept header and sessions bind to their token family", async () => {
  const h = harness()
  const { environmentId, accessToken, clientId } = await oauthAccessToken(h, "stable-healthy-dcr")
  const missingAccept = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(missingAccept.status, 406)

  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")

  const { verifier, challenge } = pkcePair("lab-test-pkce-verifier-with-plenty-of-entropy-0000000005")
  const secondAuthorization = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(secondAuthorization.code)
  const secondToken = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: secondAuthorization.code, verifier, redirectUri: webCallback },
  })
  assert.equal(secondToken.status, 200)
  const otherAccessToken = secondToken.json<{ access_token: string }>().access_token

  const crossFamily = await callStableRpc(h.wire, environmentId, otherAccessToken, session, { id: 10, method: "tools/list", params: {} })
  assert.equal(crossFamily.status, 403)
  assert.equal(crossFamily.json().error, "mcp_session_binding_mismatch")
})

test("manual bearer and open environments authenticate accordingly", async () => {
  const h = harness()
  const manualScenario = JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, any>
  manualScenario.authentication.mode = "manual_bearer"
  const created = await h.engine.createEnvironment(manualScenario)
  const bearer = created.secrets.manualBearerToken
  assert.ok(bearer)

  const wrong = await h.wire.request(labPath(created.environment.id, "/mcp"), {
    method: "POST",
    headers: mcpHeaders("not-the-token"),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(wrong.status, 401)
  const session = await initializeStableSession(h.wire, created.environment.id, bearer, "2025-11-25")
  assert.ok(session.sessionId)

  const openScenario = JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, any>
  openScenario.authentication.mode = "none"
  const openEnvironment = await h.engine.createEnvironment(openScenario)
  const openSession = await initializeStableSession(h.wire, openEnvironment.environment.id, null, "2025-11-25")
  assert.ok(openSession.sessionId)
})

test("untrusted Origin headers are rejected", async () => {
  const h = harness()
  const { environmentId, accessToken } = await oauthAccessToken(h, "stable-healthy-dcr")
  const response = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, { origin: "https://evil.example" }),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(response.status, 403)
  assert.equal(response.json().error, "origin_not_allowed")
})

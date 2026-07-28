import assert from "node:assert/strict"
import test from "node:test"
import {
  createMcpLabEngine,
  getLabScenarioPreset,
  InMemoryMcpLabStore,
  LabReleaseCandidateDisabledError,
  type McpLabEngine,
} from "../src/index.js"
import {
  authorizeWithConsent,
  deterministicRuntime,
  exchangeToken,
  fetchWire,
  labPath,
  pkcePair,
  registerDynamicClient,
  type LabWire,
} from "./lab-wire.js"

const webCallback = "https://client.example/oauth/callback"

interface DraftHarness {
  readonly engine: McpLabEngine
  readonly wire: LabWire
  readonly environmentId: string
  readonly accessToken: string
}

function draftScenario(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(getLabScenarioPreset("draft-stateless").scenario)) as Record<string, unknown>
}

async function draftHarness(): Promise<DraftHarness> {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const engine = createMcpLabEngine({ store, runtime, allowReleaseCandidate: true })
  const wire = fetchWire(engine)
  const created = await engine.createEnvironment(draftScenario())
  const environmentId = created.environment.id
  const registration = await registerDynamicClient({ wire, environmentId, issuerPath: "/oauth", redirectUris: [webCallback] })
  assert.equal(registration.status, 201, registration.text)
  const clientId = registration.json<{ client_id: string }>().client_id
  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)
  const token = await exchangeToken({
    wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(token.status, 200, token.text)
  return { engine, wire, environmentId, accessToken: token.json<{ access_token: string }>().access_token }
}

function draftHeaders(accessToken: string, method: string, extra?: Record<string, string>): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json",
    authorization: `Bearer ${accessToken}`,
    "mcp-protocol-version": "DRAFT-2026-v1",
    "mcp-method": method,
    ...extra,
  }
}

function draftBody(method: string, id: number, params?: unknown): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id,
    method,
    ...(params === undefined ? {} : { params }),
    meta: {
      protocolVersion: "DRAFT-2026-v1",
      client: { name: "lab-draft-client", version: "1.0.0" },
      capabilities: {},
    },
  })
}

test("the release candidate stays behind the explicit engine flag", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const gatedEngine = createMcpLabEngine({ store, runtime })
  await assert.rejects(gatedEngine.createEnvironment(draftScenario()), LabReleaseCandidateDisabledError)

  // An environment created by a flag-enabled engine still refuses to serve
  // through a deployment whose flag is off.
  const enabledEngine = createMcpLabEngine({ store, runtime, allowReleaseCandidate: true })
  const created = await enabledEngine.createEnvironment(draftScenario())
  const gatedWire = fetchWire(gatedEngine)
  const response = await gatedWire.request(labPath(created.environment.id, "/mcp"), {
    method: "POST",
    headers: draftHeaders("irrelevant", "server/discover"),
    body: draftBody("server/discover", 1),
  })
  assert.equal(response.status, 503)
  assert.equal(response.json().error, "release_candidate_disabled")
})

test("server/discover returns per-request protocol, server, and capability metadata without any session", async () => {
  const h = await draftHarness()
  const discover = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "server/discover"),
    body: draftBody("server/discover", 1),
  })
  assert.equal(discover.status, 200, discover.text)
  assert.equal(discover.headers["mcp-session-id"], undefined, "the draft engine must not mint sessions")
  const body = discover.json<{ result: { protocol: { version: string; supportedVersions: string[] }; capabilities: Record<string, unknown> } }>()
  assert.equal(body.result.protocol.version, "DRAFT-2026-v1")
  assert.deepEqual(body.result.protocol.supportedVersions, ["DRAFT-2026-v1"])
  assert.ok(body.result.capabilities.tools)
})

test("initialize is rejected as removed lifecycle and unknown versions produce structured errors", async () => {
  const h = await draftHarness()
  const initialize = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "initialize"),
    body: draftBody("initialize", 1, { protocolVersion: "DRAFT-2026-v1" }),
  })
  assert.equal(initialize.status, 400)
  assert.equal(initialize.json<{ error: { code: string } }>().error.code, "lifecycle_removed")

  const wrongVersion = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "server/discover", { "mcp-protocol-version": "2025-11-25" }),
    body: draftBody("server/discover", 2),
  })
  assert.equal(wrongVersion.status, 400)
  const structured = wrongVersion.json<{ error: { code: string; requested: string; supported: string[] } }>()
  assert.equal(structured.error.code, "unsupported_protocol_version")
  assert.equal(structured.error.requested, "2025-11-25")
  assert.deepEqual(structured.error.supported, ["DRAFT-2026-v1"])
})

test("required headers and header/body consistency are enforced", async () => {
  const h = await draftHarness()
  const missingMethodHeader = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${h.accessToken}`,
      "mcp-protocol-version": "DRAFT-2026-v1",
    },
    body: draftBody("server/discover", 1),
  })
  assert.equal(missingMethodHeader.status, 400)
  assert.equal(missingMethodHeader.json<{ error: { code: string } }>().error.code, "missing_mcp_method_header")

  const mismatchedMethod = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "tools/list"),
    body: draftBody("server/discover", 2),
  })
  assert.equal(mismatchedMethod.status, 400)
  assert.equal(mismatchedMethod.json<{ error: { code: string } }>().error.code, "header_body_mismatch")

  const missingMeta = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "server/discover"),
    body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "server/discover" }),
  })
  assert.equal(missingMeta.status, 400)
  assert.equal(missingMeta.json<{ error: { code: string } }>().error.code, "invalid_request_envelope")

  const bodyVersionMismatch = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "server/discover"),
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 4,
      method: "server/discover",
      meta: { protocolVersion: "2025-11-25", client: { name: "x", version: "1" } },
    }),
  })
  assert.equal(bodyVersionMismatch.status, 400)
  assert.equal(bodyVersionMismatch.json<{ error: { code: string } }>().error.code, "header_body_mismatch")
})

test("draft tools/list carries caching metadata and 2020-12 schemas; tools/call needs Mcp-Name", async () => {
  const h = await draftHarness()
  const list = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "tools/list"),
    body: draftBody("tools/list", 1, {}),
  })
  assert.equal(list.status, 200, list.text)
  const listBody = list.json<{
    result: { tools: Array<{ name: string; inputSchema: Record<string, unknown> }>; ttlMs: number; cacheScope: string }
  }>()
  assert.equal(listBody.result.ttlMs, 60_000)
  assert.equal(listBody.result.cacheScope, "client")
  assert.equal(listBody.result.tools[0]?.inputSchema.$schema, "https://json-schema.org/draft/2020-12/schema")

  const toolName = listBody.result.tools[0]?.name
  assert.ok(toolName)

  const missingName = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "tools/call"),
    body: draftBody("tools/call", 2, { name: toolName, arguments: {} }),
  })
  assert.equal(missingName.status, 400)
  assert.equal(missingName.json<{ error: { code: string } }>().error.code, "missing_mcp_name_header")

  const wrongName = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "tools/call", { "mcp-name": "another_tool" }),
    body: draftBody("tools/call", 3, { name: toolName, arguments: {} }),
  })
  assert.equal(wrongName.status, 400)

  const call = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: draftHeaders(h.accessToken, "tools/call", { "mcp-name": toolName }),
    body: draftBody("tools/call", 4, { name: toolName, arguments: { query: "draft" } }),
  })
  assert.equal(call.status, 200, call.text)
  const callBody = call.json<{ result: { isError: boolean; structuredContent: { synthetic: boolean } } }>()
  assert.equal(callBody.result.isError, false)
  assert.equal(callBody.result.structuredContent.synthetic, true)
})

test("draft requests still require OAuth and GET is rejected", async () => {
  const h = await draftHarness()
  const unauthenticated = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    method: "POST",
    headers: { "content-type": "application/json", "mcp-protocol-version": "DRAFT-2026-v1", "mcp-method": "server/discover" },
    body: draftBody("server/discover", 1),
  })
  assert.equal(unauthenticated.status, 401)
  assert.match(unauthenticated.headers["www-authenticate"] ?? "", /resource_metadata/)

  const getRejected = await h.wire.request(labPath(h.environmentId, "/mcp"), {
    headers: draftHeaders(h.accessToken, "server/discover"),
  })
  assert.equal(getRejected.status, 405)
  assert.equal(getRejected.headers.allow, "POST")
})

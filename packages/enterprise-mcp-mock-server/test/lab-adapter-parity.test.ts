import assert from "node:assert/strict"
import test from "node:test"
import {
  createLabNodeServer,
  createMcpLabEngine,
  getLabScenarioPreset,
  InMemoryMcpLabStore,
} from "../src/index.js"
import {
  consentFields,
  deterministicRuntime,
  fetchWire,
  labPath,
  mcpHeaders,
  nodeWire,
  pkcePair,
  type LabWire,
  type WireResponse,
} from "./lab-wire.js"

const webCallback = "https://client.example/oauth/callback"

interface StepRecord {
  readonly label: string
  readonly status: number
  readonly contentType: string
  readonly headers: Record<string, string | undefined>
  readonly body: string
}

const comparedHeaders = ["mcp-session-id", "mcp-protocol-version", "location", "www-authenticate", "allow"] as const

/**
 * The two adapters necessarily run on different origins, so the origin is
 * replaced before comparison. It also has to be replaced in its percent-encoded
 * form: the authorization response carries `iss` as a query parameter, where
 * `https://lab.test` is serialized as `https%3A%2F%2Flab.test`.
 */
function normalize(value: string, origin: string): string {
  return value.split(origin).join("{ORIGIN}").split(encodeURIComponent(origin)).join("{ORIGIN}")
}

/**
 * Drives one full journey and records every wire exchange with the origin
 * normalized away, so the Node and Fetch adapters can be compared for
 * equivalent wire behavior. Recording is a side effect: callers get the raw
 * response so control flow never reads a normalized value back.
 */
async function runJourney(wire: LabWire, environmentId: string): Promise<StepRecord[]> {
  const steps: StepRecord[] = []
  const record = async (label: string, response: WireResponse): Promise<WireResponse> => {
    const headers: Record<string, string | undefined> = {}
    for (const header of comparedHeaders) {
      const raw = response.headers[header]
      headers[header] = raw === undefined ? undefined : normalize(raw, wire.origin)
    }
    steps.push({
      label,
      status: response.status,
      contentType: response.headers["content-type"] ?? "",
      headers,
      body: normalize(response.text, wire.origin),
    })
    return response
  }

  await record("challenge", await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(null),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "parity", version: "1" } } }),
  }))
  await record("prm", await wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`))
  await record("as-metadata", await wire.request(`/.well-known/oauth-authorization-server${labPath(environmentId, "/oauth")}`))
  // RFC 7591 defaults token_endpoint_auth_method to client_secret_basic, so a
  // public client has to declare "none" explicitly or this preset rejects it.
  const registration = await record("register", await wire.request(labPath(environmentId, "/oauth/register"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [webCallback], token_endpoint_auth_method: "none", client_name: "Parity client" }),
  }))
  assert.equal(registration.status, 201, registration.text)
  const clientId = registration.json<{ client_id: string }>().client_id

  const { verifier, challenge } = pkcePair()
  const authorizeParameters = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: webCallback,
    scope: "mcp:tools",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `${wire.origin}${labPath(environmentId, "/mcp")}`,
    state: "parity-state",
  })
  const authorize = await record("authorize", await wire.request(labPath(environmentId, `/oauth/authorize?${authorizeParameters.toString()}`)))
  const fields = consentFields(authorize.text)
  const consentForm = new URLSearchParams({ request_id: fields.requestId, decision: "approve" })
  if (fields.state !== null) consentForm.set("state", fields.state)
  const consent = await record("consent", await wire.request(labPath(environmentId, "/oauth/consent"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: consentForm.toString(),
  }))
  const location = consent.headers.location
  assert.ok(location)
  const code = new URL(location).searchParams.get("code")
  assert.ok(code)

  const token = await record("token", await wire.request(labPath(environmentId, "/oauth/token"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: webCallback,
      resource: `${wire.origin}${labPath(environmentId, "/mcp")}`,
    }).toString(),
  }))
  assert.equal(token.status, 200, token.text)
  const accessToken = token.json<{ access_token: string }>().access_token

  const initialize = await record("initialize", await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken),
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "parity", version: "1" } } }),
  }))
  const sessionId = initialize.headers["mcp-session-id"]
  assert.ok(sessionId)
  const sessionHeaders = { "mcp-session-id": sessionId, "mcp-protocol-version": "2025-11-25" }

  await record("initialized", await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, sessionHeaders),
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  }))
  await record("tools-list", await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, sessionHeaders),
    body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list", params: {} }),
  }))
  await record("tools-call", await wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken, sessionHeaders),
    body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "conformance_echo", arguments: { query: "parity" } } }),
  }))
  await record("session-delete", await wire.request(labPath(environmentId, "/mcp"), {
    method: "DELETE",
    headers: mcpHeaders(accessToken, sessionHeaders),
  }))
  await record("not-found", await wire.request(labPath(environmentId, "/nope")))
  return steps
}

test("the Node and Fetch adapters return equivalent wire behavior for the whole journey", async () => {
  const scenario = (): Record<string, unknown> =>
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>

  const fetchEngine = createMcpLabEngine({ store: new InMemoryMcpLabStore(), runtime: deterministicRuntime() })
  const fetchCreated = await fetchEngine.createEnvironment(scenario())
  const fetchSteps = await runJourney(fetchWire(fetchEngine), fetchCreated.environment.id)

  const nodeEngine = createMcpLabEngine({ store: new InMemoryMcpLabStore(), runtime: deterministicRuntime() })
  const nodeServer = createLabNodeServer({ engine: nodeEngine })
  const baseUrl = await nodeServer.start()
  try {
    const nodeCreated = await nodeEngine.createEnvironment(scenario())
    assert.equal(nodeCreated.environment.id, fetchCreated.environment.id, "deterministic runtimes must mint identical ids")
    const nodeSteps = await runJourney(nodeWire(baseUrl), nodeCreated.environment.id)
    assert.equal(fetchSteps.length, nodeSteps.length)
    for (const [index, fetchStep] of fetchSteps.entries()) {
      const nodeStep = nodeSteps[index]
      assert.ok(nodeStep)
      assert.deepEqual(
        { ...nodeStep },
        { ...fetchStep },
        `adapter divergence at step '${fetchStep.label}'`,
      )
    }
  } finally {
    await nodeServer.stop()
  }
})

test("the node adapter refuses to bind beyond loopback", () => {
  const engine = createMcpLabEngine({ store: new InMemoryMcpLabStore(), runtime: deterministicRuntime() })
  assert.throws(() => createLabNodeServer({ engine, host: "0.0.0.0" }))
})

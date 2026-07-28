import assert from "node:assert/strict"
import test from "node:test"
import {
  assertSafeCimdUrl,
  createMcpLabEngine,
  defaultCimdPolicy,
  getLabScenarioPreset,
  InMemoryMcpLabStore,
  type CimdFetcher,
  type McpLabEngine,
} from "../src/index.js"
import {
  authorizeWithConsent,
  deterministicRuntime,
  exchangeToken,
  fetchWire,
  initializeStableSession,
  labPath,
  pkcePair,
  type DeterministicRuntime,
  type LabWire,
} from "./lab-wire.js"

const webCallback = "https://client.example/oauth/callback"
const cimdUrl = "https://client.example/.well-known/cimd.json"

interface FakeDocumentServer {
  readonly fetcher: CimdFetcher
  readonly requests: Array<{ url: string; headers: Record<string, string> }>
  set(url: string, response: { status: number; headers?: Record<string, string>; body: string }): void
}

function fakeDocumentServer(): FakeDocumentServer {
  const responses = new Map<string, { status: number; headers?: Record<string, string>; body: string }>()
  const requests: Array<{ url: string; headers: Record<string, string> }> = []
  return {
    requests,
    set(url, response) {
      responses.set(url, response)
    },
    fetcher: async (url, init) => {
      requests.push({ url, headers: { ...init.headers } })
      const found = responses.get(url)
      if (!found) return { status: 404, headers: {}, body: "" }
      return { status: found.status, headers: { "content-type": "application/json", ...found.headers }, body: found.body }
    },
  }
}

function cimdDocument(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    client_id: cimdUrl,
    client_name: "CIMD lab client",
    redirect_uris: [webCallback],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    ...overrides,
  })
}

interface Harness {
  readonly engine: McpLabEngine
  readonly wire: LabWire
  readonly runtime: DeterministicRuntime
  readonly documents: FakeDocumentServer
}

function cimdHarness(): Harness {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const documents = fakeDocumentServer()
  const engine = createMcpLabEngine({ store, runtime, cimdFetcher: documents.fetcher })
  return { engine, wire: fetchWire(engine), runtime, documents }
}

async function cimdEnvironment(h: Harness): Promise<string> {
  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-cimd").scenario)) as Record<string, unknown>
  const created = await h.engine.createEnvironment(scenario)
  return created.environment.id
}

test("CIMD metadata is advertised and a URL client completes the full flow without DCR", async () => {
  const h = cimdHarness()
  const environmentId = await cimdEnvironment(h)
  h.documents.set(cimdUrl, { status: 200, body: cimdDocument() })

  const metadata = await h.wire.request(`/.well-known/oauth-authorization-server${labPath(environmentId, "/oauth")}`)
  const metadataBody = metadata.json<Record<string, unknown>>()
  assert.equal(metadataBody.client_id_metadata_document_supported, true)
  assert.equal(metadataBody.registration_endpoint, undefined, "CIMD preset keeps DCR disabled")

  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
    state: "cimd-state",
  })
  assert.ok(outcome.code)
  assert.equal(outcome.state, "cimd-state")

  const token = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(token.status, 200, token.text)
  const accessToken = token.json<{ access_token: string }>().access_token
  const session = await initializeStableSession(h.wire, environmentId, accessToken, "2025-11-25")
  assert.ok(session.sessionId)
})

test("CIMD fetches never forward credentials and respect the short cache lifetime", async () => {
  const h = cimdHarness()
  const environmentId = await cimdEnvironment(h)
  h.documents.set(cimdUrl, { status: 200, body: cimdDocument() })
  const { challenge } = pkcePair()

  await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.equal(h.documents.requests.length, 1, "the second authorization must hit the cached document")
  for (const request of h.documents.requests) {
    assert.equal(request.headers.authorization, undefined)
    assert.equal(request.headers.cookie, undefined)
  }

  h.runtime.advance((defaultCimdPolicy.cacheTtlSeconds + 5) * 1_000)
  await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.equal(h.documents.requests.length, 2, "an expired cache entry must be refetched")
})

test("CIMD documents with a mismatched client_id are rejected", async () => {
  const h = cimdHarness()
  const environmentId = await cimdEnvironment(h)
  h.documents.set(cimdUrl, { status: 200, body: cimdDocument({ client_id: "https://client.example/other.json" }) })
  const { challenge } = pkcePair()
  const parameters = new URLSearchParams({
    response_type: "code",
    client_id: cimdUrl,
    redirect_uri: webCallback,
    scope: "mcp:tools",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `https://lab.test${labPath(environmentId, "/mcp")}`,
  })
  const response = await h.wire.request(labPath(environmentId, `/oauth/authorize?${parameters.toString()}`))
  assert.equal(response.status, 400)
  assert.match(response.text, /Unknown client/)
})

test("malformed, oversized-status, and non-JSON CIMD documents are rejected", async () => {
  const h = cimdHarness()
  const environmentId = await cimdEnvironment(h)
  const { challenge } = pkcePair()
  const attempt = async (): Promise<number> => {
    const parameters = new URLSearchParams({
      response_type: "code",
      client_id: cimdUrl,
      redirect_uri: webCallback,
      scope: "mcp:tools",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: `https://lab.test${labPath(environmentId, "/mcp")}`,
    })
    const response = await h.wire.request(labPath(environmentId, `/oauth/authorize?${parameters.toString()}`))
    return response.status
  }

  h.documents.set(cimdUrl, { status: 200, body: "not json {" })
  assert.equal(await attempt(), 400)
  h.documents.set(cimdUrl, { status: 500, body: cimdDocument() })
  assert.equal(await attempt(), 400)
  h.documents.set(cimdUrl, { status: 200, headers: { "content-type": "text/html" }, body: cimdDocument() })
  assert.equal(await attempt(), 400)
  h.documents.set(cimdUrl, { status: 200, body: JSON.stringify({ client_id: cimdUrl }) })
  assert.equal(await attempt(), 400, "documents without redirect_uris are malformed")
})

test("SSRF guard blocks private, loopback, credentialed, and non-HTTPS client_id URLs", () => {
  const policy = defaultCimdPolicy
  const blocked = [
    "https://10.0.0.8/cimd.json",
    "https://192.168.1.10/cimd.json",
    "https://172.16.0.1/cimd.json",
    "https://169.254.169.254/latest/meta-data",
    "https://127.0.0.1/cimd.json",
    "https://[::1]/cimd.json",
    "https://[fd00::1]/cimd.json",
    "https://[fe80::1]/cimd.json",
    // URL canonicalizes these to hex (e.g. [::ffff:a00:8]), so they only stay
    // blocked if the guard parses the address instead of matching spellings.
    "https://[::ffff:10.0.0.8]/cimd.json",
    "https://[::ffff:127.0.0.1]/cimd.json",
    "https://[::ffff:192.168.1.10]/cimd.json",
    "https://[64:ff9b::10.0.0.8]/cimd.json",
    "https://[ff02::1]/cimd.json",
    "https://[::]/cimd.json",
    "https://[fcff::1]/cimd.json",
    "https://[febf::1]/cimd.json",
    "https://100.64.0.1/cimd.json",
    "https://localhost/cimd.json",
    "http://client.example/cimd.json",
    "https://user:pass@client.example/cimd.json",
    "https://client.example/cimd.json#fragment",
    "ftp://client.example/cimd.json",
  ]
  for (const url of blocked) {
    const verdict = assertSafeCimdUrl(url, policy)
    assert.equal(verdict.ok, false, `expected rejection for ${url}`)
  }
  assert.equal(assertSafeCimdUrl("https://client.example/cimd.json", policy).ok, true)
  assert.equal(assertSafeCimdUrl("http://127.0.0.1:8080/cimd.json", { ...policy, allowLoopback: true }).ok, true)
  assert.equal(assertSafeCimdUrl("http://localhost:3000/cimd.json", policy).ok, false)

  // The fail-closed IPv6 default must not over-block routable hosts.
  for (const allowed of ["https://[2606:4700::1111]/cimd.json", "https://[2001:4860:4860::8888]/cimd.json"]) {
    assert.equal(assertSafeCimdUrl(allowed, policy).ok, true, `expected ${allowed} to be allowed`)
  }
})

test("CIMD redirects are revalidated and bounded", async () => {
  const h = cimdHarness()
  const environmentId = await cimdEnvironment(h)
  const { challenge } = pkcePair()
  const attempt = async (): Promise<number> => {
    const parameters = new URLSearchParams({
      response_type: "code",
      client_id: cimdUrl,
      redirect_uri: webCallback,
      scope: "mcp:tools",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource: `https://lab.test${labPath(environmentId, "/mcp")}`,
    })
    const response = await h.wire.request(labPath(environmentId, `/oauth/authorize?${parameters.toString()}`))
    return response.status
  }

  // Redirect to a private address must be blocked even though the first URL is public.
  h.documents.set(cimdUrl, { status: 302, headers: { location: "https://169.254.169.254/meta" }, body: "" })
  assert.equal(await attempt(), 400)

  // Redirect loops beyond the budget are cut off.
  h.documents.set(cimdUrl, { status: 302, headers: { location: cimdUrl }, body: "" })
  assert.equal(await attempt(), 400)

  // A single safe redirect is followed, but the document must still name the original client_id URL.
  const movedUrl = "https://client.example/moved-cimd.json"
  h.documents.set(cimdUrl, { status: 302, headers: { location: movedUrl }, body: "" })
  h.documents.set(movedUrl, { status: 200, body: cimdDocument() })
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)
})

test("CIMD works alongside DCR when both are advertised, and stays disabled when unsupported", async () => {
  const h = cimdHarness()
  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, any>
  scenario.authentication.authorizationServers = [
    { issuerPath: "/oauth", clientIdMetadataDocumentSupported: true, registrationEndpointEnabled: true },
  ]
  const created = await h.engine.createEnvironment(scenario)
  const environmentId = created.environment.id
  h.documents.set(cimdUrl, { status: 200, body: cimdDocument() })

  const metadata = await h.wire.request(`/.well-known/oauth-authorization-server${labPath(environmentId, "/oauth")}`)
  const metadataBody = metadata.json<Record<string, unknown>>()
  assert.equal(metadataBody.client_id_metadata_document_supported, true)
  assert.ok(metadataBody.registration_endpoint, "both registration paths advertised")

  const { challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: cimdUrl,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code, "a client that prefers CIMD over DCR completes without registering")

  const h2 = cimdHarness()
  const plainDcr = await h2.engine.createEnvironment(
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>,
  )
  h2.documents.set(cimdUrl, { status: 200, body: cimdDocument() })
  const pkce = pkcePair()
  const parameters = new URLSearchParams({
    response_type: "code",
    client_id: cimdUrl,
    redirect_uri: webCallback,
    scope: "mcp:tools",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    resource: `https://lab.test${labPath(plainDcr.environment.id, "/mcp")}`,
  })
  const rejected = await h2.wire.request(labPath(plainDcr.environment.id, `/oauth/authorize?${parameters.toString()}`))
  assert.equal(rejected.status, 400, "URL client ids are refused when the issuer does not support CIMD")
  assert.equal(h2.documents.requests.length, 0, "no fetch may happen when CIMD is unsupported")
})

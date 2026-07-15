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
  deterministicRuntime,
  exchangeToken,
  fetchWire,
  initializeStableSession,
  labPath,
  callStableRpc,
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

function presetScenario(presetId: LabScenarioPresetId, patch?: (scenario: Record<string, any>) => void): unknown {
  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset(presetId).scenario)) as Record<string, any>
  patch?.(scenario)
  return scenario
}

const webCallback = "https://client.example/oauth/callback"

async function dcrEnvironment(h: Harness, presetId: LabScenarioPresetId = "stable-healthy-dcr", patch?: (s: Record<string, any>) => void) {
  const created = await h.engine.createEnvironment(presetScenario(presetId, patch))
  return created
}

async function registeredClient(h: Harness, environmentId: string, issuerPath = "/oauth"): Promise<string> {
  const registration = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath,
    redirectUris: [webCallback],
  })
  assert.equal(registration.status, 201, registration.text)
  const clientId = registration.json<{ client_id: string }>().client_id
  assert.ok(clientId)
  return clientId
}

test("RFC 9728 challenge points at the environment PRM and both well-known locations serve metadata", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const environmentId = environment.id

  const unauthenticated = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(null),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(unauthenticated.status, 401)
  const challenge = unauthenticated.headers["www-authenticate"] ?? ""
  assert.match(challenge, /resource_metadata="https:\/\/lab\.test\/\.well-known\/oauth-protected-resource\/lab\//)
  assert.match(challenge, /scope="mcp:tools"/)

  const prm = await h.wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`)
  assert.equal(prm.status, 200)
  const prmBody = prm.json<{ resource: string; authorization_servers: string[] }>()
  assert.equal(prmBody.resource, `https://lab.test${labPath(environmentId, "/mcp")}`)
  assert.deepEqual(prmBody.authorization_servers, [`https://lab.test${labPath(environmentId, "/oauth")}`])

  const rfc8414 = await h.wire.request(`/.well-known/oauth-authorization-server${labPath(environmentId, "/oauth")}`)
  assert.equal(rfc8414.status, 200)
  const asMetadata = rfc8414.json<Record<string, unknown>>()
  assert.equal(asMetadata.issuer, `https://lab.test${labPath(environmentId, "/oauth")}`)
  assert.deepEqual(asMetadata.code_challenge_methods_supported, ["S256"])
  assert.ok(asMetadata.registration_endpoint)
  assert.equal(asMetadata.client_id_metadata_document_supported, undefined)

  const oidc = await h.wire.request(`/.well-known/openid-configuration${labPath(environmentId, "/oauth")}`)
  assert.equal(oidc.status, 200)
  assert.ok(oidc.json<Record<string, unknown>>().jwks_uri)

  const oidcSuffix = await h.wire.request(labPath(environmentId, "/oauth/.well-known/openid-configuration"))
  assert.equal(oidcSuffix.status, 200)
})

test("OIDC-only discovery hides the RFC 8414 document so fallback ordering is exercised", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "oidc-only-discovery")
  const rfc8414 = await h.wire.request(`/.well-known/oauth-authorization-server${labPath(environment.id, "/oauth")}`)
  assert.equal(rfc8414.status, 404)
  const oidc = await h.wire.request(`/.well-known/openid-configuration${labPath(environment.id, "/oauth")}`)
  assert.equal(oidc.status, 200)
})

test("full web DCR journey: register, consent, exchange, initialize, list, call", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const environmentId = environment.id
  const issuer = `https://lab.test${labPath(environmentId, "/oauth")}`
  const clientId = await registeredClient(h, environmentId)
  const { verifier, challenge } = pkcePair()

  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
    state: "journey-state-1",
  })
  assert.ok(outcome.code)
  assert.equal(outcome.state, "journey-state-1")
  assert.equal(outcome.iss, issuer)

  const token = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(token.status, 200, token.text)
  const tokenBody = token.json<{ access_token: string; refresh_token?: string; token_type: string; expires_in: number; scope: string }>()
  assert.equal(tokenBody.token_type, "Bearer")
  assert.equal(tokenBody.scope, "mcp:tools")
  assert.ok(tokenBody.refresh_token, "healthy DCR preset issues refresh tokens")

  const session = await initializeStableSession(h.wire, environmentId, tokenBody.access_token, "2025-11-25")
  assert.equal(session.protocolVersion, "2025-11-25")

  const list = await callStableRpc(h.wire, environmentId, tokenBody.access_token, session, { id: 2, method: "tools/list", params: {} })
  assert.equal(list.status, 200)
  const listBody = parseRpcBody<{ result: { tools: Array<{ name: string }>; nextCursor?: string } }>(list)
  assert.ok(listBody.result.tools.length > 0)

  const firstTool = listBody.result.tools[0]?.name
  assert.ok(firstTool)
  const call = await callStableRpc(h.wire, environmentId, tokenBody.access_token, session, {
    id: 3,
    method: "tools/call",
    params: { name: firstTool, arguments: { query: "hello" } },
  })
  assert.equal(call.status, 200)
  const callBody = parseRpcBody<{ result: { isError: boolean; structuredContent: { synthetic: boolean } } }>(call)
  assert.equal(callBody.result.isError, false)
  assert.equal(callBody.result.structuredContent.synthetic, true)

  const trace = await h.engine.listTrace(environmentId)
  assert.ok(trace.length > 5)
})

test("authorization codes are single-use and PKCE mismatches are rejected", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const environmentId = environment.id
  const clientId = await registeredClient(h, environmentId)
  const { verifier, challenge } = pkcePair()

  const first = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(first.code)
  const wrongVerifier = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: first.code, verifier: `${verifier}-but-wrong`, redirectUri: webCallback },
  })
  assert.equal(wrongVerifier.status, 400)
  assert.equal(wrongVerifier.json().error, "invalid_grant")

  const consumedReplay = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: first.code, verifier, redirectUri: webCallback },
  })
  assert.equal(consumedReplay.status, 400)
  assert.equal(consumedReplay.json().error, "invalid_grant")

  const second = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(second.code)
  const success = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: second.code, verifier, redirectUri: webCallback },
  })
  assert.equal(success.status, 200)
  const replayAfterSuccess = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    grant: { type: "authorization_code", code: second.code, verifier, redirectUri: webCallback },
  })
  assert.equal(replayAfterSuccess.status, 400)
  assert.equal(replayAfterSuccess.json().error, "invalid_grant")
})

test("authorize enforces exact redirect, resource, response type, PKCE method, and scopes", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const environmentId = environment.id
  const clientId = await registeredClient(h, environmentId)
  const { challenge } = pkcePair()
  const resource = `https://lab.test${labPath(environmentId, "/mcp")}`

  const base = () =>
    new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: webCallback,
      scope: "mcp:tools",
      code_challenge: challenge,
      code_challenge_method: "S256",
      resource,
      state: "edge-state",
    })

  const unregisteredRedirect = base()
  unregisteredRedirect.set("redirect_uri", "https://attacker.example/callback")
  const redirectRejected = await h.wire.request(labPath(environmentId, `/oauth/authorize?${unregisteredRedirect.toString()}`))
  assert.equal(redirectRejected.status, 400)
  assert.match(redirectRejected.headers["content-type"] ?? "", /text\/html/)

  const cases: ReadonlyArray<{ mutate: (parameters: URLSearchParams) => void; error: string }> = [
    { mutate: (parameters) => parameters.set("response_type", "token"), error: "unsupported_response_type" },
    { mutate: (parameters) => parameters.set("code_challenge_method", "plain"), error: "invalid_request" },
    { mutate: (parameters) => parameters.delete("resource"), error: "invalid_target" },
    { mutate: (parameters) => parameters.set("resource", "https://other.example/mcp"), error: "invalid_target" },
    { mutate: (parameters) => parameters.set("scope", "unknown:scope mcp:tools"), error: "invalid_scope" },
    { mutate: (parameters) => parameters.delete("scope"), error: "invalid_scope" },
  ]
  for (const { mutate, error } of cases) {
    const parameters = base()
    mutate(parameters)
    const response = await h.wire.request(labPath(environmentId, `/oauth/authorize?${parameters.toString()}`))
    assert.equal(response.status, 302, `${error}: expected redirect`)
    const location = new URL(response.headers.location ?? "")
    assert.equal(location.searchParams.get("error"), error)
    assert.equal(location.searchParams.get("state"), "edge-state")
  }
})

test("authorization response iss behavior: correct, missing, and mismatched", async () => {
  for (const [presetId, expectation] of [
    ["stable-healthy-dcr", "correct"],
    ["issuer-mismatch", "mismatched"],
  ] as const) {
    const h = harness()
    const { environment } = await dcrEnvironment(h, presetId)
    const environmentId = environment.id
    const clientId = await registeredClient(h, environmentId)
    const { challenge } = pkcePair()
    const outcome = await authorizeWithConsent({
      wire: h.wire,
      environmentId,
      issuerPath: "/oauth",
      clientId,
      redirectUri: webCallback,
      scopes: ["mcp:tools"],
      challenge,
    })
    const issuer = `https://lab.test${labPath(environmentId, "/oauth")}`
    if (expectation === "correct") {
      assert.equal(outcome.iss, issuer)
    } else {
      assert.ok(outcome.iss)
      assert.notEqual(outcome.iss, issuer)
    }
  }

  const h = harness()
  const { environment } = await dcrEnvironment(h, "stable-healthy-dcr", (scenario) => {
    scenario.authentication.authorizationResponseIssuer = "missing"
  })
  const clientId = await registeredClient(h, environment.id)
  const { challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId: environment.id,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.equal(outcome.iss, null)
})

test("consent deny redirects with access_denied and echoes state", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const clientId = await registeredClient(h, environment.id)
  const { challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId: environment.id,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
    state: "deny-state",
    decision: "deny",
  })
  assert.equal(outcome.code, null)
  assert.equal(outcome.error, "access_denied")
  assert.equal(outcome.state, "deny-state")
})

test("consent requests are single-use and automation requires the signed token", async () => {
  const h = harness()
  const created = await h.engine.createEnvironment(presetScenario("stable-healthy-dcr"), { enableAutomationConsent: true })
  const environmentId = created.environment.id
  const automationToken = created.secrets.automationConsentToken
  assert.ok(automationToken)
  const clientId = await registeredClient(h, environmentId)
  const { challenge } = pkcePair()

  const approved = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
    automationToken,
  })
  assert.ok(approved.code)

  const authorize = await h.wire.request(
    labPath(
      environmentId,
      `/oauth/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: webCallback,
        scope: "mcp:tools",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: `https://lab.test${labPath(environmentId, "/mcp")}`,
      }).toString()}`,
    ),
  )
  const requestId = /name="request_id" value="([^"]+)"/.exec(authorize.text)?.[1]
  assert.ok(requestId)

  const wrongToken = await h.wire.request(labPath(environmentId, "/oauth/consent"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId, decision: "approve", automation_token: "forged-token" }).toString(),
  })
  assert.equal(wrongToken.status, 403)
  assert.equal(wrongToken.json().error, "invalid_automation_token")

  const reuse = await h.wire.request(labPath(environmentId, "/oauth/consent"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId, decision: "approve", automation_token: automationToken }).toString(),
  })
  assert.equal(reuse.status, 302)

  const replayed = await h.wire.request(labPath(environmentId, "/oauth/consent"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: requestId, decision: "approve", automation_token: automationToken }).toString(),
  })
  assert.equal(replayed.status, 400)
})

test("query parameters can never auto-approve an authorization request", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h)
  const clientId = await registeredClient(h, environment.id)
  const { challenge } = pkcePair()
  const parameters = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: webCallback,
    scope: "mcp:tools",
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `https://lab.test${labPath(environment.id, "/mcp")}`,
    auto_approve: "true",
    prompt: "none",
  })
  const response = await h.wire.request(labPath(environment.id, `/oauth/authorize?${parameters.toString()}`))
  assert.equal(response.status, 200)
  assert.match(response.headers["content-type"] ?? "", /text\/html/)
  assert.match(response.text, /Approve/)
})

test("DCR validates application types, redirects, grants, response types, auth method, and scope", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "stable-healthy-dcr", (scenario) => {
    scenario.authentication.applicationTypes = ["web", "native"]
  })
  const environmentId = environment.id

  const webLoopback = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: ["http://127.0.0.1:43110/callback"],
    applicationType: "web",
  })
  assert.equal(webLoopback.status, 400)
  assert.equal(webLoopback.json().error, "invalid_redirect_uri")

  const nativeLoopback = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: ["http://127.0.0.1:43110/callback", "com.example.app:/oauth"],
    applicationType: "native",
  })
  assert.equal(nativeLoopback.status, 201, nativeLoopback.text)

  const badGrant = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    grantTypes: ["implicit"],
  })
  assert.equal(badGrant.status, 400)
  assert.equal(badGrant.json().error, "invalid_client_metadata")

  const badResponseType = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    responseTypes: ["token"],
  })
  assert.equal(badResponseType.status, 400)

  const badMethod = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    tokenEndpointAuthMethod: "client_secret_post",
  })
  assert.equal(badMethod.status, 400)
  assert.equal(badMethod.json().error, "invalid_client_metadata")

  const badScope = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    scope: "mcp:tools not:allowed",
  })
  assert.equal(badScope.status, 400)
})

test("dynamic registration with secrets stores hashes and enforces the auth method at the token endpoint", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "stable-healthy-dcr", (scenario) => {
    scenario.authentication.tokenEndpointAuthMethods = ["client_secret_basic", "none"]
  })
  const environmentId = environment.id
  const registration = await registerDynamicClient({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    tokenEndpointAuthMethod: "client_secret_basic",
  })
  assert.equal(registration.status, 201, registration.text)
  const registrationBody = registration.json<{ client_id: string; client_secret?: string }>()
  assert.ok(registrationBody.client_secret, "confidential registration returns the secret exactly once")

  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)

  const missingSecret = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(missingSecret.status, 401)
  assert.equal(missingSecret.json().error, "invalid_client")

  const outcome2 = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome2.code)
  const withBasic = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    clientSecret: registrationBody.client_secret,
    secretTransport: "basic",
    grant: { type: "authorization_code", code: outcome2.code, verifier, redirectUri: webCallback },
  })
  assert.equal(withBasic.status, 200, withBasic.text)
})

test("manual pre-registered clients work with the one-time secret", async () => {
  const h = harness()
  const created = await h.engine.createEnvironment(presetScenario("stable-manual-client"))
  const environmentId = created.environment.id
  const manualClient = created.environment.manualClient
  const manualSecret = created.secrets.manualClientSecret
  assert.ok(manualClient)
  assert.ok(manualSecret)
  assert.equal(created.environment.manualClient?.clientSecretHash?.startsWith("sha256:"), true)

  const redirectUri = manualClient.redirectUris[0]
  assert.ok(redirectUri)
  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: manualClient.clientId,
    redirectUri,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)
  const token = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: manualClient.clientId,
    clientSecret: manualSecret,
    secretTransport: "basic",
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri },
  })
  assert.equal(token.status, 200, token.text)
})

test("none_available environments expose no registration surface", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "no-registration-available")
  const metadata = await h.wire.request(`/.well-known/oauth-authorization-server${labPath(environment.id, "/oauth")}`)
  assert.equal(metadata.status, 200)
  const body = metadata.json<Record<string, unknown>>()
  assert.equal(body.registration_endpoint, undefined)
  assert.equal(body.client_id_metadata_document_supported, undefined)
  const registration = await registerDynamicClient({
    wire: h.wire,
    environmentId: environment.id,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
  })
  assert.equal(registration.status, 404)
  assert.equal(registration.json().error, "registration_not_supported")
})

test("multiple issuers advertise separately and registrations stay issuer-bound", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "multiple-issuers")
  const environmentId = environment.id
  const prm = await h.wire.request(`/.well-known/oauth-protected-resource${labPath(environmentId, "/mcp")}`)
  const servers = prm.json<{ authorization_servers: string[] }>().authorization_servers
  assert.equal(servers.length, 2)

  const clientId = await registeredClient(h, environmentId, "/oauth-primary")
  const { verifier, challenge } = pkcePair()
  const outcome = await authorizeWithConsent({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth-primary",
    clientId,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
  })
  assert.ok(outcome.code)

  const crossIssuerExchange = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth-secondary",
    clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(crossIssuerExchange.status, 401)
  assert.equal(crossIssuerExchange.json().error, "invalid_client")

  const sameIssuerExchange = await exchangeToken({
    wire: h.wire,
    environmentId,
    issuerPath: "/oauth-primary",
    clientId,
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(sameIssuerExchange.status, 200, sameIssuerExchange.text)
})

test("invalid-grant fault forces clean reauthorization and 503 fault stays bounded", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "invalid-grant")
  const environmentId = environment.id
  const clientId = await registeredClient(h, environmentId)
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
  assert.equal(token.status, 400)
  assert.equal(token.json().error, "invalid_grant")

  const h2 = harness()
  const second = await h2.engine.createEnvironment(
    presetScenario("stable-healthy-dcr", (scenario) => {
      scenario.fault = { id: "authorization-server-unavailable", occurrence: "once" }
    }),
  )
  const clientId2 = await registeredClient(h2, second.environment.id)
  const pkce2 = pkcePair("lab-test-pkce-verifier-with-plenty-of-entropy-0000000002")
  const outcome2 = await authorizeWithConsent({
    wire: h2.wire,
    environmentId: second.environment.id,
    issuerPath: "/oauth",
    clientId: clientId2,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge: pkce2.challenge,
  })
  assert.ok(outcome2.code)
  const unavailable = await exchangeToken({
    wire: h2.wire,
    environmentId: second.environment.id,
    issuerPath: "/oauth",
    clientId: clientId2,
    grant: { type: "authorization_code", code: outcome2.code, verifier: pkce2.verifier, redirectUri: webCallback },
  })
  assert.equal(unavailable.status, 503)
  const retried = await exchangeToken({
    wire: h2.wire,
    environmentId: second.environment.id,
    issuerPath: "/oauth",
    clientId: clientId2,
    grant: { type: "authorization_code", code: outcome2.code, verifier: pkce2.verifier, redirectUri: webCallback },
  })
  assert.equal(retried.status, 200, "the once fault must clear after a single failure")
})

test("wrong-resource fault produces an audience rejection at the MCP endpoint", async () => {
  const h = harness()
  const { environment } = await dcrEnvironment(h, "wrong-resource")
  const environmentId = environment.id
  const clientId = await registeredClient(h, environmentId)
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
  assert.equal(token.status, 200)
  const accessToken = token.json<{ access_token: string }>().access_token
  const mcp = await h.wire.request(labPath(environmentId, "/mcp"), {
    method: "POST",
    headers: mcpHeaders(accessToken),
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "1" } } }),
  })
  assert.equal(mcp.status, 401)
})

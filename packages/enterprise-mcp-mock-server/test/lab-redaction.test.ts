import assert from "node:assert/strict"
import test from "node:test"
import { createMcpLabEngine, getLabScenarioPreset, InMemoryMcpLabStore } from "../src/index.js"
import {
  authorizeWithConsent,
  deterministicRuntime,
  exchangeToken,
  fetchWire,
  initializeStableSession,
  labPath,
  callStableRpc,
  pkcePair,
  registerDynamicClient,
} from "./lab-wire.js"

const webCallback = "https://client.example/oauth/callback"

test("every trace stays free of codes, tokens, secrets, state, PKCE verifiers, and session ids", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const engine = createMcpLabEngine({ store, runtime })
  const wire = fetchWire(engine)

  const scenario = JSON.parse(JSON.stringify(getLabScenarioPreset("stable-manual-client").scenario)) as Record<string, any>
  scenario.authentication.registration = "dynamic"
  scenario.authentication.authorizationServers = [
    { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
  ]
  scenario.authentication.tokenEndpointAuthMethods = ["client_secret_post"]
  delete scenario.authentication.preRegisteredRedirectUris
  const created = await engine.createEnvironment(scenario, { enableAutomationConsent: true })
  const environmentId = created.environment.id
  const automationToken = created.secrets.automationConsentToken
  assert.ok(automationToken)

  const registration = await registerDynamicClient({
    wire,
    environmentId,
    issuerPath: "/oauth",
    redirectUris: [webCallback],
    tokenEndpointAuthMethod: "client_secret_post",
  })
  assert.equal(registration.status, 201, registration.text)
  const registrationBody = registration.json<{ client_id: string; client_secret: string }>()
  assert.ok(registrationBody.client_secret)

  const { verifier, challenge } = pkcePair()
  const oauthState = "super-secret-client-state-value-90210"
  const outcome = await authorizeWithConsent({
    wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    redirectUri: webCallback,
    scopes: ["mcp:tools"],
    challenge,
    state: oauthState,
    automationToken,
  })
  assert.ok(outcome.code)

  const token = await exchangeToken({
    wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    clientSecret: registrationBody.client_secret,
    secretTransport: "post",
    grant: { type: "authorization_code", code: outcome.code, verifier, redirectUri: webCallback },
  })
  assert.equal(token.status, 200, token.text)
  const tokenBody = token.json<{ access_token: string; refresh_token?: string }>()
  assert.ok(tokenBody.refresh_token)

  const session = await initializeStableSession(wire, environmentId, tokenBody.access_token, "2025-11-25")
  await callStableRpc(wire, environmentId, tokenBody.access_token, session, { id: 3, method: "tools/list", params: {} })
  const refreshed = await exchangeToken({
    wire,
    environmentId,
    issuerPath: "/oauth",
    clientId: registrationBody.client_id,
    clientSecret: registrationBody.client_secret,
    secretTransport: "post",
    grant: { type: "refresh_token", refreshToken: tokenBody.refresh_token },
  })
  assert.equal(refreshed.status, 200)
  await wire.request(labPath(environmentId, "/oauth/revoke"), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: registrationBody.client_id,
      client_secret: registrationBody.client_secret,
      token: tokenBody.access_token,
    }).toString(),
  })

  const trace = await engine.listTrace(environmentId)
  assert.ok(trace.length > 8, "the journey must produce phase-by-phase evidence")
  const serialized = JSON.stringify(trace)

  const forbiddenValues: ReadonlyArray<readonly [string, string]> = [
    ["authorization code", outcome.code],
    ["access token", tokenBody.access_token],
    ["refresh token", tokenBody.refresh_token],
    ["client secret", registrationBody.client_secret],
    ["OAuth state", oauthState],
    ["PKCE verifier", verifier],
    ["PKCE challenge", challenge],
    ["MCP session id", session.sessionId],
    ["automation consent token", automationToken],
  ]
  for (const [label, value] of forbiddenValues) {
    assert.ok(value.length > 8)
    assert.equal(serialized.includes(value), false, `trace must not contain the raw ${label}`)
  }

  for (const event of trace) {
    assert.equal(typeof event.summary, "string")
    for (const [key, value] of Object.entries(event.details)) {
      if (/(authorization|token|secret|password|code|verifier|session|cookie)/i.test(key)) {
        assert.equal(value, "[REDACTED]", `sensitive detail key '${key}' must be redacted`)
      }
    }
  }
})

test("trace events cap per environment and stay isolated", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const engine = createMcpLabEngine({ store, runtime })
  const wire = fetchWire(engine)
  const created = await engine.createEnvironment(
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>,
  )
  const other = await engine.createEnvironment(
    JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>,
  )
  for (let index = 0; index < 30; index += 1) {
    await wire.request(`/.well-known/oauth-protected-resource${labPath(created.environment.id, "/mcp")}`)
  }
  const trace = await engine.listTrace(created.environment.id)
  const otherTrace = await engine.listTrace(other.environment.id)
  assert.ok(trace.length >= 30)
  assert.equal(otherTrace.length, 0)
})

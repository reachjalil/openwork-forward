import assert from "node:assert/strict"
import test from "node:test"
import { getLabScenarioPreset, labScenarioV2Schema, listLabScenarioPresets } from "../src/index.js"

function baseScenario(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(getLabScenarioPreset("stable-healthy-dcr").scenario)) as Record<string, unknown>
}

function withPatch(patch: (scenario: Record<string, any>) => void): Record<string, unknown> {
  const scenario = baseScenario() as Record<string, any>
  patch(scenario)
  return scenario
}

test("all fifteen required presets parse and stay frozen", () => {
  const presets = listLabScenarioPresets()
  assert.equal(presets.length, 15)
  const ids = new Set(presets.map((preset) => preset.presetId))
  assert.equal(ids.size, 15)
  for (const preset of presets) {
    assert.equal(preset.scenario.schemaVersion, 2)
    assert.ok(Object.isFrozen(preset.scenario))
    assert.ok(Object.isFrozen(preset.scenario.authentication))
  }
})

test("preset semantics match their purposes", () => {
  assert.equal(getLabScenarioPreset("stable-healthy-cimd").scenario.authentication.registration, "client_metadata")
  assert.equal(
    getLabScenarioPreset("stable-healthy-cimd").scenario.authentication.authorizationServers[0]?.registrationEndpointEnabled,
    false,
  )
  assert.equal(getLabScenarioPreset("refresh-rotation").scenario.authentication.refresh.rotate, true)
  assert.equal(getLabScenarioPreset("refresh-omission").scenario.authentication.refresh.omitReplacementOnRefresh, true)
  assert.equal(getLabScenarioPreset("multiple-issuers").scenario.authentication.authorizationServers.length, 2)
  assert.equal(getLabScenarioPreset("oidc-only-discovery").scenario.authentication.discovery, "oidc")
  assert.equal(getLabScenarioPreset("draft-stateless").scenario.protocol.mode, "stateless-draft")
  assert.deepEqual(getLabScenarioPreset("stable-downgrade").scenario.protocol.versions, ["2025-06-18", "2025-03-26"])
  assert.deepEqual(getLabScenarioPreset("session-expiry").scenario.fault, { id: "mcp-session-expired", occurrence: "once" })
  assert.deepEqual(getLabScenarioPreset("incremental-scope").scenario.authentication.optionalScopes, ["mcp:admin"])
})

test("draft versions cannot be used with the stable engine and vice versa", () => {
  assert.throws(() => labScenarioV2Schema.parse(withPatch((scenario) => (scenario.protocol.versions = ["DRAFT-2026-v1"]))))
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.protocol.mode = "stateless-draft"
        scenario.protocol.versions = ["2025-11-25"]
      }),
    ),
  )
})

test("the draft engine only accepts JSON responses", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.protocol.mode = "stateless-draft"
        scenario.protocol.versions = ["DRAFT-2026-v1"]
        scenario.protocol.responseMode = "sse"
      }),
    ),
  )
})

test("refresh configuration contradictions are rejected", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.refresh = { advertised: true, issueRefreshToken: false, rotate: true, omitReplacementOnRefresh: false }
      }),
    ),
  )
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.refresh = { advertised: true, issueRefreshToken: true, rotate: true, omitReplacementOnRefresh: true }
      }),
    ),
  )
})

test("registration modes must match advertised authorization-server capabilities", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.registration = "dynamic"
        scenario.authentication.authorizationServers = [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: false },
        ]
      }),
    ),
  )
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.registration = "client_metadata"
        scenario.authentication.authorizationServers = [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
        ]
      }),
    ),
  )
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.registration = "none_available"
      }),
    ),
  )
})

test("pre-registered scenarios require a manual redirect URI", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.registration = "pre_registered"
        scenario.authentication.authorizationServers = [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: false },
        ]
        delete scenario.authentication.preRegisteredRedirectUris
      }),
    ),
  )
})

test("nth faults require the request number and one fault at most is active", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(withPatch((scenario) => (scenario.fault = { id: "token-invalid-grant", occurrence: "nth" }))),
  )
  const parsed = labScenarioV2Schema.parse(
    withPatch((scenario) => (scenario.fault = { id: "token-invalid-grant", occurrence: "nth", nth: 3 })),
  )
  assert.equal(parsed.fault?.nth, 3)
  assert.throws(() =>
    labScenarioV2Schema.parse(withPatch((scenario) => (scenario.fault = { id: "mcp-session-expired", occurrence: "always", nth: 2 }))),
  )
})

test("session-expiry faults require the stable session engine", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.protocol.mode = "stateless-draft"
        scenario.protocol.versions = ["DRAFT-2026-v1"]
        scenario.fault = { id: "mcp-session-expired", occurrence: "once" }
      }),
    ),
  )
})

test("issuer paths must be unique and scopes must not overlap", () => {
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.authorizationServers = [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
        ]
      }),
    ),
  )
  assert.throws(() =>
    labScenarioV2Schema.parse(
      withPatch((scenario) => {
        scenario.authentication.optionalScopes = ["mcp:tools"]
      }),
    ),
  )
})

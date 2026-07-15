import assert from "node:assert/strict"
import test from "node:test"
import {
  getLabScenarioPreset,
  InMemoryMcpLabStore,
  LabEnvironmentRevisionConflictError,
  type LabEnvironment,
} from "../src/index.js"
import { deterministicRuntime } from "./lab-wire.js"

function environmentFixture(id: string, nowMs: number): LabEnvironment {
  return {
    id,
    createdAtMs: nowMs,
    expiresAtMs: nowMs + 3_600_000,
    revision: 1,
    status: "active",
    scenario: getLabScenarioPreset("stable-healthy-dcr").scenario,
    manualClient: null,
    manualBearer: null,
    automation: { enabled: false, consentTokenHash: null },
  }
}

test("authorization codes are single-use and expire", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-code-test", runtime.now()))
  await store.saveAuthorizationCode("env-code-test", {
    codeHash: "sha256:code",
    clientIdHash: "sha256:client",
    issuerPath: "/oauth",
    redirectUri: "https://example.invalid/cb",
    codeChallenge: "challenge",
    resource: "https://lab.test/lab/env-code-test/mcp",
    scopes: ["mcp:tools"],
    subject: "synthetic",
    expiresAtMs: runtime.now() + 60_000,
  })
  const first = await store.consumeAuthorizationCode("env-code-test", "sha256:code", runtime.now())
  assert.ok(first)
  const replay = await store.consumeAuthorizationCode("env-code-test", "sha256:code", runtime.now())
  assert.equal(replay, null)

  await store.saveAuthorizationCode("env-code-test", { ...first, codeHash: "sha256:code2" })
  const expired = await store.consumeAuthorizationCode("env-code-test", "sha256:code2", runtime.now() + 120_000)
  assert.equal(expired, null)
})

test("refresh rotation marks tokens and replay revokes the family", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-refresh-test", runtime.now()))
  const record = {
    tokenHash: "sha256:refresh",
    familyId: "family-1",
    clientIdHash: "sha256:client",
    issuerPath: "/oauth",
    resource: "https://lab.test/lab/env-refresh-test/mcp",
    scopes: ["mcp:tools"],
    subject: "synthetic",
    expiresAtMs: runtime.now() + 3_600_000,
    status: "active" as const,
  }
  await store.saveRefreshToken("env-refresh-test", record)
  await store.saveAccessToken("env-refresh-test", {
    tokenHash: "sha256:access",
    familyId: "family-1",
    clientIdHash: "sha256:client",
    issuerPath: "/oauth",
    resource: record.resource,
    scopes: record.scopes,
    subject: record.subject,
    expiresAtMs: runtime.now() + 900_000,
  })

  const nonRotating = await store.rotateRefreshToken("env-refresh-test", "sha256:refresh", { rotate: false, nowMs: runtime.now() })
  assert.equal(nonRotating.kind, "valid")

  const rotated = await store.rotateRefreshToken("env-refresh-test", "sha256:refresh", { rotate: true, nowMs: runtime.now() })
  assert.equal(rotated.kind, "rotated")

  const replayed = await store.rotateRefreshToken("env-refresh-test", "sha256:refresh", { rotate: true, nowMs: runtime.now() })
  assert.equal(replayed.kind, "replayed")
  assert.equal(await store.validateAccessToken("env-refresh-test", "sha256:access", runtime.now()), null)

  const unknown = await store.rotateRefreshToken("env-refresh-test", "sha256:absent", { rotate: true, nowMs: runtime.now() })
  assert.equal(unknown.kind, "not_found")
})

test("expired refresh tokens rotate to expired", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-refresh-expiry", runtime.now()))
  await store.saveRefreshToken("env-refresh-expiry", {
    tokenHash: "sha256:refresh",
    familyId: "family-1",
    clientIdHash: "sha256:client",
    issuerPath: "/oauth",
    resource: "https://lab.test/lab/env-refresh-expiry/mcp",
    scopes: ["mcp:tools"],
    subject: "synthetic",
    expiresAtMs: runtime.now() + 1_000,
    status: "active",
  })
  const expired = await store.rotateRefreshToken("env-refresh-expiry", "sha256:refresh", { rotate: true, nowMs: runtime.now() + 5_000 })
  assert.equal(expired.kind, "expired")
})

test("environment updates enforce optimistic revisions and clear connection state", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-revision", runtime.now()))
  await store.saveClient("env-revision", {
    clientIdHash: "sha256:client",
    clientId: "client-1",
    issuerPath: "/oauth",
    source: "dynamic",
    applicationType: "web",
    redirectUris: ["https://example.invalid/cb"],
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    tokenEndpointAuthMethod: "none",
    clientSecretHash: null,
    scopes: null,
    clientName: null,
    createdAtMs: runtime.now(),
    expiresAtMs: null,
  })

  await assert.rejects(
    store.updateEnvironment("env-revision", 99, { status: "stopped" }),
    LabEnvironmentRevisionConflictError,
  )
  const updated = await store.updateEnvironment("env-revision", 1, {
    scenario: getLabScenarioPreset("refresh-rotation").scenario,
  })
  assert.equal(updated.revision, 2)
  assert.equal(await store.getClient("env-revision", "sha256:client"), null)
})

test("environments and their artifacts are isolated", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-isolation-a", runtime.now()))
  await store.createEnvironment(environmentFixture("env-isolation-b", runtime.now()))
  await store.saveAccessToken("env-isolation-a", {
    tokenHash: "sha256:token",
    familyId: "family-a",
    clientIdHash: "sha256:client",
    issuerPath: "/oauth",
    resource: "https://lab.test/lab/env-isolation-a/mcp",
    scopes: ["mcp:tools"],
    subject: "synthetic",
    expiresAtMs: runtime.now() + 900_000,
  })
  assert.ok(await store.validateAccessToken("env-isolation-a", "sha256:token", runtime.now()))
  assert.equal(await store.validateAccessToken("env-isolation-b", "sha256:token", runtime.now()), null)

  await store.appendTrace("env-isolation-a", {
    id: "event-1",
    occurredAt: new Date(runtime.now()).toISOString(),
    correlationId: "corr-1",
    revision: 1,
    phase: "CONFIGURATION",
    direction: "internal",
    kind: "lifecycle",
    outcome: "completed",
    summary: "isolated event",
    details: {},
  })
  assert.equal((await store.listTrace("env-isolation-a")).length, 1)
  assert.equal((await store.listTrace("env-isolation-b")).length, 0)

  await store.deleteEnvironment("env-isolation-a")
  assert.equal(await store.getEnvironment("env-isolation-a"), null)
  assert.equal(await store.validateAccessToken("env-isolation-a", "sha256:token", runtime.now()), null)
})

test("expired environments are dropped when new ones are created", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  const shortLived: LabEnvironment = { ...environmentFixture("env-short", runtime.now()), expiresAtMs: runtime.now() + 1_000 }
  await store.createEnvironment(shortLived)
  runtime.advance(10_000)
  await store.createEnvironment(environmentFixture("env-later", runtime.now()))
  assert.equal(await store.getEnvironment("env-short"), null)
})

test("fault counters increment atomically per key", async () => {
  const runtime = deterministicRuntime()
  const store = new InMemoryMcpLabStore()
  await store.createEnvironment(environmentFixture("env-counter", runtime.now()))
  assert.equal(await store.incrementCounter("env-counter", "fault:1:token-invalid-grant"), 1)
  assert.equal(await store.incrementCounter("env-counter", "fault:1:token-invalid-grant"), 2)
  assert.equal(await store.incrementCounter("env-counter", "fault:1:other"), 1)
})

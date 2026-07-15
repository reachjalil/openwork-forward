import type { LabEnvironment } from "./contracts/environment.js"
import { labScenarioV2Schema, type McpLabScenarioV2 } from "./contracts/scenario.js"
import type { McpLabStore } from "./store/contract.js"
import type { LabTraceEvent } from "./contracts/environment.js"
import { labIdentityFor, type ResolvedLabIssuer } from "./identity.js"
import { createLabFaultEvaluator } from "./faults/evaluator.js"
import { createLabTracer, defaultLabRuntimeEnvironment, sha256Hex, type LabRuntimeEnvironment } from "./trace.js"
import { labJson, type LabHttpRequest, type LabHttpResponse } from "./http.js"
import {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  handleAuthorize,
  handleConsent,
  handleRegister,
  handleRevoke,
  handleToken,
  type LabAuthorityContext,
} from "./oauth/authority.js"
import { createDefaultCimdFetcher, defaultCimdPolicy, type CimdFetcher, type CimdPolicy } from "./oauth/cimd.js"
import { handleStableMcpRequest } from "./mcp/stable-engine.js"
import { handleDraftMcpRequest } from "./mcp/draft-engine.js"
import type { LabMcpContext } from "./mcp/shared.js"

export class LabReleaseCandidateDisabledError extends Error {
  constructor() {
    super(
      "This scenario uses the DRAFT-2026-v1 release candidate; create the engine with allowReleaseCandidate: true to opt in explicitly",
    )
    this.name = "LabReleaseCandidateDisabledError"
  }
}

export interface CreateMcpLabEngineOptions {
  readonly store: McpLabStore
  readonly runtime?: LabRuntimeEnvironment
  readonly cimdFetcher?: CimdFetcher
  readonly cimdPolicy?: Partial<CimdPolicy>
  /** Explicit opt-in for DRAFT-2026-v1 environments. Never enable in production defaults. */
  readonly allowReleaseCandidate?: boolean
  /** Overrides the emitted origin when the deployment sits behind a proxy. */
  readonly publicOrigin?: string
}

export interface CreateLabEnvironmentOptions {
  readonly environmentId?: string
  /** Enables signed automated consent for this environment (integration tests). */
  readonly enableAutomationConsent?: boolean
}

export interface CreatedLabEnvironment {
  readonly environment: LabEnvironment
  /**
   * Raw secrets for one-time display. Only hashes are stored; these values
   * cannot be recovered later.
   */
  readonly secrets: {
    readonly manualClientSecret: string | null
    readonly manualBearerToken: string | null
    readonly automationConsentToken: string | null
  }
}

export interface McpLabEngine {
  handle(request: LabHttpRequest): Promise<LabHttpResponse>
  createEnvironment(scenarioValue: unknown, options?: CreateLabEnvironmentOptions): Promise<CreatedLabEnvironment>
  getEnvironment(id: string): Promise<LabEnvironment | null>
  /** Replaces the scenario (optimistic revision check) and clears connection state. */
  updateEnvironmentScenario(id: string, expectedRevision: number, scenarioValue: unknown): Promise<LabEnvironment>
  stopEnvironment(id: string, expectedRevision: number): Promise<LabEnvironment>
  deleteEnvironment(id: string): Promise<void>
  listTrace(id: string): Promise<readonly LabTraceEvent[]>
  readonly store: McpLabStore
}

interface RouteMatch {
  readonly environmentId: string
  readonly kind:
    | { readonly route: "protected-resource-metadata" }
    | { readonly route: "authorization-server-metadata"; readonly issuerPath: string; readonly flavor: "rfc8414" | "oidc" }
    | { readonly route: "authority"; readonly issuerPath: string; readonly endpoint: string }
    | { readonly route: "mcp" }
    | { readonly route: "health" }
}

const environmentIdPattern = /^[A-Za-z0-9_-]{8,128}$/
const issuerSegmentPattern = /^[a-z][a-z0-9-]*$/
const authorityEndpoints = new Set(["authorize", "consent", "token", "register", "revoke", "jwks"])

function matchRoute(pathname: string): RouteMatch | null {
  const wellKnownPrefixes: ReadonlyArray<{ prefix: string; flavor: "rfc8414" | "oidc" | "prm" }> = [
    { prefix: "/.well-known/oauth-protected-resource/lab/", flavor: "prm" },
    { prefix: "/.well-known/oauth-authorization-server/lab/", flavor: "rfc8414" },
    { prefix: "/.well-known/openid-configuration/lab/", flavor: "oidc" },
  ]
  for (const { prefix, flavor } of wellKnownPrefixes) {
    if (!pathname.startsWith(prefix)) continue
    const rest = pathname.slice(prefix.length).split("/")
    if (flavor === "prm") {
      if (rest.length === 2 && environmentIdPattern.test(rest[0] ?? "") && rest[1] === "mcp") {
        return { environmentId: rest[0] ?? "", kind: { route: "protected-resource-metadata" } }
      }
      return null
    }
    if (rest.length === 2 && environmentIdPattern.test(rest[0] ?? "") && issuerSegmentPattern.test(rest[1] ?? "")) {
      return {
        environmentId: rest[0] ?? "",
        kind: { route: "authorization-server-metadata", issuerPath: `/${rest[1]}`, flavor },
      }
    }
    return null
  }

  if (!pathname.startsWith("/lab/")) return null
  const segments = pathname.slice("/lab/".length).split("/")
  const environmentId = segments[0] ?? ""
  if (!environmentIdPattern.test(environmentId)) return null
  const rest = segments.slice(1)
  if (rest.length === 1 && rest[0] === "mcp") return { environmentId, kind: { route: "mcp" } }
  if (rest.length === 1 && rest[0] === "health") return { environmentId, kind: { route: "health" } }
  if (rest.length === 3 && issuerSegmentPattern.test(rest[0] ?? "") && rest[1] === ".well-known" && rest[2] === "openid-configuration") {
    return {
      environmentId,
      kind: { route: "authorization-server-metadata", issuerPath: `/${rest[0]}`, flavor: "oidc" },
    }
  }
  if (rest.length === 2 && issuerSegmentPattern.test(rest[0] ?? "") && authorityEndpoints.has(rest[1] ?? "")) {
    return { environmentId, kind: { route: "authority", issuerPath: `/${rest[0]}`, endpoint: rest[1] ?? "" } }
  }
  return null
}

export function createMcpLabEngine(options: CreateMcpLabEngineOptions): McpLabEngine {
  const store = options.store
  const runtime = options.runtime ?? defaultLabRuntimeEnvironment()
  const cimdFetcher = options.cimdFetcher ?? createDefaultCimdFetcher()
  const cimdPolicy: CimdPolicy = { ...defaultCimdPolicy, ...options.cimdPolicy }
  const allowReleaseCandidate = options.allowReleaseCandidate ?? false

  async function resolveEnvironment(id: string): Promise<{ environment: LabEnvironment } | { response: LabHttpResponse }> {
    const environment = await store.getEnvironment(id)
    if (!environment) return { response: labJson(404, { error: "lab_environment_not_found" }) }
    if (environment.expiresAtMs < runtime.now()) {
      await store.deleteEnvironment(id)
      return { response: labJson(404, { error: "lab_environment_expired" }) }
    }
    if (environment.status === "stopped") {
      return { response: labJson(410, { error: "lab_environment_stopped" }) }
    }
    return { environment }
  }

  function issuerFor(environment: LabEnvironment, origin: string, issuerPath: string): ResolvedLabIssuer | null {
    const identity = labIdentityFor(origin, environment)
    return identity.issuers.find((issuer) => issuer.path === issuerPath) ?? null
  }

  async function handle(request: LabHttpRequest): Promise<LabHttpResponse> {
    const origin = options.publicOrigin ?? request.url.origin
    const match = matchRoute(request.url.pathname)
    if (!match) return labJson(404, { error: "not_found" })
    const resolved = await resolveEnvironment(match.environmentId)
    if ("response" in resolved) return resolved.response
    const environment = resolved.environment
    const scenario = environment.scenario
    const identity = labIdentityFor(origin, environment)
    const correlationId = runtime.randomId()
    const tracer = createLabTracer(store, environment.id, environment.revision, runtime)
    const faults = createLabFaultEvaluator(store, environment)

    const kind = match.kind
    if (kind.route === "health") {
      return labJson(200, {
        status: "ok",
        environmentId: environment.id,
        revision: environment.revision,
        profileId: scenario.profileId,
        protocolMode: scenario.protocol.mode,
        expiresAt: new Date(environment.expiresAtMs).toISOString(),
      })
    }

    if (kind.route === "protected-resource-metadata") {
      if (request.method !== "GET") return labJson(405, { error: "method_not_allowed" }, { allow: "GET" })
      if (scenario.authentication.mode !== "oauth") return labJson(404, { error: "not_found" })
      await tracer.emit({
        correlationId,
        phase: "AUTH_RESOURCE_DISCOVERY",
        direction: "outbound",
        kind: "response",
        outcome: "passed",
        summary: "Served protected-resource metadata",
        details: { authorizationServerCount: identity.issuers.length },
      })
      return labJson(200, buildProtectedResourceMetadata(identity, scenario))
    }

    if (kind.route === "authorization-server-metadata") {
      if (request.method !== "GET") return labJson(405, { error: "method_not_allowed" }, { allow: "GET" })
      if (scenario.authentication.mode !== "oauth") return labJson(404, { error: "not_found" })
      const discovery = scenario.authentication.discovery
      const flavorAllowed =
        kind.flavor === "rfc8414" ? discovery === "rfc8414" || discovery === "rfc8414_then_oidc" : discovery === "oidc" || discovery === "rfc8414_then_oidc"
      const issuer = issuerFor(environment, origin, kind.issuerPath)
      if (!issuer || !flavorAllowed) return labJson(404, { error: "not_found" })
      await tracer.emit({
        correlationId,
        phase: "AUTH_ISSUER_DISCOVERY",
        direction: "outbound",
        kind: "response",
        outcome: "passed",
        summary: `Served ${kind.flavor === "rfc8414" ? "RFC 8414" : "OIDC"} authorization-server metadata`,
        details: { issuerPath: kind.issuerPath },
      })
      return labJson(200, buildAuthorizationServerMetadata(identity, issuer, scenario, kind.flavor))
    }

    if (kind.route === "authority") {
      if (scenario.authentication.mode !== "oauth") return labJson(404, { error: "not_found" })
      const issuer = issuerFor(environment, origin, kind.issuerPath)
      if (!issuer) return labJson(404, { error: "not_found" })
      if (kind.endpoint === "jwks") {
        if (request.method !== "GET") return labJson(405, { error: "method_not_allowed" }, { allow: "GET" })
        return labJson(200, { keys: [] })
      }
      const authorityContext: LabAuthorityContext = {
        environment,
        identity,
        issuer,
        store,
        runtime,
        tracer,
        faults,
        cimd: { fetcher: cimdFetcher, policy: cimdPolicy },
        correlationId,
      }
      if (kind.endpoint === "authorize") {
        if (request.method !== "GET") return labJson(405, { error: "method_not_allowed" }, { allow: "GET" })
        return handleAuthorize(authorityContext, request)
      }
      if (request.method !== "POST") return labJson(405, { error: "method_not_allowed" }, { allow: "POST" })
      if (kind.endpoint === "consent") return handleConsent(authorityContext, request)
      if (kind.endpoint === "token") return handleToken(authorityContext, request)
      if (kind.endpoint === "register") return handleRegister(authorityContext, request)
      return handleRevoke(authorityContext, request)
    }

    // MCP resource endpoint
    const mcpContext: LabMcpContext = { environment, identity, store, runtime, tracer, faults, correlationId }
    if (scenario.protocol.mode === "stable-session") {
      return handleStableMcpRequest(mcpContext, request)
    }
    if (scenario.protocol.mode === "stateless-draft") {
      return handleDraftMcpRequest(mcpContext, request, { releaseCandidateEnabled: allowReleaseCandidate })
    }
    return labJson(501, {
      error: "legacy_sse_not_hosted",
      error_description:
        "The 2024-11-05 HTTP+SSE transport requires a long-lived connection and runs only in the local/container Node mock, never on serverless hosting",
    })
  }

  async function createEnvironment(scenarioValue: unknown, createOptions: CreateLabEnvironmentOptions = {}): Promise<CreatedLabEnvironment> {
    const scenario: McpLabScenarioV2 = labScenarioV2Schema.parse(scenarioValue)
    if (scenario.protocol.mode === "stateless-draft" && !allowReleaseCandidate) {
      throw new LabReleaseCandidateDisabledError()
    }
    const nowMs = runtime.now()
    const environmentId = createOptions.environmentId ?? runtime.opaqueValue("labenv").replaceAll(".", "-")
    if (!environmentIdPattern.test(environmentId)) {
      throw new Error("Lab environment ids must be 8-128 URL-safe characters")
    }

    const authentication = scenario.authentication
    const manualClientSecretNeeded =
      authentication.mode === "oauth" &&
      authentication.registration === "pre_registered" &&
      authentication.tokenEndpointAuthMethods.some((method) => method !== "none")
    const manualClientNeeded = authentication.mode === "oauth" && authentication.registration === "pre_registered"
    const manualClientId = manualClientNeeded ? runtime.opaqueValue("lab-manual-client") : null
    const manualClientSecret = manualClientSecretNeeded ? runtime.opaqueValue("lab-manual-secret") : null
    const manualBearerToken = authentication.mode === "manual_bearer" ? runtime.opaqueValue("lab-manual-bearer") : null
    const automationConsentToken = createOptions.enableAutomationConsent ? runtime.opaqueValue("lab-consent-automation") : null
    const manualClientAuthMethod = manualClientSecretNeeded
      ? (authentication.tokenEndpointAuthMethods.find((method) => method !== "none") ?? "none")
      : "none"

    const environment: LabEnvironment = {
      id: environmentId,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + scenario.lifetimeSeconds * 1_000,
      revision: 1,
      status: "active",
      scenario,
      manualClient:
        manualClientNeeded && manualClientId
          ? {
              clientId: manualClientId,
              clientSecretHash: manualClientSecret ? sha256Hex(manualClientSecret) : null,
              tokenEndpointAuthMethod: manualClientAuthMethod,
              redirectUris: authentication.preRegisteredRedirectUris ?? [],
            }
          : null,
      manualBearer: manualBearerToken ? { tokenHash: sha256Hex(manualBearerToken) } : null,
      automation: { enabled: automationConsentToken !== null, consentTokenHash: automationConsentToken ? sha256Hex(automationConsentToken) : null },
    }
    await store.createEnvironment(environment)
    if (environment.manualClient && manualClientId) {
      const firstIssuer = authentication.authorizationServers[0]
      await store.saveClient(environment.id, {
        clientIdHash: sha256Hex(manualClientId),
        clientId: manualClientId,
        issuerPath: firstIssuer?.issuerPath ?? "/oauth",
        source: "manual",
        applicationType: authentication.applicationTypes[0] ?? "web",
        redirectUris: environment.manualClient.redirectUris,
        grantTypes: ["authorization_code", ...(authentication.refresh.advertised ? ["refresh_token"] : [])],
        responseTypes: ["code"],
        tokenEndpointAuthMethod: environment.manualClient.tokenEndpointAuthMethod,
        clientSecretHash: environment.manualClient.clientSecretHash,
        scopes: null,
        clientName: "Pre-registered lab client",
        createdAtMs: nowMs,
        expiresAtMs: null,
      })
    }
    return {
      environment,
      secrets: { manualClientSecret, manualBearerToken, automationConsentToken },
    }
  }

  return {
    handle,
    createEnvironment,
    getEnvironment: (id) => store.getEnvironment(id),
    updateEnvironmentScenario: async (id, expectedRevision, scenarioValue) => {
      const scenario = labScenarioV2Schema.parse(scenarioValue)
      if (scenario.protocol.mode === "stateless-draft" && !allowReleaseCandidate) {
        throw new LabReleaseCandidateDisabledError()
      }
      return store.updateEnvironment(id, expectedRevision, { scenario })
    },
    stopEnvironment: (id, expectedRevision) => store.updateEnvironment(id, expectedRevision, { status: "stopped" }),
    deleteEnvironment: (id) => store.deleteEnvironment(id),
    listTrace: (id) => store.listTrace(id),
    store,
  }
}

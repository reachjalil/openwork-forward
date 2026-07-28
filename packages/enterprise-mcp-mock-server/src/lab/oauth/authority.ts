import { createHash, timingSafeEqual } from "node:crypto"
import { z } from "zod"
import type {
  LabApplicationType,
  LabEnvironment,
  LabOAuthClientRecord,
  LabTokenEndpointAuthMethod,
} from "../contracts/environment.js"
import type { McpLabScenarioV2 } from "../contracts/scenario.js"
import type { McpLabStore } from "../store/contract.js"
import type { LabIdentity, ResolvedLabIssuer } from "../identity.js"
import type { LabFaultEvaluator } from "../faults/evaluator.js"
import type { LabRuntimeEnvironment, LabTracer } from "../trace.js"
import { sha256Hex } from "../trace.js"
import {
  labJson,
  labOAuthError,
  labRedirect,
  readLabForm,
  readLabJson,
  LabHttpInputError,
  type LabHttpRequest,
  type LabHttpResponse,
} from "../http.js"
import { renderConsentError, renderConsentScreen } from "./consent.js"
import { validateLabRedirectUri } from "./redirects.js"
import { resolveClientMetadataDocument, type CimdFetcher, type CimdPolicy } from "./cimd.js"

export interface LabAuthorityContext {
  readonly environment: LabEnvironment
  readonly identity: LabIdentity
  readonly issuer: ResolvedLabIssuer
  readonly store: McpLabStore
  readonly runtime: LabRuntimeEnvironment
  readonly tracer: LabTracer
  readonly faults: LabFaultEvaluator
  readonly cimd: { readonly fetcher: CimdFetcher; readonly policy: CimdPolicy }
  readonly correlationId: string
}

export const labSyntheticSubject = "synthetic-lab-user@example.invalid"
export const labAccessTokenLifetimeSeconds = 900
export const labAuthorizationCodeLifetimeSeconds = 60
export const labPendingAuthorizationLifetimeSeconds = 300
const labRefreshTokenLifetimeMs = 30 * 24 * 60 * 60 * 1000

const pkceVerifierPattern = /^[A-Za-z0-9._~-]{43,128}$/
const pkceS256ChallengePattern = /^[A-Za-z0-9_-]{43}$/

function pkceChallengeFromVerifier(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url")
}

function hashesEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)
  return (
    leftBuffer.byteLength === rightBuffer.byteLength &&
    timingSafeEqual(Uint8Array.from(leftBuffer), Uint8Array.from(rightBuffer))
  )
}

function secretMatches(rawSecret: string, storedHash: string | null): boolean {
  if (!storedHash) return false
  return hashesEqual(sha256Hex(rawSecret), storedHash)
}

// ---------------------------------------------------------------------------
// Metadata documents
// ---------------------------------------------------------------------------

export function buildProtectedResourceMetadata(identity: LabIdentity, scenario: McpLabScenarioV2): Record<string, unknown> {
  return {
    resource: identity.mcpUrl,
    authorization_servers: identity.issuers.map((issuer) => issuer.issuerUrl),
    scopes_supported: [...scenario.authentication.requiredScopes, ...scenario.authentication.optionalScopes],
    bearer_methods_supported: ["header"],
    resource_name: "OpenWork Diagnostics synthetic MCP lab resource",
  }
}

export function buildAuthorizationServerMetadata(
  identity: LabIdentity,
  issuer: ResolvedLabIssuer,
  scenario: McpLabScenarioV2,
  flavor: "rfc8414" | "oidc",
): Record<string, unknown> {
  const authentication = scenario.authentication
  const registrationEnabled = authentication.registration === "dynamic" && issuer.registrationEndpointEnabled
  const metadata: Record<string, unknown> = {
    issuer: issuer.issuerUrl,
    authorization_endpoint: issuer.authorizationEndpoint,
    token_endpoint: issuer.tokenEndpoint,
    revocation_endpoint: issuer.revocationEndpoint,
    ...(registrationEnabled ? { registration_endpoint: issuer.registrationEndpoint } : {}),
    ...(issuer.clientIdMetadataDocumentSupported ? { client_id_metadata_document_supported: true } : {}),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", ...(authentication.refresh.advertised ? ["refresh_token"] : [])],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: authentication.tokenEndpointAuthMethods,
    scopes_supported: [...authentication.requiredScopes, ...authentication.optionalScopes],
    authorization_response_iss_parameter_supported: authentication.authorizationResponseIssuer !== "missing",
  }
  if (flavor === "oidc") {
    metadata.jwks_uri = `${issuer.issuerUrl}/jwks`
    metadata.subject_types_supported = ["public"]
    metadata.id_token_signing_alg_values_supported = ["none"]
  }
  return metadata
}

// ---------------------------------------------------------------------------
// Client resolution
// ---------------------------------------------------------------------------

type ResolvedClient =
  | { readonly ok: true; readonly client: LabOAuthClientRecord; readonly viaClientMetadata: boolean }
  | { readonly ok: false; readonly error: "invalid_client" | "invalid_client_metadata"; readonly description: string }

function looksLikeClientMetadataUrl(clientId: string): boolean {
  return clientId.startsWith("https://") || clientId.startsWith("http://")
}

async function resolveClient(context: LabAuthorityContext, clientId: string): Promise<ResolvedClient> {
  const { environment, issuer, store, runtime } = context
  if (looksLikeClientMetadataUrl(clientId)) {
    if (!issuer.clientIdMetadataDocumentSupported) {
      return {
        ok: false,
        error: "invalid_client",
        description: "This authorization server does not accept client ID metadata documents",
      }
    }
    const resolution = await resolveClientMetadataDocument({
      clientIdUrl: clientId,
      fetcher: context.cimd.fetcher,
      policy: context.cimd.policy,
      store,
      environmentId: environment.id,
      nowMs: runtime.now(),
    })
    if (!resolution.ok) {
      await context.tracer.emit({
        correlationId: context.correlationId,
        phase: "AUTH_CLIENT_REGISTRATION",
        direction: "outbound",
        kind: "security",
        outcome: "failed",
        summary: "Rejected a client ID metadata document",
        details: { reason: resolution.reason },
      })
      return { ok: false, error: resolution.error, description: resolution.reason }
    }
    const document = resolution.document
    return {
      ok: true,
      viaClientMetadata: true,
      client: {
        clientIdHash: sha256Hex(clientId),
        clientId,
        issuerPath: issuer.path,
        source: "client_metadata",
        applicationType: "web",
        redirectUris: document.redirectUris,
        grantTypes: document.grantTypes,
        responseTypes: document.responseTypes,
        tokenEndpointAuthMethod: document.tokenEndpointAuthMethod,
        clientSecretHash: null,
        scopes: document.scopes,
        clientName: document.clientName,
        createdAtMs: runtime.now(),
        expiresAtMs: null,
      },
    }
  }

  const record = await store.getClient(environment.id, sha256Hex(clientId))
  if (!record) return { ok: false, error: "invalid_client", description: "Unknown OAuth client for this lab environment" }
  if (record.expiresAtMs !== null && record.expiresAtMs < runtime.now()) {
    return { ok: false, error: "invalid_client", description: "The client registration has expired" }
  }
  if (record.issuerPath !== context.issuer.path) {
    return {
      ok: false,
      error: "invalid_client",
      description: "The client registration is bound to a different authorization server issuer",
    }
  }
  return { ok: true, client: record, viaClientMetadata: false }
}

// ---------------------------------------------------------------------------
// Authorization endpoint + consent
// ---------------------------------------------------------------------------

function authorizationResponseIssuerValue(context: LabAuthorityContext): string | null {
  const behavior = context.environment.scenario.authentication.authorizationResponseIssuer
  if (behavior === "missing") return null
  if (behavior === "mismatched") return `${context.identity.origin}${context.identity.basePath}/mismatched-issuer`
  return context.issuer.issuerUrl
}

function errorRedirect(
  context: LabAuthorityContext,
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): LabHttpResponse {
  const destination = new URL(redirectUri)
  destination.searchParams.set("error", error)
  destination.searchParams.set("error_description", description)
  if (state !== null) destination.searchParams.set("state", state)
  const issValue = authorizationResponseIssuerValue(context)
  if (issValue !== null) destination.searchParams.set("iss", issValue)
  return labRedirect(destination.href)
}

export async function handleAuthorize(context: LabAuthorityContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, identity, runtime, store, tracer, correlationId } = context
  const scenario = environment.scenario
  const parameters = request.url.searchParams
  await tracer.emit({
    correlationId,
    phase: "AUTH_USER_OR_WORKLOAD",
    direction: "inbound",
    kind: "request",
    outcome: "started",
    summary: "Synthetic authorization requested",
    details: { issuerPath: context.issuer.path },
  })

  const clientId = parameters.get("client_id") ?? ""
  if (!clientId) return renderConsentError(400, "Invalid authorization request", "client_id is required.")
  const resolved = await resolveClient(context, clientId)
  if (!resolved.ok) {
    return renderConsentError(400, "Unknown client", resolved.description)
  }
  const redirectUri = parameters.get("redirect_uri") ?? ""
  if (!redirectUri || !resolved.client.redirectUris.includes(redirectUri)) {
    await tracer.emit({
      correlationId,
      phase: "AUTH_USER_OR_WORKLOAD",
      direction: "inbound",
      kind: "security",
      outcome: "failed",
      summary: "Rejected an authorization request with an unregistered redirect URI",
      details: { redirectHost: safeHost(redirectUri) },
    })
    return renderConsentError(400, "Invalid redirect", "redirect_uri must exactly match a registered redirect URI.")
  }

  const state = parameters.get("state")
  if (parameters.get("response_type") !== "code") {
    return errorRedirect(context, redirectUri, "unsupported_response_type", "Only the authorization code flow is supported", state)
  }
  const codeChallenge = parameters.get("code_challenge") ?? ""
  const codeChallengeMethod = parameters.get("code_challenge_method") ?? ""
  if (codeChallengeMethod !== "S256" || !pkceS256ChallengePattern.test(codeChallenge)) {
    return errorRedirect(context, redirectUri, "invalid_request", "PKCE with code_challenge_method=S256 is required", state)
  }
  const resource = parameters.get("resource") ?? ""
  if (!resource) {
    return errorRedirect(context, redirectUri, "invalid_target", "The resource parameter is required", state)
  }
  if (resource !== identity.mcpUrl) {
    return errorRedirect(context, redirectUri, "invalid_target", "The requested resource is not served by this lab environment", state)
  }
  const requestedScopes = (parameters.get("scope") ?? "").split(" ").filter(Boolean)
  const allowedScopes = new Set([...scenario.authentication.requiredScopes, ...scenario.authentication.optionalScopes])
  if (
    requestedScopes.length === 0 ||
    requestedScopes.some((scope) => !allowedScopes.has(scope)) ||
    scenario.authentication.requiredScopes.some((scope) => !requestedScopes.includes(scope))
  ) {
    return errorRedirect(
      context,
      redirectUri,
      "invalid_scope",
      "Scopes must include every required scope and stay within the scopes this environment supports",
      state,
    )
  }
  if (resolved.client.scopes && requestedScopes.some((scope) => !resolved.client.scopes?.includes(scope))) {
    return errorRedirect(context, redirectUri, "invalid_scope", "The client registration does not allow one of the requested scopes", state)
  }

  const requestId = runtime.opaqueValue("lab-consent-request")
  await store.savePendingAuthorization(environment.id, {
    requestId,
    clientIdHash: resolved.client.clientIdHash,
    clientDisplayName: resolved.client.clientName ?? resolved.client.clientId,
    issuerPath: context.issuer.path,
    redirectUri,
    codeChallenge,
    resource,
    scopes: requestedScopes,
    expiresAtMs: runtime.now() + labPendingAuthorizationLifetimeSeconds * 1_000,
  })
  await tracer.emit({
    correlationId,
    phase: "AUTH_USER_OR_WORKLOAD",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Rendered the synthetic consent screen",
    details: { scopeCount: requestedScopes.length, redirectHost: safeHost(redirectUri) },
  })
  return renderConsentScreen({
    consentEndpoint: context.issuer.consentEndpoint,
    requestId,
    clientDisplayName: resolved.client.clientName ?? resolved.client.clientId,
    callbackHostname: safeHost(redirectUri),
    resource,
    scopes: requestedScopes,
    state,
  })
}

function safeHost(value: string): string {
  try {
    const url = new URL(value)
    return url.host || url.protocol
  } catch {
    return "invalid"
  }
}

export async function handleConsent(context: LabAuthorityContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, runtime, store, tracer, correlationId } = context
  let form: URLSearchParams
  try {
    form = readLabForm(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) return labJson(error.status, { error: "invalid_request", error_description: error.message })
    throw error
  }
  const automationToken = form.get("automation_token")
  if (automationToken !== null) {
    const automation = environment.automation
    if (!automation.enabled || !automation.consentTokenHash || !secretMatches(automationToken, automation.consentTokenHash)) {
      await tracer.emit({
        correlationId,
        phase: "AUTH_USER_OR_WORKLOAD",
        direction: "inbound",
        kind: "security",
        outcome: "failed",
        summary: "Rejected an unsigned automated consent attempt",
      })
      return labJson(403, { error: "invalid_automation_token", error_description: "Automated consent requires this environment's signed automation token" })
    }
  }

  const requestId = form.get("request_id") ?? ""
  const pending = requestId ? await store.consumePendingAuthorization(environment.id, requestId, runtime.now()) : null
  if (!pending || pending.issuerPath !== context.issuer.path) {
    return renderConsentError(400, "Consent request expired", "This authorization request is unknown, already used, or expired. Restart the flow from your client.")
  }
  const state = form.get("state")
  const decision = form.get("decision") ?? ""
  if (decision === "deny") {
    await tracer.emit({
      correlationId,
      phase: "AUTH_USER_OR_WORKLOAD",
      direction: "outbound",
      kind: "response",
      outcome: "failed",
      summary: "Synthetic consent denied",
    })
    return errorRedirect(context, pending.redirectUri, "access_denied", "The synthetic user denied the authorization request", state)
  }
  if (decision !== "approve") {
    return renderConsentError(400, "Invalid consent decision", "The consent decision must be approve or deny.")
  }

  const code = runtime.opaqueValue("lab-authorization-code")
  await store.saveAuthorizationCode(environment.id, {
    codeHash: sha256Hex(code),
    clientIdHash: pending.clientIdHash,
    issuerPath: pending.issuerPath,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    resource: pending.resource,
    scopes: pending.scopes,
    subject: labSyntheticSubject,
    expiresAtMs: runtime.now() + labAuthorizationCodeLifetimeSeconds * 1_000,
  })
  const destination = new URL(pending.redirectUri)
  destination.searchParams.set("code", code)
  if (state !== null) destination.searchParams.set("state", state)
  const issValue = authorizationResponseIssuerValue(context)
  if (issValue !== null) destination.searchParams.set("iss", issValue)
  await tracer.emit({
    correlationId,
    phase: "AUTH_USER_OR_WORKLOAD",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Synthetic consent approved and a single-use authorization code was issued",
    details: { automated: automationToken !== null, redirectHost: safeHost(pending.redirectUri), scopeCount: pending.scopes.length },
  })
  return labRedirect(destination.href)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

interface PresentedClientAuthentication {
  readonly clientId: string
  readonly method: LabTokenEndpointAuthMethod
  readonly secret: string | null
}

function presentedClientAuthentication(
  request: LabHttpRequest,
  form: URLSearchParams,
): PresentedClientAuthentication | { readonly failure: string } {
  const authorization = request.headers.authorization
  if (authorization && /^Basic /i.test(authorization)) {
    let decoded: string
    try {
      decoded = Buffer.from(authorization.slice(6).trim(), "base64").toString("utf8")
    } catch {
      return { failure: "The Basic authorization header is not valid base64" }
    }
    const separator = decoded.indexOf(":")
    if (separator < 1) return { failure: "The Basic authorization header is malformed" }
    const decodePart = (part: string): string => {
      try {
        return decodeURIComponent(part)
      } catch {
        return part
      }
    }
    return {
      clientId: decodePart(decoded.slice(0, separator)),
      method: "client_secret_basic",
      secret: decodePart(decoded.slice(separator + 1)),
    }
  }
  const clientId = form.get("client_id") ?? ""
  if (!clientId) return { failure: "client_id is required" }
  const secret = form.get("client_secret")
  if (secret !== null && secret.length > 0) return { clientId, method: "client_secret_post", secret }
  return { clientId, method: "none", secret: null }
}

async function authenticateTokenClient(
  context: LabAuthorityContext,
  request: LabHttpRequest,
  form: URLSearchParams,
): Promise<{ readonly ok: true; readonly client: LabOAuthClientRecord } | { readonly ok: false; readonly response: LabHttpResponse }> {
  const presented = presentedClientAuthentication(request, form)
  if ("failure" in presented) {
    return { ok: false, response: labOAuthError(401, "invalid_client", presented.failure) }
  }
  const resolved = await resolveClient(context, presented.clientId)
  if (!resolved.ok) {
    return { ok: false, response: labOAuthError(401, resolved.error === "invalid_client_metadata" ? "invalid_client" : "invalid_client", resolved.description) }
  }
  const client = resolved.client
  if (presented.method !== client.tokenEndpointAuthMethod) {
    return {
      ok: false,
      response: labOAuthError(
        401,
        "invalid_client",
        `This client must authenticate with token_endpoint_auth_method '${client.tokenEndpointAuthMethod}'`,
      ),
    }
  }
  if (client.tokenEndpointAuthMethod !== "none") {
    if (!presented.secret || !secretMatches(presented.secret, client.clientSecretHash)) {
      await context.tracer.emit({
        correlationId: context.correlationId,
        phase: "AUTH_TOKEN_ACQUISITION",
        direction: "inbound",
        kind: "security",
        outcome: "failed",
        summary: "Rejected client authentication at the token endpoint",
      })
      return { ok: false, response: labOAuthError(401, "invalid_client", "Client authentication failed") }
    }
  }
  return { ok: true, client }
}

function refreshTokenAllowed(scenario: McpLabScenarioV2, scopes: readonly string[]): boolean {
  const refresh = scenario.authentication.refresh
  if (!refresh.issueRefreshToken) return false
  const offlineAccessDeclared = [...scenario.authentication.requiredScopes, ...scenario.authentication.optionalScopes].includes("offline_access")
  return offlineAccessDeclared ? scopes.includes("offline_access") : true
}

interface IssuedTokens {
  readonly accessToken: string
  readonly refreshToken: string | null
  readonly familyId: string
}

async function issueTokens(
  context: LabAuthorityContext,
  input: {
    readonly clientIdHash: string
    readonly scopes: readonly string[]
    readonly resource: string
    readonly subject: string
    readonly familyId?: string
    readonly includeRefreshToken: boolean
  },
): Promise<IssuedTokens> {
  const { environment, runtime, store } = context
  const nowMs = runtime.now()
  const boundResource = (await context.faults.shouldApply("wrong-resource-audience"))
    ? `${input.resource}/wrong-audience`
    : input.resource
  const familyId = input.familyId ?? runtime.opaqueValue("lab-token-family")
  const accessToken = runtime.opaqueValue("lab-access-token")
  await store.saveAccessToken(environment.id, {
    tokenHash: sha256Hex(accessToken),
    familyId,
    clientIdHash: input.clientIdHash,
    issuerPath: context.issuer.path,
    resource: boundResource,
    scopes: input.scopes,
    subject: input.subject,
    expiresAtMs: Math.min(nowMs + labAccessTokenLifetimeSeconds * 1_000, environment.expiresAtMs),
  })
  let refreshToken: string | null = null
  if (input.includeRefreshToken) {
    refreshToken = runtime.opaqueValue("lab-refresh-token")
    await store.saveRefreshToken(environment.id, {
      tokenHash: sha256Hex(refreshToken),
      familyId,
      clientIdHash: input.clientIdHash,
      issuerPath: context.issuer.path,
      resource: boundResource,
      scopes: input.scopes,
      subject: input.subject,
      expiresAtMs: Math.min(nowMs + labRefreshTokenLifetimeMs, environment.expiresAtMs),
      status: "active",
    })
  }
  return { accessToken, refreshToken, familyId }
}

function tokenSuccessResponse(
  tokens: IssuedTokens,
  scopes: readonly string[],
  options: { readonly includeRefreshField: boolean; readonly refreshFieldValue?: string | null },
): LabHttpResponse {
  return labJson(
    200,
    {
      access_token: tokens.accessToken,
      token_type: "Bearer",
      expires_in: labAccessTokenLifetimeSeconds,
      scope: scopes.join(" "),
      ...(options.includeRefreshField && (options.refreshFieldValue ?? tokens.refreshToken)
        ? { refresh_token: options.refreshFieldValue ?? tokens.refreshToken }
        : {}),
    },
    { pragma: "no-cache" },
  )
}

export async function handleToken(context: LabAuthorityContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, identity, runtime, store, tracer, correlationId } = context
  const scenario = environment.scenario
  await tracer.emit({
    correlationId,
    phase: "AUTH_TOKEN_ACQUISITION",
    direction: "inbound",
    kind: "request",
    outcome: "started",
    summary: "OAuth token exchange requested",
    details: { issuerPath: context.issuer.path },
  })
  if (await context.faults.shouldApply("authorization-server-unavailable")) {
    await emitFault(context, "Returned HTTP 503 from the synthetic authorization server")
    return labJson(503, { error: "temporarily_unavailable", error_description: "The synthetic authorization server is unavailable" }, { "retry-after": "3" })
  }

  let form: URLSearchParams
  try {
    form = readLabForm(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) return labOAuthError(error.status === 415 ? 415 : 400, "invalid_request", error.message)
    throw error
  }
  const authenticated = await authenticateTokenClient(context, request, form)
  if (!authenticated.ok) return authenticated.response
  const client = authenticated.client

  const grantType = form.get("grant_type") ?? ""
  if (grantType === "authorization_code") {
    const code = form.get("code") ?? ""
    const verifier = form.get("code_verifier") ?? ""
    const redirectUri = form.get("redirect_uri") ?? ""
    const resource = form.get("resource") ?? ""
    if (await context.faults.shouldApply("token-invalid-grant")) {
      await emitFault(context, "Rejected the authorization grant with invalid_grant")
      return labOAuthError(400, "invalid_grant", "The authorization grant was rejected; restart authorization from the client")
    }
    if (!code) return labOAuthError(400, "invalid_request", "code is required")
    if (!resource) return labOAuthError(400, "invalid_target", "The resource parameter is required in the token request")
    const record = await store.consumeAuthorizationCode(environment.id, sha256Hex(code), runtime.now())
    const verifierValid = pkceVerifierPattern.test(verifier) && record !== null && hashesEqual(record.codeChallenge, pkceChallengeFromVerifier(verifier))
    const bindingValid =
      record !== null &&
      record.clientIdHash === client.clientIdHash &&
      record.issuerPath === context.issuer.path &&
      record.redirectUri === redirectUri &&
      record.resource === resource &&
      record.resource === identity.mcpUrl
    if (!record || !bindingValid || !verifierValid) {
      await tracer.emit({
        correlationId,
        phase: "AUTH_TOKEN_ACQUISITION",
        direction: "outbound",
        kind: "security",
        outcome: "failed",
        summary: "Rejected an authorization-code exchange (replay, binding, or PKCE mismatch)",
      })
      return labOAuthError(400, "invalid_grant", "The authorization code, its bindings, or the PKCE verifier were rejected")
    }
    const includeRefreshToken = refreshTokenAllowed(scenario, record.scopes)
    const tokens = await issueTokens(context, {
      clientIdHash: client.clientIdHash,
      scopes: record.scopes,
      resource: record.resource,
      subject: record.subject,
      includeRefreshToken,
    })
    await tracer.emit({
      correlationId,
      phase: "AUTH_TOKEN_ACQUISITION",
      direction: "outbound",
      kind: "response",
      outcome: "passed",
      summary: "Issued bounded synthetic OAuth tokens",
      details: { scopeCount: record.scopes.length, refreshIssued: includeRefreshToken },
    })
    return tokenSuccessResponse(tokens, record.scopes, { includeRefreshField: includeRefreshToken })
  }

  if (grantType === "refresh_token") {
    if (!scenario.authentication.refresh.issueRefreshToken) {
      return labOAuthError(400, "unsupported_grant_type", "This environment does not issue refresh tokens")
    }
    if (await context.faults.shouldApply("token-invalid-grant")) {
      await emitFault(context, "Rejected the refresh grant with invalid_grant")
      return labOAuthError(400, "invalid_grant", "The refresh grant was rejected; restart authorization from the client")
    }
    const rawRefreshToken = form.get("refresh_token") ?? ""
    if (!rawRefreshToken) return labOAuthError(400, "invalid_request", "refresh_token is required")
    const resourceParameter = form.get("resource")
    const rotate = scenario.authentication.refresh.rotate
    const rotation = await store.rotateRefreshToken(environment.id, sha256Hex(rawRefreshToken), {
      rotate,
      nowMs: runtime.now(),
    })
    if (rotation.kind === "replayed") {
      await tracer.emit({
        correlationId,
        phase: "CONTINUITY_REFRESH",
        direction: "outbound",
        kind: "security",
        outcome: "failed",
        summary: "Detected refresh-token reuse and revoked the token family",
      })
      return labOAuthError(400, "invalid_grant", "Refresh token reuse detected; the token family has been revoked")
    }
    if (rotation.kind !== "valid" && rotation.kind !== "rotated") {
      return labOAuthError(400, "invalid_grant", "The refresh token is unknown or expired")
    }
    const record = rotation.record
    if (record.clientIdHash !== client.clientIdHash || record.issuerPath !== context.issuer.path) {
      return labOAuthError(400, "invalid_grant", "The refresh token is bound to a different client or issuer")
    }
    if (resourceParameter !== null && resourceParameter !== record.resource) {
      return labOAuthError(400, "invalid_target", "The refresh request names a different resource than the token family")
    }
    const tokens = await issueTokens(context, {
      clientIdHash: client.clientIdHash,
      scopes: record.scopes,
      resource: record.resource,
      subject: record.subject,
      familyId: record.familyId,
      includeRefreshToken: rotation.kind === "rotated",
    })
    const omit = scenario.authentication.refresh.omitReplacementOnRefresh
    await tracer.emit({
      correlationId,
      phase: "CONTINUITY_REFRESH",
      direction: "outbound",
      kind: "response",
      outcome: "passed",
      summary:
        rotation.kind === "rotated"
          ? "Refreshed access and rotated the refresh token family"
          : omit
            ? "Refreshed access and deliberately omitted a replacement refresh token"
            : "Refreshed access and preserved the existing refresh token",
      details: { rotated: rotation.kind === "rotated", replacementOmitted: omit },
    })
    if (rotation.kind === "rotated") {
      return tokenSuccessResponse(tokens, record.scopes, { includeRefreshField: true })
    }
    return tokenSuccessResponse(tokens, record.scopes, {
      includeRefreshField: !omit,
      refreshFieldValue: omit ? null : rawRefreshToken,
    })
  }

  return labOAuthError(
    400,
    "unsupported_grant_type",
    "Only authorization_code and refresh_token are supported; this lab has no client-credentials shortcut",
  )
}

async function emitFault(context: LabAuthorityContext, summary: string): Promise<void> {
  const faultId = context.faults.activeFaultId
  if (!faultId) return
  await context.tracer.emit({
    correlationId: context.correlationId,
    phase: "AUTH_TOKEN_ACQUISITION",
    direction: "outbound",
    kind: "fault",
    outcome: "applied",
    summary,
    details: { faultId },
  })
}

// ---------------------------------------------------------------------------
// Dynamic client registration
// ---------------------------------------------------------------------------

const registrationRequestSchema = z.object({
  application_type: z.enum(["web", "native"]).optional(),
  redirect_uris: z.array(z.string().min(1).max(2_048)).min(1).max(10),
  grant_types: z.array(z.string().min(1).max(64)).min(1).max(4).optional(),
  response_types: z.array(z.string().min(1).max(64)).min(1).max(2).optional(),
  token_endpoint_auth_method: z.string().min(1).max(64).optional(),
  scope: z.string().max(1_024).optional(),
  client_name: z.string().min(1).max(200).optional(),
})

export async function handleRegister(context: LabAuthorityContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, issuer, runtime, store, tracer, correlationId } = context
  const scenario = environment.scenario
  await tracer.emit({
    correlationId,
    phase: "AUTH_CLIENT_REGISTRATION",
    direction: "inbound",
    kind: "request",
    outcome: "started",
    summary: "Dynamic client registration requested",
    details: { issuerPath: issuer.path },
  })
  if (scenario.authentication.registration !== "dynamic" || !issuer.registrationEndpointEnabled) {
    return labJson(404, { error: "registration_not_supported" })
  }

  let body: unknown
  try {
    body = readLabJson(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) return labJson(error.status, { error: "invalid_client_metadata", error_description: error.message })
    throw error
  }
  const parsed = registrationRequestSchema.safeParse(body)
  if (!parsed.success) {
    return labJson(400, {
      error: "invalid_client_metadata",
      error_description: parsed.error.issues[0]?.message ?? "The registration request is malformed",
    })
  }
  const registration = parsed.data
  const applicationType: LabApplicationType = registration.application_type ?? "web"
  if (!scenario.authentication.applicationTypes.includes(applicationType)) {
    return labJson(400, {
      error: "invalid_client_metadata",
      error_description: `application_type '${applicationType}' is not enabled for this environment`,
    })
  }
  for (const redirectUri of registration.redirect_uris) {
    const verdict = validateLabRedirectUri(redirectUri, applicationType)
    if (!verdict.ok) {
      return labJson(400, {
        error: "invalid_redirect_uri",
        error_description: `Redirect URI is not valid for application_type '${applicationType}': ${verdict.reason}`,
      })
    }
  }
  const grantTypes = registration.grant_types ?? ["authorization_code"]
  if (!grantTypes.includes("authorization_code")) {
    return labJson(400, { error: "invalid_client_metadata", error_description: "grant_types must include authorization_code" })
  }
  for (const grantType of grantTypes) {
    if (grantType !== "authorization_code" && grantType !== "refresh_token") {
      return labJson(400, { error: "invalid_client_metadata", error_description: `grant_type '${grantType}' is not supported` })
    }
  }
  if (grantTypes.includes("refresh_token") && !scenario.authentication.refresh.advertised) {
    return labJson(400, { error: "invalid_client_metadata", error_description: "This environment does not advertise the refresh_token grant" })
  }
  const responseTypes = registration.response_types ?? ["code"]
  if (responseTypes.length !== 1 || responseTypes[0] !== "code") {
    return labJson(400, { error: "invalid_client_metadata", error_description: "response_types must be exactly [\"code\"]" })
  }
  const tokenEndpointAuthMethod = (registration.token_endpoint_auth_method ?? "client_secret_basic") as LabTokenEndpointAuthMethod
  if (!scenario.authentication.tokenEndpointAuthMethods.includes(tokenEndpointAuthMethod)) {
    return labJson(400, {
      error: "invalid_client_metadata",
      error_description: `token_endpoint_auth_method '${registration.token_endpoint_auth_method ?? "client_secret_basic"}' is not enabled for this environment`,
    })
  }
  const allowedScopes = new Set([...scenario.authentication.requiredScopes, ...scenario.authentication.optionalScopes])
  const registeredScopes = registration.scope === undefined ? null : registration.scope.split(" ").filter(Boolean)
  if (registeredScopes && registeredScopes.some((scope) => !allowedScopes.has(scope))) {
    return labJson(400, { error: "invalid_client_metadata", error_description: "scope requests a scope this environment does not support" })
  }

  const nowMs = runtime.now()
  const clientId = runtime.opaqueValue("lab-client")
  const needsSecret = tokenEndpointAuthMethod === "client_secret_post" || tokenEndpointAuthMethod === "client_secret_basic"
  const clientSecret = needsSecret ? runtime.opaqueValue("lab-client-secret") : null
  const lifetimeSeconds = scenario.authentication.registrationLifetimeSeconds ?? scenario.lifetimeSeconds
  const expiresAtMs = Math.min(nowMs + lifetimeSeconds * 1_000, environment.expiresAtMs)
  await store.saveClient(environment.id, {
    clientIdHash: sha256Hex(clientId),
    clientId,
    issuerPath: issuer.path,
    source: "dynamic",
    applicationType,
    redirectUris: registration.redirect_uris,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    clientSecretHash: clientSecret ? sha256Hex(clientSecret) : null,
    scopes: registeredScopes,
    clientName: registration.client_name ?? null,
    createdAtMs: nowMs,
    expiresAtMs,
  })
  await tracer.emit({
    correlationId,
    phase: "AUTH_CLIENT_REGISTRATION",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Registered a synthetic OAuth client bound to this issuer and environment",
    details: {
      clientIdHash: sha256Hex(clientId),
      applicationType,
      redirectCount: registration.redirect_uris.length,
      issuerPath: issuer.path,
    },
  })
  return labJson(201, {
    client_id: clientId,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
    client_id_issued_at: Math.floor(nowMs / 1_000),
    client_secret_expires_at: needsSecret ? Math.floor(expiresAtMs / 1_000) : 0,
    application_type: applicationType,
    redirect_uris: registration.redirect_uris,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    ...(registeredScopes ? { scope: registeredScopes.join(" ") } : {}),
    ...(registration.client_name ? { client_name: registration.client_name } : {}),
  })
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

export async function handleRevoke(context: LabAuthorityContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, runtime, store, tracer, correlationId } = context
  let form: URLSearchParams
  try {
    form = readLabForm(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) return labOAuthError(error.status === 415 ? 415 : 400, "invalid_request", error.message)
    throw error
  }
  const authenticated = await authenticateTokenClient(context, request, form)
  if (!authenticated.ok) return authenticated.response
  const token = form.get("token") ?? ""
  if (!token) return labOAuthError(400, "invalid_request", "token is required")

  const tokenHash = sha256Hex(token)
  const nowMs = runtime.now()
  const accessToken = await store.validateAccessToken(environment.id, tokenHash, nowMs)
  const rotation = accessToken ? null : await store.rotateRefreshToken(environment.id, tokenHash, { rotate: false, nowMs })
  const record = accessToken ?? (rotation && rotation.kind === "valid" ? rotation.record : null)
  // RFC 7009: unknown, expired, or foreign tokens still return HTTP 200.
  if (record && record.clientIdHash === authenticated.client.clientIdHash) {
    await store.revokeTokenFamily(environment.id, record.familyId)
    await tracer.emit({
      correlationId,
      phase: "SHUTDOWN",
      direction: "internal",
      kind: "lifecycle",
      outcome: "completed",
      summary: "Revoked a synthetic token family",
    })
  }
  return labEmptyOk()
}

function labEmptyOk(): LabHttpResponse {
  return { status: 200, headers: { "cache-control": "no-store" }, body: "" }
}

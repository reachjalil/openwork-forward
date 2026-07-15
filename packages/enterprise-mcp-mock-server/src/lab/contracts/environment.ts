import type { SafeTraceEvent } from "../../contracts/runtime.js"
import type { McpLabScenarioV2 } from "./scenario.js"

/**
 * Durable lab records.
 *
 * Every secret-bearing artifact is stored by hash only: the store never holds
 * a raw client secret, authorization code, access token, refresh token,
 * session identifier, consent form token, or manual bearer token. Raw values
 * exist only inside a single HTTP exchange (issuance response or lookup key).
 */

export type LabTokenEndpointAuthMethod = "none" | "client_secret_post" | "client_secret_basic"
export type LabApplicationType = "web" | "native"
export type LabClientSource = "manual" | "dynamic" | "client_metadata"

export interface LabOAuthClientRecord {
  /** sha256 of the raw client_id; the store key. */
  readonly clientIdHash: string
  /** The public client identifier (not a secret) as shown to administrators. */
  readonly clientId: string
  /** Issuer path this registration is bound to; other issuers must reject it. */
  readonly issuerPath: string
  readonly source: LabClientSource
  readonly applicationType: LabApplicationType
  readonly redirectUris: readonly string[]
  readonly grantTypes: readonly string[]
  readonly responseTypes: readonly string[]
  readonly tokenEndpointAuthMethod: LabTokenEndpointAuthMethod
  readonly clientSecretHash: string | null
  readonly scopes: readonly string[] | null
  readonly clientName: string | null
  readonly createdAtMs: number
  readonly expiresAtMs: number | null
}

export interface LabAuthorizationCodeRecord {
  readonly codeHash: string
  readonly clientIdHash: string
  readonly issuerPath: string
  readonly redirectUri: string
  readonly codeChallenge: string
  readonly resource: string
  readonly scopes: readonly string[]
  readonly subject: string
  readonly expiresAtMs: number
}

export interface LabAccessTokenRecord {
  readonly tokenHash: string
  readonly familyId: string
  readonly clientIdHash: string
  readonly issuerPath: string
  readonly resource: string
  readonly scopes: readonly string[]
  readonly subject: string
  readonly expiresAtMs: number
}

export interface LabRefreshTokenRecord {
  readonly tokenHash: string
  readonly familyId: string
  readonly clientIdHash: string
  readonly issuerPath: string
  readonly resource: string
  readonly scopes: readonly string[]
  readonly subject: string
  readonly expiresAtMs: number
  readonly status: "active" | "rotated" | "revoked"
}

export interface LabSessionRecord {
  readonly sessionIdHash: string
  readonly tokenFamilyId: string | null
  readonly protocolVersion: string
  readonly scenarioRevision: number
  readonly expiresAtMs: number
  readonly initialized: boolean
}

/**
 * A pending authorization request awaiting synthetic consent. The client's
 * OAuth `state` is deliberately absent: it round-trips through the rendered
 * consent form so the authority never retains it.
 */
export interface LabPendingAuthorizationRecord {
  readonly requestId: string
  readonly clientIdHash: string
  readonly clientDisplayName: string
  readonly issuerPath: string
  readonly redirectUri: string
  readonly codeChallenge: string
  readonly resource: string
  readonly scopes: readonly string[]
  readonly expiresAtMs: number
}

export interface LabCimdDocumentRecord {
  readonly urlHash: string
  readonly document: {
    readonly clientId: string
    readonly clientName: string | null
    readonly redirectUris: readonly string[]
    readonly grantTypes: readonly string[]
    readonly responseTypes: readonly string[]
    readonly tokenEndpointAuthMethod: LabTokenEndpointAuthMethod
    readonly scopes: readonly string[] | null
  }
  readonly expiresAtMs: number
}

export interface LabEnvironment {
  /** Cryptographically random identifier; also the URL path segment. */
  readonly id: string
  readonly createdAtMs: number
  readonly expiresAtMs: number
  /** Optimistic concurrency revision covering scenario and status changes. */
  readonly revision: number
  readonly status: "active" | "stopped"
  readonly scenario: McpLabScenarioV2
  /** Present when the scenario uses pre-registered manual clients. */
  readonly manualClient: {
    readonly clientId: string
    readonly clientSecretHash: string | null
    readonly tokenEndpointAuthMethod: LabTokenEndpointAuthMethod
    readonly redirectUris: readonly string[]
  } | null
  /** Present when authentication.mode is manual_bearer. */
  readonly manualBearer: { readonly tokenHash: string } | null
  /**
   * Signed automated-test consent. When enabled, a consent decision may be
   * submitted programmatically by presenting the raw automation token whose
   * sha256 matches this hash. Interactive consent never requires it, and no
   * query parameter can ever trigger automatic approval.
   */
  readonly automation: { readonly enabled: boolean; readonly consentTokenHash: string | null }
}

export interface LabEnvironmentUpdate {
  readonly scenario?: McpLabScenarioV2
  readonly status?: "active" | "stopped"
  readonly expiresAtMs?: number
}

export type LabTraceEvent = SafeTraceEvent

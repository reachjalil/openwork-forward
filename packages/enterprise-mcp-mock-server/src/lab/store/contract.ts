import type {
  LabAccessTokenRecord,
  LabAuthorizationCodeRecord,
  LabCimdDocumentRecord,
  LabEnvironment,
  LabEnvironmentUpdate,
  LabOAuthClientRecord,
  LabPendingAuthorizationRecord,
  LabRefreshTokenRecord,
  LabSessionRecord,
  LabTraceEvent,
} from "../contracts/environment.js"

export class LabEnvironmentRevisionConflictError extends Error {
  constructor(
    readonly environmentId: string,
    readonly expectedRevision: number,
    readonly actualRevision: number,
  ) {
    super(`Lab environment '${environmentId}' revision conflict: expected ${expectedRevision}, found ${actualRevision}`)
    this.name = "LabEnvironmentRevisionConflictError"
  }
}

export class LabEnvironmentAlreadyExistsError extends Error {
  constructor(readonly environmentId: string) {
    super(`Lab environment '${environmentId}' already exists`)
    this.name = "LabEnvironmentAlreadyExistsError"
  }
}

export class LabEnvironmentNotFoundError extends Error {
  constructor(readonly environmentId: string) {
    super(`Lab environment '${environmentId}' does not exist`)
    this.name = "LabEnvironmentNotFoundError"
  }
}

export type LabRefreshRotationResult =
  | { readonly kind: "not_found" }
  | { readonly kind: "expired" }
  /** The token was already rotated or revoked; the whole family has now been revoked. */
  | { readonly kind: "replayed"; readonly familyId: string }
  /** Rotation disabled: the token stays active and valid. */
  | { readonly kind: "valid"; readonly record: LabRefreshTokenRecord }
  /** Rotation enabled: the token was atomically marked rotated; issue a replacement. */
  | { readonly kind: "rotated"; readonly record: LabRefreshTokenRecord }

/**
 * Asynchronous state port for the lab engine.
 *
 * The in-memory implementation backs local development, tests, and the Node
 * adapter. A Redis implementation backs hosted Diagnostics. Implementations
 * must make `consumeAuthorizationCode`, `rotateRefreshToken`,
 * `consumePendingAuthorization`, and `incrementCounter` atomic (single Lua
 * script or equivalent in Redis) so replay across concurrent serverless
 * invocations cannot double-spend a code, refresh token, or consent request.
 * Every environment-owned key must expire with its environment.
 */
export interface McpLabStore {
  getEnvironment(id: string): Promise<LabEnvironment | null>
  createEnvironment(environment: LabEnvironment): Promise<void>
  updateEnvironment(id: string, expectedRevision: number, update: LabEnvironmentUpdate): Promise<LabEnvironment>
  deleteEnvironment(id: string): Promise<void>

  getClient(environmentId: string, clientIdHash: string): Promise<LabOAuthClientRecord | null>
  saveClient(environmentId: string, client: LabOAuthClientRecord): Promise<void>

  savePendingAuthorization(environmentId: string, pending: LabPendingAuthorizationRecord): Promise<void>
  /** Atomic single-use consume; expired or unknown requests return null. */
  consumePendingAuthorization(environmentId: string, requestId: string, nowMs: number): Promise<LabPendingAuthorizationRecord | null>

  saveAuthorizationCode(environmentId: string, code: LabAuthorizationCodeRecord): Promise<void>
  /** Atomic single-use consume; expired or unknown codes return null. */
  consumeAuthorizationCode(environmentId: string, codeHash: string, nowMs: number): Promise<LabAuthorizationCodeRecord | null>

  saveAccessToken(environmentId: string, token: LabAccessTokenRecord): Promise<void>
  validateAccessToken(environmentId: string, tokenHash: string, nowMs: number): Promise<LabAccessTokenRecord | null>

  saveRefreshToken(environmentId: string, token: LabRefreshTokenRecord): Promise<void>
  rotateRefreshToken(
    environmentId: string,
    tokenHash: string,
    options: { readonly rotate: boolean; readonly nowMs: number },
  ): Promise<LabRefreshRotationResult>
  revokeTokenFamily(environmentId: string, familyId: string): Promise<void>

  saveSession(environmentId: string, session: LabSessionRecord): Promise<void>
  getSession(environmentId: string, sessionIdHash: string, nowMs: number): Promise<LabSessionRecord | null>
  deleteSession(environmentId: string, sessionIdHash: string): Promise<void>

  getCimdDocument(environmentId: string, urlHash: string, nowMs: number): Promise<LabCimdDocumentRecord | null>
  saveCimdDocument(environmentId: string, record: LabCimdDocumentRecord): Promise<void>

  /** Atomically increment and return the per-environment counter for fault occurrence tracking. */
  incrementCounter(environmentId: string, key: string): Promise<number>

  appendTrace(environmentId: string, event: LabTraceEvent): Promise<void>
  listTrace(environmentId: string): Promise<readonly LabTraceEvent[]>
}

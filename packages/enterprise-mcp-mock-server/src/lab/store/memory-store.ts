import { deepFreeze } from "../../immutability.js"
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
import {
  LabEnvironmentAlreadyExistsError,
  LabEnvironmentNotFoundError,
  LabEnvironmentRevisionConflictError,
  type LabRefreshRotationResult,
  type McpLabStore,
} from "./contract.js"

const maximumEnvironmentCount = 100
const maximumClientCount = 100
const maximumPendingAuthorizationCount = 100
const maximumAuthorizationCodeCount = 100
const maximumTokenCount = 200
const maximumSessionCount = 100
const maximumCimdDocumentCount = 20
const maximumCounterCount = 100
const maximumTraceEventCount = 500

interface EnvironmentBucket {
  environment: LabEnvironment
  readonly clients: Map<string, LabOAuthClientRecord>
  readonly pendingAuthorizations: Map<string, LabPendingAuthorizationRecord>
  readonly authorizationCodes: Map<string, LabAuthorizationCodeRecord>
  readonly accessTokens: Map<string, LabAccessTokenRecord>
  readonly refreshTokens: Map<string, LabRefreshTokenRecord>
  readonly sessions: Map<string, LabSessionRecord>
  readonly cimdDocuments: Map<string, LabCimdDocumentRecord>
  readonly counters: Map<string, number>
  readonly traceEvents: LabTraceEvent[]
}

function trimOldest<Key, Value>(map: Map<Key, Value>, maximum: number): void {
  while (map.size > maximum) {
    const oldestKey = map.keys().next().value
    if (oldestKey === undefined) return
    map.delete(oldestKey)
  }
}

/**
 * In-memory implementation of the lab store.
 *
 * Node's single-threaded execution makes each method atomic, matching the
 * semantics the Redis implementation must provide with Lua scripts. Bounds
 * mirror the v1 instance state so a runaway client cannot grow memory.
 */
export class InMemoryMcpLabStore implements McpLabStore {
  private readonly buckets = new Map<string, EnvironmentBucket>()

  async getEnvironment(id: string): Promise<LabEnvironment | null> {
    return this.buckets.get(id)?.environment ?? null
  }

  async createEnvironment(environment: LabEnvironment): Promise<void> {
    if (this.buckets.has(environment.id)) throw new LabEnvironmentAlreadyExistsError(environment.id)
    this.expireEnvironments(environment.createdAtMs)
    if (this.buckets.size >= maximumEnvironmentCount) {
      trimOldest(this.buckets, maximumEnvironmentCount - 1)
    }
    this.buckets.set(environment.id, {
      environment: deepFreeze(environment),
      clients: new Map(),
      pendingAuthorizations: new Map(),
      authorizationCodes: new Map(),
      accessTokens: new Map(),
      refreshTokens: new Map(),
      sessions: new Map(),
      cimdDocuments: new Map(),
      counters: new Map(),
      traceEvents: [],
    })
  }

  async updateEnvironment(id: string, expectedRevision: number, update: LabEnvironmentUpdate): Promise<LabEnvironment> {
    const bucket = this.buckets.get(id)
    if (!bucket) throw new LabEnvironmentNotFoundError(id)
    const current = bucket.environment
    if (current.revision !== expectedRevision) {
      throw new LabEnvironmentRevisionConflictError(id, expectedRevision, current.revision)
    }
    const next: LabEnvironment = deepFreeze({
      ...current,
      scenario: update.scenario ?? current.scenario,
      status: update.status ?? current.status,
      expiresAtMs: update.expiresAtMs ?? current.expiresAtMs,
      revision: current.revision + 1,
    })
    bucket.environment = next
    if (update.scenario) {
      // A scenario change invalidates connection state but keeps the trace.
      bucket.clients.clear()
      bucket.pendingAuthorizations.clear()
      bucket.authorizationCodes.clear()
      bucket.accessTokens.clear()
      bucket.refreshTokens.clear()
      bucket.sessions.clear()
      bucket.cimdDocuments.clear()
      bucket.counters.clear()
    }
    return next
  }

  async deleteEnvironment(id: string): Promise<void> {
    this.buckets.delete(id)
  }

  async getClient(environmentId: string, clientIdHash: string): Promise<LabOAuthClientRecord | null> {
    return this.bucket(environmentId)?.clients.get(clientIdHash) ?? null
  }

  async saveClient(environmentId: string, client: LabOAuthClientRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.clients.set(client.clientIdHash, deepFreeze(client))
    trimOldest(bucket.clients, maximumClientCount)
  }

  async savePendingAuthorization(environmentId: string, pending: LabPendingAuthorizationRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.pendingAuthorizations.set(pending.requestId, deepFreeze(pending))
    trimOldest(bucket.pendingAuthorizations, maximumPendingAuthorizationCount)
  }

  async consumePendingAuthorization(
    environmentId: string,
    requestId: string,
    nowMs: number,
  ): Promise<LabPendingAuthorizationRecord | null> {
    const bucket = this.bucket(environmentId)
    if (!bucket) return null
    const pending = bucket.pendingAuthorizations.get(requestId)
    if (!pending) return null
    bucket.pendingAuthorizations.delete(requestId)
    return pending.expiresAtMs < nowMs ? null : pending
  }

  async saveAuthorizationCode(environmentId: string, code: LabAuthorizationCodeRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.authorizationCodes.set(code.codeHash, deepFreeze(code))
    trimOldest(bucket.authorizationCodes, maximumAuthorizationCodeCount)
  }

  async consumeAuthorizationCode(
    environmentId: string,
    codeHash: string,
    nowMs: number,
  ): Promise<LabAuthorizationCodeRecord | null> {
    const bucket = this.bucket(environmentId)
    if (!bucket) return null
    const code = bucket.authorizationCodes.get(codeHash)
    if (!code) return null
    bucket.authorizationCodes.delete(codeHash)
    return code.expiresAtMs < nowMs ? null : code
  }

  async saveAccessToken(environmentId: string, token: LabAccessTokenRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.accessTokens.set(token.tokenHash, deepFreeze(token))
    trimOldest(bucket.accessTokens, maximumTokenCount)
  }

  async validateAccessToken(environmentId: string, tokenHash: string, nowMs: number): Promise<LabAccessTokenRecord | null> {
    const bucket = this.bucket(environmentId)
    const token = bucket?.accessTokens.get(tokenHash)
    if (!token) return null
    if (token.expiresAtMs < nowMs) {
      bucket?.accessTokens.delete(tokenHash)
      return null
    }
    return token
  }

  async saveRefreshToken(environmentId: string, token: LabRefreshTokenRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.refreshTokens.set(token.tokenHash, deepFreeze(token))
    trimOldest(bucket.refreshTokens, maximumTokenCount)
  }

  async rotateRefreshToken(
    environmentId: string,
    tokenHash: string,
    options: { readonly rotate: boolean; readonly nowMs: number },
  ): Promise<LabRefreshRotationResult> {
    const bucket = this.bucket(environmentId)
    const record = bucket?.refreshTokens.get(tokenHash)
    if (!bucket || !record) return { kind: "not_found" }
    if (record.status !== "active") {
      await this.revokeTokenFamily(environmentId, record.familyId)
      return { kind: "replayed", familyId: record.familyId }
    }
    if (record.expiresAtMs < options.nowMs) {
      bucket.refreshTokens.delete(tokenHash)
      return { kind: "expired" }
    }
    if (!options.rotate) return { kind: "valid", record }
    const rotated: LabRefreshTokenRecord = deepFreeze({ ...record, status: "rotated" as const })
    bucket.refreshTokens.set(tokenHash, rotated)
    return { kind: "rotated", record: rotated }
  }

  async revokeTokenFamily(environmentId: string, familyId: string): Promise<void> {
    const bucket = this.bucket(environmentId)
    if (!bucket) return
    for (const [tokenHash, record] of bucket.accessTokens) {
      if (record.familyId === familyId) bucket.accessTokens.delete(tokenHash)
    }
    for (const [tokenHash, record] of bucket.refreshTokens) {
      if (record.familyId === familyId && record.status !== "revoked") {
        bucket.refreshTokens.set(tokenHash, deepFreeze({ ...record, status: "revoked" as const }))
      }
    }
  }

  async saveSession(environmentId: string, session: LabSessionRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.sessions.set(session.sessionIdHash, deepFreeze(session))
    trimOldest(bucket.sessions, maximumSessionCount)
  }

  async getSession(environmentId: string, sessionIdHash: string, nowMs: number): Promise<LabSessionRecord | null> {
    const bucket = this.bucket(environmentId)
    const session = bucket?.sessions.get(sessionIdHash)
    if (!session) return null
    if (session.expiresAtMs < nowMs) {
      bucket?.sessions.delete(sessionIdHash)
      return null
    }
    return session
  }

  async deleteSession(environmentId: string, sessionIdHash: string): Promise<void> {
    this.bucket(environmentId)?.sessions.delete(sessionIdHash)
  }

  async getCimdDocument(environmentId: string, urlHash: string, nowMs: number): Promise<LabCimdDocumentRecord | null> {
    const bucket = this.bucket(environmentId)
    const record = bucket?.cimdDocuments.get(urlHash)
    if (!record) return null
    if (record.expiresAtMs < nowMs) {
      bucket?.cimdDocuments.delete(urlHash)
      return null
    }
    return record
  }

  async saveCimdDocument(environmentId: string, record: LabCimdDocumentRecord): Promise<void> {
    const bucket = this.requireBucket(environmentId)
    bucket.cimdDocuments.set(record.urlHash, deepFreeze(record))
    trimOldest(bucket.cimdDocuments, maximumCimdDocumentCount)
  }

  async incrementCounter(environmentId: string, key: string): Promise<number> {
    const bucket = this.requireBucket(environmentId)
    const next = (bucket.counters.get(key) ?? 0) + 1
    bucket.counters.set(key, next)
    trimOldest(bucket.counters, maximumCounterCount)
    return next
  }

  async appendTrace(environmentId: string, event: LabTraceEvent): Promise<void> {
    const bucket = this.bucket(environmentId)
    if (!bucket) return
    bucket.traceEvents.push(deepFreeze(event))
    if (bucket.traceEvents.length > maximumTraceEventCount) {
      bucket.traceEvents.splice(0, bucket.traceEvents.length - maximumTraceEventCount)
    }
  }

  async listTrace(environmentId: string): Promise<readonly LabTraceEvent[]> {
    return deepFreeze([...(this.bucket(environmentId)?.traceEvents ?? [])])
  }

  private bucket(environmentId: string): EnvironmentBucket | undefined {
    return this.buckets.get(environmentId)
  }

  private requireBucket(environmentId: string): EnvironmentBucket {
    const bucket = this.buckets.get(environmentId)
    if (!bucket) throw new LabEnvironmentNotFoundError(environmentId)
    return bucket
  }

  private expireEnvironments(nowMs: number): void {
    for (const [id, bucket] of this.buckets) {
      if (bucket.environment.expiresAtMs < nowMs) this.buckets.delete(id)
    }
  }
}

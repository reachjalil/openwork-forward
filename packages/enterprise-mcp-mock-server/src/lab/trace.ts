import { createHash, randomBytes, randomUUID } from "node:crypto"
import type { HandshakePhase } from "../contracts/phases.js"
import type { SafeTraceDetail, SafeTraceEvent } from "../contracts/runtime.js"
import { sanitizeTraceDetails } from "../observability/redaction.js"
import { deepFreeze } from "../immutability.js"
import type { McpLabStore } from "./store/contract.js"

/** Deterministic clock/randomness port so tests can replay exact timelines. */
export interface LabRuntimeEnvironment {
  now(): number
  randomId(): string
  opaqueValue(prefix: string): string
}

export function defaultLabRuntimeEnvironment(): LabRuntimeEnvironment {
  return {
    now: () => Date.now(),
    randomId: () => randomUUID(),
    opaqueValue: (prefix) => `${prefix}-${randomBytes(24).toString("base64url")}`,
  }
}

export function sha256Hex(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`
}

export interface LabTraceInput {
  readonly correlationId: string
  readonly phase: HandshakePhase
  readonly direction: SafeTraceEvent["direction"]
  readonly kind: SafeTraceEvent["kind"]
  readonly outcome: SafeTraceEvent["outcome"]
  readonly summary: string
  readonly details?: Readonly<Record<string, SafeTraceDetail>>
}

export interface LabTracer {
  emit(input: LabTraceInput): Promise<void>
}

/**
 * Emits redacted phase-by-phase evidence into the store. Callers never pass
 * raw codes, tokens, secrets, OAuth state, or PKCE material; the key-pattern
 * redaction is the second line of defense, not the contract.
 */
export function createLabTracer(
  store: McpLabStore,
  environmentId: string,
  revision: number,
  runtime: LabRuntimeEnvironment,
): LabTracer {
  return {
    async emit(input: LabTraceInput): Promise<void> {
      const event: SafeTraceEvent = deepFreeze({
        id: runtime.randomId(),
        occurredAt: new Date(runtime.now()).toISOString(),
        correlationId: input.correlationId,
        revision,
        phase: input.phase,
        direction: input.direction,
        kind: input.kind,
        outcome: input.outcome,
        summary: input.summary,
        details: sanitizeTraceDetails(input.details ?? {}, []),
      })
      await store.appendTrace(environmentId, event)
    },
  }
}

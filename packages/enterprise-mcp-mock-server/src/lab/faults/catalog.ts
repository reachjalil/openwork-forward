import { z } from "zod"
import { deepFreeze, type DeepReadonly } from "../../immutability.js"
import type { HandshakePhase } from "../../contracts/phases.js"

/**
 * Connection-breaking faults for scenario schema v2.
 *
 * Most v1 fault effects became first-class scenario configuration in v2
 * (issuer behavior, refresh behavior, discovery shape, registration shape).
 * Only faults that break an otherwise healthy connection remain here, and a
 * scenario carries at most one so the first failing phase stays deterministic.
 */

export const labFaultIdSchema = z.enum([
  "token-invalid-grant",
  "wrong-resource-audience",
  "access-token-expired",
  "mcp-session-expired",
  "authorization-server-unavailable",
])

export type LabFaultId = z.infer<typeof labFaultIdSchema>

export interface LabFaultDefinition {
  readonly id: LabFaultId
  readonly displayName: string
  readonly description: string
  readonly phase: HandshakePhase
  readonly category: string
  readonly requiresOAuth: boolean
  readonly requiresProtocolMode: "stable-session" | "stateless-draft" | "legacy-sse" | null
}

const definitions: DeepReadonly<Record<LabFaultId, LabFaultDefinition>> = deepFreeze({
  "token-invalid-grant": {
    id: "token-invalid-grant",
    displayName: "Token exchange returns invalid_grant",
    description: "Every affected token request fails with invalid_grant so clients must enter a clean reauthorization state without looping.",
    phase: "AUTH_TOKEN_ACQUISITION",
    category: "oauth_token",
    requiresOAuth: true,
    requiresProtocolMode: null,
  },
  "wrong-resource-audience": {
    id: "wrong-resource-audience",
    displayName: "Access token bound to the wrong resource",
    description: "Issued access tokens are bound to a different MCP resource, so the resource server rejects them with HTTP 401.",
    phase: "AUTH_RESOURCE_VALIDATION",
    category: "oauth_wrong_audience",
    requiresOAuth: true,
    requiresProtocolMode: null,
  },
  "access-token-expired": {
    id: "access-token-expired",
    displayName: "Access token expires immediately",
    description: "Access-token validation treats affected tokens as expired, forcing refresh or reauthorization.",
    phase: "AUTH_RESOURCE_VALIDATION",
    category: "oauth_token_expired",
    requiresOAuth: true,
    requiresProtocolMode: null,
  },
  "mcp-session-expired": {
    id: "mcp-session-expired",
    displayName: "MCP session expires early",
    description: "The affected session lookup fails with HTTP 404 so the client must recover with exactly one re-initialization.",
    phase: "CONTINUITY_SESSION",
    category: "mcp_session",
    requiresOAuth: false,
    requiresProtocolMode: "stable-session",
  },
  "authorization-server-unavailable": {
    id: "authorization-server-unavailable",
    displayName: "Authorization server unavailable",
    description: "Affected token requests fail with HTTP 503 so clients must apply bounded retry behavior.",
    phase: "AUTH_TOKEN_ACQUISITION",
    category: "oauth_availability",
    requiresOAuth: true,
    requiresProtocolMode: null,
  },
}) as DeepReadonly<Record<LabFaultId, LabFaultDefinition>>

export function getLabFaultDefinition(id: LabFaultId): LabFaultDefinition {
  return definitions[id]
}

export function listLabFaultDefinitions(): readonly LabFaultDefinition[] {
  return deepFreeze(Object.values(definitions))
}

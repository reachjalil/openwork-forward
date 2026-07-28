import { z } from "zod"
import type { LabAccessTokenRecord, LabEnvironment } from "../contracts/environment.js"
import type { McpLabStore } from "../store/contract.js"
import type { LabIdentity } from "../identity.js"
import type { LabFaultEvaluator } from "../faults/evaluator.js"
import type { LabRuntimeEnvironment, LabTracer } from "../trace.js"
import { sha256Hex } from "../trace.js"
import { labBearerToken, labJson, type LabHttpRequest, type LabHttpResponse } from "../http.js"

export interface LabMcpContext {
  readonly environment: LabEnvironment
  readonly identity: LabIdentity
  readonly store: McpLabStore
  readonly runtime: LabRuntimeEnvironment
  readonly tracer: LabTracer
  readonly faults: LabFaultEvaluator
  readonly correlationId: string
}

export const labJsonRpcRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite()]).optional(),
  method: z.string().min(1),
  params: z.unknown().optional(),
})

export type LabJsonRpcRequest = z.infer<typeof labJsonRpcRequestSchema>

export function jsonRpcResult(id: string | number, result: unknown): unknown {
  return { jsonrpc: "2.0", id, result }
}

export function jsonRpcError(id: string | number | null, code: number, message: string, data?: unknown): unknown {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } }
}

export type LabMcpAuthorization =
  | { readonly ok: true; readonly token: LabAccessTokenRecord | null }
  | { readonly ok: false; readonly response: LabHttpResponse }

export function unauthorizedChallenge(context: LabMcpContext, description: string): LabHttpResponse {
  const scopes = context.environment.scenario.authentication.requiredScopes.join(" ")
  return labJson(
    401,
    { error: "unauthorized", error_description: description },
    {
      "www-authenticate": `Bearer resource_metadata="${context.identity.protectedResourceMetadataUrl}", scope="${scopes}"`,
    },
  )
}

export function insufficientScopeChallenge(context: LabMcpContext, neededScopes: readonly string[]): LabHttpResponse {
  return labJson(
    403,
    { error: "insufficient_scope", error_description: "The access token does not carry the scope this operation requires" },
    {
      "www-authenticate": `Bearer error="insufficient_scope", resource_metadata="${context.identity.protectedResourceMetadataUrl}", scope="${neededScopes.join(" ")}"`,
    },
  )
}

/**
 * Applies the environment's authentication mode to one MCP request. In OAuth
 * mode this is where audience binding, expiry, the expired-token fault, and
 * required-scope enforcement happen.
 */
export async function authorizeMcpRequest(context: LabMcpContext, request: LabHttpRequest): Promise<LabMcpAuthorization> {
  const { environment, runtime, store, tracer, correlationId } = context
  const mode = environment.scenario.authentication.mode
  if (mode === "none") return { ok: true, token: null }

  const bearer = labBearerToken(request)
  if (!bearer) {
    return { ok: false, response: unauthorizedChallenge(context, "Provide a bearer access token") }
  }
  if (mode === "manual_bearer") {
    const expected = environment.manualBearer?.tokenHash
    if (!expected || sha256Hex(bearer) !== expected) {
      return { ok: false, response: unauthorizedChallenge(context, "The manual bearer token was rejected") }
    }
    return { ok: true, token: null }
  }

  const token = await store.validateAccessToken(environment.id, sha256Hex(bearer), runtime.now())
  if (!token) {
    return { ok: false, response: unauthorizedChallenge(context, "The access token is unknown, expired, or revoked") }
  }
  if (await context.faults.shouldApply("access-token-expired")) {
    await tracer.emit({
      correlationId,
      phase: "AUTH_RESOURCE_VALIDATION",
      direction: "outbound",
      kind: "fault",
      outcome: "applied",
      summary: "Treated a live access token as expired",
      details: { faultId: "access-token-expired" },
    })
    return { ok: false, response: unauthorizedChallenge(context, "The access token has expired") }
  }
  if (token.resource !== context.identity.mcpUrl) {
    await tracer.emit({
      correlationId,
      phase: "AUTH_RESOURCE_VALIDATION",
      direction: "inbound",
      kind: "security",
      outcome: "failed",
      summary: "Rejected an access token bound to a different MCP resource",
    })
    return { ok: false, response: unauthorizedChallenge(context, "The access token audience does not match this MCP resource") }
  }
  const missingScopes = environment.scenario.authentication.requiredScopes.filter((scope) => !token.scopes.includes(scope))
  if (missingScopes.length > 0) {
    return { ok: false, response: insufficientScopeChallenge(context, environment.scenario.authentication.requiredScopes) }
  }
  await tracer.emit({
    correlationId,
    phase: "AUTH_RESOURCE_VALIDATION",
    direction: "internal",
    kind: "lifecycle",
    outcome: "passed",
    summary: "Accepted a synthetic access token for this MCP resource",
    details: { scopeCount: token.scopes.length },
  })
  return { ok: true, token }
}

export function validateLabOrigin(context: LabMcpContext, request: LabHttpRequest): LabHttpResponse | null {
  const origin = request.headers.origin
  if (origin && origin !== new URL(context.identity.origin).origin) {
    return labJson(403, { error: "origin_not_allowed" })
  }
  return null
}

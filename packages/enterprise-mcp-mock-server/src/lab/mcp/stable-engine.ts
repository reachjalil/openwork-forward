import { z } from "zod"
import { validateToolArguments } from "../../contracts/tool.js"
import type { LabAccessTokenRecord, LabSessionRecord } from "../contracts/environment.js"
import {
  labAcceptedMediaTypes,
  labEmpty,
  labJson,
  labSse,
  readLabJson,
  LabHttpInputError,
  type LabHttpRequest,
  type LabHttpResponse,
} from "../http.js"
import { sha256Hex } from "../trace.js"
import { labToolCatalog, syntheticToolResult, type LabTool } from "./tools.js"
import {
  authorizeMcpRequest,
  insufficientScopeChallenge,
  jsonRpcError,
  jsonRpcResult,
  labJsonRpcRequestSchema,
  validateLabOrigin,
  type LabMcpContext,
} from "./shared.js"

/**
 * Stable session-based MCP engine for 2025-11-25, 2025-06-18, and 2025-03-26.
 *
 * Owns initialize, notifications/initialized, MCP-Protocol-Version and
 * MCP-Session-Id handling, JSON and SSE response modes, session expiry with
 * 404 recovery, tools/list pagination, tools/call, and GET/DELETE behavior.
 * GET returns 405: this engine never opens a server-initiated stream, which
 * the Streamable HTTP transport explicitly allows and which keeps the engine
 * serverless-safe.
 */

const sessionLifetimeMs = 24 * 60 * 60 * 1000

const initializeParamsSchema = z.object({
  protocolVersion: z.string().min(1),
  capabilities: z.record(z.string(), z.unknown()),
  clientInfo: z.object({ name: z.string().min(1), version: z.string().min(1) }),
})
const listToolsParamsSchema = z.object({ cursor: z.string().optional() }).optional()
const callToolParamsSchema = z.object({ name: z.string().min(1), arguments: z.unknown().optional() })

/** The header was introduced with 2025-06-18; 2025-03-26 clients never send it. */
function protocolVersionHeaderExpected(negotiatedVersion: string): boolean {
  return negotiatedVersion !== "2025-03-26"
}

function respond(context: LabMcpContext, body: unknown, headers?: Readonly<Record<string, string>>): LabHttpResponse {
  return context.environment.scenario.protocol.responseMode === "sse" ? labSse(body, headers) : labJson(200, body, headers)
}

export async function handleStableMcpRequest(context: LabMcpContext, request: LabHttpRequest): Promise<LabHttpResponse> {
  const { environment, runtime, store, tracer, correlationId } = context
  const scenario = environment.scenario

  const originRejection = validateLabOrigin(context, request)
  if (originRejection) return originRejection

  await tracer.emit({
    correlationId,
    phase: "MCP_TRANSPORT",
    direction: "inbound",
    kind: "request",
    outcome: "started",
    summary: "MCP endpoint request received",
    details: { method: request.method },
  })

  const authorization = await authorizeMcpRequest(context, request)
  if (!authorization.ok) return authorization.response
  const token = authorization.token

  if (request.method === "DELETE") {
    return handleSessionDelete(context, request, token)
  }
  if (request.method === "GET") {
    return labEmpty(405, { allow: "POST, DELETE" })
  }
  if (request.method !== "POST") {
    return labEmpty(405, { allow: "POST, DELETE" })
  }
  const accepted = labAcceptedMediaTypes(request.headers.accept)
  if (!accepted.has("application/json") || !accepted.has("text/event-stream")) {
    return labJson(406, { error: "not_acceptable", message: "Accept must include application/json and text/event-stream" })
  }

  let body: unknown
  try {
    body = readLabJson(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) {
      if (error.status === 400) return respond(context, jsonRpcError(null, -32700, "Parse error"))
      return labJson(error.status, { error: "invalid_http_input", message: error.message })
    }
    throw error
  }
  const parsed = labJsonRpcRequestSchema.safeParse(body)
  if (!parsed.success) {
    return respond(context, jsonRpcError(null, -32600, "Invalid Request", { issues: parsed.error.issues.map((issue) => issue.message) }))
  }
  const rpc = parsed.data

  if (rpc.method === "initialize") {
    if (rpc.id === undefined) return labEmpty(202)
    return handleInitialize(context, rpc.id, rpc.params, token)
  }

  const session = await resolveSession(context, request, token)
  if ("response" in session) return session.response

  if (rpc.method === "notifications/initialized") {
    if (rpc.id !== undefined) {
      return respond(context, jsonRpcError(rpc.id, -32600, "notifications/initialized must not include a JSON-RPC id"))
    }
    await store.saveSession(environment.id, { ...session.record, initialized: true })
    await tracer.emit({
      correlationId,
      phase: "MCP_INITIALIZED",
      direction: "internal",
      kind: "lifecycle",
      outcome: "passed",
      summary: "Accepted notifications/initialized",
    })
    return labEmpty(202)
  }

  if (scenario.protocol.requireStrictLifecycle && !session.record.initialized) {
    return respond(context, jsonRpcError(rpc.id ?? null, -32002, "MCP session is not initialized"))
  }

  if (rpc.id === undefined) {
    return labEmpty(202)
  }

  const sessionHeaders = {
    "mcp-session-id": session.rawSessionId,
    "mcp-protocol-version": session.record.protocolVersion,
  }
  if (rpc.method === "tools/list") {
    return handleToolsList(context, rpc.id, rpc.params, sessionHeaders)
  }
  if (rpc.method === "tools/call") {
    return handleToolCall(context, rpc.id, rpc.params, token, sessionHeaders)
  }
  return respond(context, jsonRpcError(rpc.id, -32601, `Unknown MCP method '${rpc.method}'`), sessionHeaders)
}

async function handleInitialize(
  context: LabMcpContext,
  requestId: string | number,
  params: unknown,
  token: LabAccessTokenRecord | null,
): Promise<LabHttpResponse> {
  const { environment, runtime, store, tracer, correlationId } = context
  const scenario = environment.scenario
  const parsedParams = initializeParamsSchema.safeParse(params)
  if (!parsedParams.success) {
    return respond(context, jsonRpcError(requestId, -32602, "Invalid initialize params"))
  }
  const requestedVersion = parsedParams.data.protocolVersion
  const supportedVersions = scenario.protocol.versions
  const negotiatedVersion = supportedVersions.includes(requestedVersion) ? requestedVersion : supportedVersions[0]
  if (!negotiatedVersion) {
    return respond(context, jsonRpcError(requestId, -32603, "The scenario has no supported MCP protocol version"))
  }

  const rawSessionId = runtime.opaqueValue("lab-mcp-session")
  await store.saveSession(environment.id, {
    sessionIdHash: sha256Hex(rawSessionId),
    tokenFamilyId: token?.familyId ?? null,
    protocolVersion: negotiatedVersion,
    scenarioRevision: environment.revision,
    expiresAtMs: Math.min(runtime.now() + sessionLifetimeMs, environment.expiresAtMs),
    initialized: false,
  })
  await tracer.emit({
    correlationId,
    phase: "MCP_INITIALIZE",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Negotiated the MCP protocol version and created an isolated session",
    details: { requestedVersion, negotiatedVersion },
  })
  return respond(
    context,
    jsonRpcResult(requestId, {
      protocolVersion: negotiatedVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "openwork-mcp-lab", version: "0.1.0" },
      instructions:
        "Synthetic OpenWork Diagnostics lab MCP server. All identities and records are synthetic; no provider authority is present.",
    }),
    { "mcp-session-id": rawSessionId, "mcp-protocol-version": negotiatedVersion },
  )
}

type ResolvedSession = { readonly record: LabSessionRecord; readonly rawSessionId: string } | { readonly response: LabHttpResponse }

async function resolveSession(
  context: LabMcpContext,
  request: LabHttpRequest,
  token: LabAccessTokenRecord | null,
): Promise<ResolvedSession> {
  const { environment, runtime, store, tracer, correlationId } = context
  const rawSessionId = request.headers["mcp-session-id"]
  if (!rawSessionId) {
    return { response: labJson(400, { error: "missing_mcp_session" }) }
  }
  const record = await store.getSession(environment.id, sha256Hex(rawSessionId), runtime.now())
  if (!record) {
    return { response: labJson(404, { error: "mcp_session_not_found" }) }
  }
  if (await context.faults.shouldApply("mcp-session-expired")) {
    await store.deleteSession(environment.id, record.sessionIdHash)
    await tracer.emit({
      correlationId,
      phase: "CONTINUITY_SESSION",
      direction: "outbound",
      kind: "fault",
      outcome: "applied",
      summary: "Expired the MCP session so the client must recover with one re-initialization",
      details: { faultId: "mcp-session-expired" },
    })
    return { response: labJson(404, { error: "mcp_session_expired" }) }
  }
  if (record.scenarioRevision !== environment.revision || (token && record.tokenFamilyId !== null && record.tokenFamilyId !== token.familyId)) {
    await tracer.emit({
      correlationId,
      phase: "CONTINUITY_SESSION",
      direction: "inbound",
      kind: "security",
      outcome: "failed",
      summary: "Rejected an MCP session outside its token or scenario boundary",
    })
    return { response: labJson(403, { error: "mcp_session_binding_mismatch" }) }
  }
  const presentedVersion = request.headers["mcp-protocol-version"]
  if (presentedVersion !== undefined && presentedVersion !== record.protocolVersion) {
    return { response: labJson(400, { error: "mcp_protocol_version_mismatch" }) }
  }
  if (
    presentedVersion === undefined &&
    protocolVersionHeaderExpected(record.protocolVersion) &&
    context.environment.scenario.protocol.requireStrictLifecycle
  ) {
    return { response: labJson(400, { error: "mcp_protocol_version_header_required" }) }
  }
  return { record, rawSessionId }
}

async function handleSessionDelete(
  context: LabMcpContext,
  request: LabHttpRequest,
  token: LabAccessTokenRecord | null,
): Promise<LabHttpResponse> {
  const { environment, runtime, store, tracer, correlationId } = context
  const rawSessionId = request.headers["mcp-session-id"]
  if (!rawSessionId) return labJson(404, { error: "mcp_session_not_found" })
  const record = await store.getSession(environment.id, sha256Hex(rawSessionId), runtime.now())
  if (!record) return labJson(404, { error: "mcp_session_not_found" })
  if (record.scenarioRevision !== environment.revision || (token && record.tokenFamilyId !== null && record.tokenFamilyId !== token.familyId)) {
    return labJson(403, { error: "mcp_session_binding_mismatch" })
  }
  await store.deleteSession(environment.id, record.sessionIdHash)
  await tracer.emit({
    correlationId,
    phase: "SHUTDOWN",
    direction: "internal",
    kind: "lifecycle",
    outcome: "completed",
    summary: "Terminated the synthetic MCP session",
  })
  return labEmpty(204)
}

function serializeStableTool(tool: LabTool): Record<string, unknown> {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: tool.inputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }
}

async function handleToolsList(
  context: LabMcpContext,
  requestId: string | number,
  params: unknown,
  sessionHeaders: Readonly<Record<string, string>>,
): Promise<LabHttpResponse> {
  const parsedParams = listToolsParamsSchema.safeParse(params)
  if (!parsedParams.success) {
    return respond(context, jsonRpcError(requestId, -32602, "Invalid tools/list params"), sessionHeaders)
  }
  const cursorText = parsedParams.data?.cursor
  const cursorMatch = cursorText ? /^page:(0|[1-9]\d*)$/.exec(cursorText) : null
  const offset = cursorText ? (cursorMatch ? Number(cursorMatch[1]) : Number.NaN) : 0
  if (!Number.isSafeInteger(offset) || offset < 0) {
    return respond(context, jsonRpcError(requestId, -32602, "Invalid catalog cursor"), sessionHeaders)
  }
  const tools = labToolCatalog(context.environment.scenario)
  const pageSize = context.environment.scenario.protocol.toolPageSize
  const page = tools.slice(offset, offset + pageSize).map((tool) => serializeStableTool(tool))
  const nextOffset = offset + pageSize
  const nextCursor = nextOffset < tools.length ? `page:${nextOffset}` : undefined
  await context.tracer.emit({
    correlationId: context.correlationId,
    phase: "MCP_TOOL_DISCOVERY",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Returned one bounded MCP tool-catalog page",
    details: { toolCount: page.length, offset, hasNextPage: nextCursor !== undefined },
  })
  return respond(context, jsonRpcResult(requestId, { tools: page, ...(nextCursor ? { nextCursor } : {}) }), sessionHeaders)
}

async function handleToolCall(
  context: LabMcpContext,
  requestId: string | number,
  params: unknown,
  token: LabAccessTokenRecord | null,
  sessionHeaders: Readonly<Record<string, string>>,
): Promise<LabHttpResponse> {
  const parsedParams = callToolParamsSchema.safeParse(params)
  if (!parsedParams.success) {
    return respond(context, jsonRpcError(requestId, -32602, "Invalid tools/call params"), sessionHeaders)
  }
  const tools = labToolCatalog(context.environment.scenario)
  const tool = tools.find((candidate) => candidate.name === parsedParams.data.name)
  if (!tool) {
    return respond(context, jsonRpcError(requestId, -32602, `Unknown tool '${parsedParams.data.name}'`), sessionHeaders)
  }
  if (tool.requiredScope && context.environment.scenario.authentication.mode === "oauth") {
    if (!token || !token.scopes.includes(tool.requiredScope)) {
      await context.tracer.emit({
        correlationId: context.correlationId,
        phase: "AUTH_RESOURCE_VALIDATION",
        direction: "outbound",
        kind: "security",
        outcome: "failed",
        summary: "Required a user-confirmed scope step-up before executing an elevated tool",
        details: { tool: tool.name },
      })
      return insufficientScopeChallenge(context, [
        ...context.environment.scenario.authentication.requiredScopes,
        tool.requiredScope,
      ])
    }
  }
  const argumentsResult = validateToolArguments(tool.inputSchema, parsedParams.data.arguments ?? {})
  if (!argumentsResult.success) {
    return respond(
      context,
      jsonRpcError(requestId, -32602, "Tool arguments do not match the declared input schema", { issues: argumentsResult.issues }),
      sessionHeaders,
    )
  }
  const result = syntheticToolResult(
    context.environment.scenario,
    tool.name,
    argumentsResult.value,
    context.runtime.opaqueValue("lab-provider-request"),
  )
  await context.tracer.emit({
    correlationId: context.correlationId,
    phase: "MCP_TOOL_EXECUTION",
    direction: "outbound",
    kind: "response",
    outcome: "passed",
    summary: "Executed a synthetic tool and returned deterministic data",
    details: { tool: tool.name },
  })
  return respond(
    context,
    jsonRpcResult(requestId, {
      isError: false,
      content: [{ type: "text", text: JSON.stringify(result) }],
      structuredContent: result,
    }),
    sessionHeaders,
  )
}

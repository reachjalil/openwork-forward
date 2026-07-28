import { z } from "zod"
import { validateToolArguments } from "../../contracts/tool.js"
import { labEmpty, labJson, readLabJson, LabHttpInputError, type LabHttpRequest, type LabHttpResponse } from "../http.js"
import { labToolCatalog, syntheticToolResult, type LabTool } from "./tools.js"
import {
  authorizeMcpRequest,
  insufficientScopeChallenge,
  jsonRpcError,
  jsonRpcResult,
  validateLabOrigin,
  type LabMcpContext,
} from "./shared.js"

/**
 * Draft stateless MCP engine, labeled DRAFT-2026-v1.
 *
 * The 2026-07-28 release candidate removes the initialize/session lifecycle
 * and moves protocol, client, and capability metadata onto every request, so
 * this is a separate serializer and handler rather than a branch of the
 * stable engine. It stays behind an explicit release-candidate flag until the
 * final specification is published (July 28, 2026) and this engine is
 * revalidated against it.
 */

export const draftReleaseCandidateVersion = "DRAFT-2026-v1"

const draftRequestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite()]).optional(),
  method: z.string().min(1),
  params: z.unknown().optional(),
  meta: z.object({
    protocolVersion: z.string().min(1),
    client: z.object({ name: z.string().min(1), version: z.string().min(1) }),
    capabilities: z.record(z.string(), z.unknown()).optional(),
  }),
})

const draftListParamsSchema = z.object({ cursor: z.string().optional() }).optional()
const draftCallParamsSchema = z.object({ name: z.string().min(1), arguments: z.unknown().optional() })

const draftToolListCacheTtlMs = 60_000

function structuredUnsupportedVersion(requested: string | undefined, supported: readonly string[]): LabHttpResponse {
  return labJson(400, {
    error: {
      code: "unsupported_protocol_version",
      message: "The requested MCP protocol version is not supported by this environment",
      requested: requested ?? null,
      supported,
    },
  })
}

function serializeDraftTool(tool: LabTool): Record<string, unknown> {
  return {
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: { $schema: "https://json-schema.org/draft/2020-12/schema", ...tool.inputSchema },
  }
}

export async function handleDraftMcpRequest(
  context: LabMcpContext,
  request: LabHttpRequest,
  options: { readonly releaseCandidateEnabled: boolean },
): Promise<LabHttpResponse> {
  const { environment, tracer, correlationId } = context
  const scenario = environment.scenario

  if (!options.releaseCandidateEnabled) {
    return labJson(503, {
      error: "release_candidate_disabled",
      error_description:
        "This environment uses the DRAFT-2026-v1 release candidate, which is disabled on this deployment until the final specification is adopted",
    })
  }
  const originRejection = validateLabOrigin(context, request)
  if (originRejection) return originRejection

  await tracer.emit({
    correlationId,
    phase: "MCP_TRANSPORT",
    direction: "inbound",
    kind: "request",
    outcome: "started",
    summary: "Draft stateless MCP request received",
    details: { method: request.method },
  })

  const authorization = await authorizeMcpRequest(context, request)
  if (!authorization.ok) return authorization.response
  const token = authorization.token

  if (request.method !== "POST") {
    return labEmpty(405, { allow: "POST" })
  }

  const headerVersion = request.headers["mcp-protocol-version"]
  if (headerVersion === undefined || !scenario.protocol.versions.includes(headerVersion)) {
    return structuredUnsupportedVersion(headerVersion, scenario.protocol.versions)
  }
  const headerMethod = request.headers["mcp-method"]
  if (!headerMethod) {
    return labJson(400, {
      error: { code: "missing_mcp_method_header", message: "Draft stateless requests must carry the Mcp-Method header" },
    })
  }

  let body: unknown
  try {
    body = readLabJson(request)
  } catch (error) {
    if (error instanceof LabHttpInputError) {
      return labJson(error.status === 415 ? 415 : 400, {
        error: { code: "invalid_request_body", message: error.message },
      })
    }
    throw error
  }
  const parsed = draftRequestSchema.safeParse(body)
  if (!parsed.success) {
    return labJson(400, {
      error: {
        code: "invalid_request_envelope",
        message: "Draft stateless requests carry method, id, params, and per-request meta with protocolVersion and client",
        issues: parsed.error.issues.map((issue) => issue.message),
      },
    })
  }
  const rpc = parsed.data

  if (rpc.meta.protocolVersion !== headerVersion) {
    return labJson(400, {
      error: {
        code: "header_body_mismatch",
        message: "meta.protocolVersion must equal the Mcp-Protocol-Version header",
      },
    })
  }
  if (rpc.method !== headerMethod) {
    return labJson(400, {
      error: { code: "header_body_mismatch", message: "The Mcp-Method header must equal the request body method" },
    })
  }
  if (rpc.method === "initialize" || rpc.method === "notifications/initialized") {
    return labJson(400, {
      error: {
        code: "lifecycle_removed",
        message: "DRAFT-2026-v1 has no initialize lifecycle; call server/discover and include per-request metadata instead",
      },
    })
  }
  const requestId = rpc.id ?? null
  if (requestId === null) {
    return labEmpty(202)
  }

  if (rpc.method === "server/discover") {
    await tracer.emit({
      correlationId,
      phase: "MCP_VERSION",
      direction: "outbound",
      kind: "response",
      outcome: "passed",
      summary: "Served draft stateless discovery metadata",
      details: { protocolVersion: headerVersion },
    })
    return labJson(
      200,
      jsonRpcResult(requestId, {
        protocol: { version: headerVersion, supportedVersions: scenario.protocol.versions },
        server: { name: "openwork-mcp-lab", version: "0.1.0" },
        capabilities: { tools: { list: true, call: true } },
        instructions:
          "Synthetic OpenWork Diagnostics lab MCP server speaking the DRAFT-2026-v1 release candidate. All data is synthetic.",
      }),
    )
  }

  if (rpc.method === "tools/list") {
    const parsedParams = draftListParamsSchema.safeParse(rpc.params)
    if (!parsedParams.success) {
      return labJson(200, jsonRpcError(requestId, -32602, "Invalid tools/list params"))
    }
    const cursorText = parsedParams.data?.cursor
    const cursorMatch = cursorText ? /^page:(0|[1-9]\d*)$/.exec(cursorText) : null
    const offset = cursorText ? (cursorMatch ? Number(cursorMatch[1]) : Number.NaN) : 0
    if (!Number.isSafeInteger(offset) || offset < 0) {
      return labJson(200, jsonRpcError(requestId, -32602, "Invalid catalog cursor"))
    }
    const tools = labToolCatalog(scenario)
    const pageSize = scenario.protocol.toolPageSize
    const page = tools.slice(offset, offset + pageSize).map((tool) => serializeDraftTool(tool))
    const nextOffset = offset + pageSize
    const nextCursor = nextOffset < tools.length ? `page:${nextOffset}` : undefined
    await tracer.emit({
      correlationId,
      phase: "MCP_TOOL_DISCOVERY",
      direction: "outbound",
      kind: "response",
      outcome: "passed",
      summary: "Returned one draft tool-catalog page with caching metadata",
      details: { toolCount: page.length, offset, hasNextPage: nextCursor !== undefined },
    })
    return labJson(
      200,
      jsonRpcResult(requestId, {
        tools: page,
        ...(nextCursor ? { nextCursor } : {}),
        ttlMs: draftToolListCacheTtlMs,
        cacheScope: "client",
      }),
    )
  }

  if (rpc.method === "tools/call") {
    const headerName = request.headers["mcp-name"]
    if (!headerName) {
      return labJson(400, {
        error: { code: "missing_mcp_name_header", message: "Draft tools/call requests must carry the Mcp-Name header" },
      })
    }
    const parsedParams = draftCallParamsSchema.safeParse(rpc.params)
    if (!parsedParams.success) {
      return labJson(200, jsonRpcError(requestId, -32602, "Invalid tools/call params"))
    }
    if (parsedParams.data.name !== headerName) {
      return labJson(400, {
        error: { code: "header_body_mismatch", message: "The Mcp-Name header must equal params.name" },
      })
    }
    const tools = labToolCatalog(scenario)
    const tool = tools.find((candidate) => candidate.name === parsedParams.data.name)
    if (!tool) {
      return labJson(200, jsonRpcError(requestId, -32602, `Unknown tool '${parsedParams.data.name}'`))
    }
    if (tool.requiredScope && scenario.authentication.mode === "oauth") {
      if (!token || !token.scopes.includes(tool.requiredScope)) {
        return insufficientScopeChallenge(context, [...scenario.authentication.requiredScopes, tool.requiredScope])
      }
    }
    const argumentsResult = validateToolArguments(tool.inputSchema, parsedParams.data.arguments ?? {})
    if (!argumentsResult.success) {
      return labJson(200, jsonRpcError(requestId, -32602, "Tool arguments do not match the declared input schema", { issues: argumentsResult.issues }))
    }
    const result = syntheticToolResult(scenario, tool.name, argumentsResult.value, context.runtime.opaqueValue("lab-provider-request"))
    await tracer.emit({
      correlationId,
      phase: "MCP_TOOL_EXECUTION",
      direction: "outbound",
      kind: "response",
      outcome: "passed",
      summary: "Executed a synthetic tool through the draft stateless engine",
      details: { tool: tool.name },
    })
    return labJson(
      200,
      jsonRpcResult(requestId, {
        isError: false,
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result,
      }),
    )
  }

  return labJson(200, jsonRpcError(requestId, -32601, `Unknown draft MCP method '${rpc.method}'`))
}

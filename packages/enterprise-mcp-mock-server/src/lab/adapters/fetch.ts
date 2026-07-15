import { maximumLabRequestBytes, type LabHttpRequest } from "../http.js"
import type { McpLabEngine } from "../engine.js"

export type LabFetchHandler = (request: Request) => Promise<Response>

/**
 * Fetch adapter: standard Request in, standard Response out. Next.js route
 * handlers in Diagnostics call this directly:
 *
 *   const handler = createLabFetchHandler(engine)
 *   export const GET = handler; export const POST = handler; export const DELETE = handler
 */
export function createLabFetchHandler(engine: McpLabEngine): LabFetchHandler {
  return async (request: Request): Promise<Response> => {
    let body = ""
    if (request.method !== "GET" && request.method !== "HEAD") {
      body = await request.text()
      if (Buffer.byteLength(body, "utf8") > maximumLabRequestBytes) {
        return new Response(JSON.stringify({ error: "payload_too_large" }), {
          status: 413,
          headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
        })
      }
    }
    const headers: Record<string, string> = {}
    request.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })
    const labRequest: LabHttpRequest = {
      method: request.method,
      url: new URL(request.url),
      headers,
      body,
    }
    const labResponse = await engine.handle(labRequest)
    return new Response(labResponse.body.length > 0 ? labResponse.body : null, {
      status: labResponse.status,
      headers: labResponse.headers as Record<string, string>,
    })
  }
}

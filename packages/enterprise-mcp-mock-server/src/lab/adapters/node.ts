import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import type { Socket } from "node:net"
import { maximumLabRequestBytes, type LabHttpRequest } from "../http.js"
import type { McpLabEngine } from "../engine.js"

export interface CreateLabNodeServerOptions {
  readonly engine: McpLabEngine
  readonly host?: string
  readonly port?: number
}

export interface LabNodeServer {
  readonly baseUrl: string
  start(): Promise<string>
  stop(): Promise<void>
}

/**
 * Node adapter: a loopback HTTP server over the same engine, for local
 * development, CI, fault-injection reproduction, and adapter-parity tests.
 */
export function createLabNodeServer(options: CreateLabNodeServerOptions): LabNodeServer {
  const engine = options.engine
  const host = options.host ?? "127.0.0.1"
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new Error("Lab node servers bind to loopback only")
  }
  const configuredPort = options.port ?? 0
  let server: Server | null = null
  let resolvedBaseUrl: string | null = null
  const sockets = new Set<Socket>()

  async function readBody(request: IncomingMessage): Promise<string | null> {
    request.setEncoding("utf8")
    const chunks: string[] = []
    let totalBytes = 0
    for await (const chunkValue of request) {
      const chunk = typeof chunkValue === "string" ? chunkValue : String(chunkValue)
      totalBytes += Buffer.byteLength(chunk, "utf8")
      if (totalBytes > maximumLabRequestBytes) {
        request.resume()
        return null
      }
      chunks.push(chunk)
    }
    return chunks.join("")
  }

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    try {
      const body = await readBody(request)
      if (body === null) {
        response.writeHead(413, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" })
        response.end(JSON.stringify({ error: "payload_too_large" }))
        return
      }
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(request.headers)) {
        if (value === undefined) continue
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value
      }
      if (!resolvedBaseUrl) throw new Error("Lab node server is not listening")
      const labRequest: LabHttpRequest = {
        method: request.method ?? "GET",
        url: new URL(request.url ?? "/", resolvedBaseUrl),
        headers,
        body,
      }
      const labResponse = await engine.handle(labRequest)
      response.writeHead(labResponse.status, { ...labResponse.headers, connection: "close" })
      response.end(labResponse.body)
    } catch {
      if (response.headersSent || response.destroyed) return
      response.writeHead(500, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" })
      response.end(JSON.stringify({ error: "lab_internal_error" }))
    }
  }

  return {
    get baseUrl(): string {
      if (!resolvedBaseUrl) throw new Error("Lab node server has not started")
      return resolvedBaseUrl
    },
    async start(): Promise<string> {
      if (resolvedBaseUrl) return resolvedBaseUrl
      const created = createServer((request, response) => {
        void route(request, response)
      })
      created.on("connection", (socket) => {
        sockets.add(socket)
        socket.once("close", () => sockets.delete(socket))
      })
      server = created
      const port = await new Promise<number>((resolve, reject) => {
        const onError = (error: Error): void => reject(error)
        created.once("error", onError)
        created.listen(configuredPort, host, () => {
          created.off("error", onError)
          const address = created.address()
          if (!address || typeof address === "string") {
            reject(new Error("Lab node server did not expose a TCP address"))
            return
          }
          resolve(address.port)
        })
      })
      const formattedHost = host === "::1" ? "[::1]" : host
      resolvedBaseUrl = `http://${formattedHost}:${port}`
      return resolvedBaseUrl
    },
    async stop(): Promise<void> {
      const active = server
      server = null
      resolvedBaseUrl = null
      if (!active) return
      await new Promise<void>((resolve, reject) => {
        for (const socket of sockets) socket.destroy()
        sockets.clear()
        active.close((error) => (error ? reject(error) : resolve()))
      })
    },
  }
}

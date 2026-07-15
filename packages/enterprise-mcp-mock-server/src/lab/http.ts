/**
 * Transport-neutral HTTP values for the lab core.
 *
 * The core never touches IncomingMessage, ServerResponse, Request, or
 * Response; adapters marshal into and out of these plain structures. SSE
 * responses are complete single-message bodies, which keeps the core pure and
 * serverless-safe (Streamable HTTP allows a stream that carries one response
 * and then closes).
 */

export interface LabHttpRequest {
  readonly method: string
  readonly url: URL
  /** Header names lowercased; multi-value headers joined with ", ". */
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}

export interface LabHttpResponse {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}

export const maximumLabRequestBytes = 1024 * 1024

export function labJson(status: number, body: unknown, headers?: Readonly<Record<string, string>>): LabHttpResponse {
  return {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
    body: JSON.stringify(body),
  }
}

export function labSse(body: unknown, headers?: Readonly<Record<string, string>>): LabHttpResponse {
  return {
    status: 200,
    headers: { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store", ...headers },
    body: `event: message\ndata: ${JSON.stringify(body)}\n\n`,
  }
}

export function labHtml(status: number, html: string, headers?: Readonly<Record<string, string>>): LabHttpResponse {
  return {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...headers,
    },
    body: html,
  }
}

export function labRedirect(location: string): LabHttpResponse {
  return { status: 302, headers: { location, "cache-control": "no-store" }, body: "" }
}

export function labEmpty(status: number, headers?: Readonly<Record<string, string>>): LabHttpResponse {
  return { status, headers: { "cache-control": "no-store", ...headers }, body: "" }
}

export function labOAuthError(
  status: number,
  error: string,
  description: string,
  headers?: Readonly<Record<string, string>>,
): LabHttpResponse {
  return labJson(status, { error, error_description: description }, headers)
}

export class LabHttpInputError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = "LabHttpInputError"
  }
}

function mediaType(value: string | undefined): string {
  return value?.split(";", 1)[0]?.trim().toLowerCase() ?? ""
}

export function readLabJson(request: LabHttpRequest): unknown {
  if (mediaType(request.headers["content-type"]) !== "application/json") {
    throw new LabHttpInputError(415, "Content-Type must be application/json")
  }
  try {
    return JSON.parse(request.body) as unknown
  } catch {
    throw new LabHttpInputError(400, "Request body is not valid JSON")
  }
}

export function readLabForm(request: LabHttpRequest): URLSearchParams {
  if (mediaType(request.headers["content-type"]) !== "application/x-www-form-urlencoded") {
    throw new LabHttpInputError(415, "Content-Type must be application/x-www-form-urlencoded")
  }
  return new URLSearchParams(request.body)
}

export function labAcceptedMediaTypes(header: string | undefined): ReadonlySet<string> {
  const accepted = new Set<string>()
  for (const entry of (header ?? "").split(",")) {
    const [rawType, ...parameters] = entry.split(";")
    const type = rawType?.trim().toLowerCase() ?? ""
    if (!type) continue
    const qualityParameter = parameters.map((value) => value.trim()).find((value) => /^q\s*=/i.test(value))
    if (qualityParameter) {
      const quality = Number(qualityParameter.split("=", 2)[1]?.trim())
      if (!Number.isFinite(quality) || quality <= 0 || quality > 1) continue
    }
    accepted.add(type)
  }
  return accepted
}

export function labBearerToken(request: LabHttpRequest): string | undefined {
  const match = /^Bearer +([^\s]+)$/i.exec(request.headers.authorization ?? "")
  return match?.[1]
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

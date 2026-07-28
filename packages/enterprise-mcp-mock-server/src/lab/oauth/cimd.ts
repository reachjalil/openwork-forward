import { z } from "zod"
import type { LabCimdDocumentRecord, LabTokenEndpointAuthMethod } from "../contracts/environment.js"
import type { McpLabStore } from "../store/contract.js"
import { sha256Hex } from "../trace.js"

/**
 * Client ID Metadata Documents (SEP-991).
 *
 * When `client_id` is an HTTPS URL, the authority fetches that URL and treats
 * the returned JSON as the client's registration. Because the fetch target is
 * attacker-controlled, every fetch and every redirect passes the SSRF guard,
 * responses are size- and time-bounded, and no credentials are ever forwarded
 * to the metadata origin.
 */

export interface CimdFetchResult {
  readonly status: number
  /** Header names lowercased. */
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}

/**
 * Performs one HTTP GET without following redirects. The engine loops over
 * redirects itself so each hop is revalidated. Implementations must apply
 * `timeoutMs` and stop reading after `maxBytes`.
 */
export type CimdFetcher = (
  url: string,
  init: { readonly headers: Readonly<Record<string, string>>; readonly maxBytes: number; readonly timeoutMs: number },
) => Promise<CimdFetchResult>

export interface CimdPolicy {
  /** Allow http://localhost / 127.0.0.1 / [::1] documents. Local development only. */
  readonly allowLoopback: boolean
  readonly maxRedirects: number
  readonly maxDocumentBytes: number
  readonly fetchTimeoutMs: number
  readonly cacheTtlSeconds: number
}

export const defaultCimdPolicy: CimdPolicy = {
  allowLoopback: false,
  maxRedirects: 3,
  maxDocumentBytes: 64 * 1024,
  fetchTimeoutMs: 3_000,
  cacheTtlSeconds: 300,
}

const maximumCimdUrlLength = 2_048

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1"
}

function parseIpv4(hostname: string): readonly number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname)
  if (!match) return null
  const octets = match.slice(1).map(Number)
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null
}

function isBlockedIpv4(octets: readonly number[]): boolean {
  const [a = 0, b = 0] = octets
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a >= 224) return true
  return false
}

/**
 * Expands an IPv6 literal into its eight 16-bit groups.
 *
 * WHATWG `URL` canonicalizes IPv6 hosts before we ever see them, so the
 * familiar dotted-quad spelling never survives: `[::ffff:10.0.0.8]` arrives as
 * `[::ffff:a00:8]`. Comparing spellings therefore cannot work — the address has
 * to be parsed and matched numerically.
 */
function parseIpv6(hostname: string): readonly number[] | null {
  let bare = hostname.trim().toLowerCase()
  if (bare.startsWith("[") && bare.endsWith("]")) bare = bare.slice(1, -1)
  const zoneIndex = bare.indexOf("%")
  if (zoneIndex !== -1) bare = bare.slice(0, zoneIndex)
  if (!bare.includes(":")) return null

  const dotted = /^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(bare)
  if (dotted?.[1] !== undefined && dotted[2] !== undefined) {
    const octets = parseIpv4(dotted[2])
    if (!octets) return null
    const [a = 0, b = 0, c = 0, d = 0] = octets
    bare = `${dotted[1]}${(((a << 8) | b) >>> 0).toString(16)}:${(((c << 8) | d) >>> 0).toString(16)}`
  }

  const halves = bare.split("::")
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(":") : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : []
  const groups =
    halves.length === 2 ? [...head, ...Array<string>(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail] : head
  if (groups.length !== 8) return null
  const parsed = groups.map((group) => (/^[0-9a-f]{1,4}$/.test(group) ? Number.parseInt(group, 16) : Number.NaN))
  return parsed.some((value) => Number.isNaN(value)) ? null : parsed
}

/** Only call for real IPv6 literals: an unparseable literal fails closed. */
function isBlockedIpv6(hostname: string): boolean {
  const groups = parseIpv6(hostname)
  if (!groups) return true
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups
  const embeddedIpv4 = [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff]
  const leadingZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0
  if (leadingZero && g5 === 0 && g6 === 0 && (g7 === 0 || g7 === 1)) return true
  if (leadingZero && g5 === 0xffff) return isBlockedIpv4(embeddedIpv4)
  if (leadingZero && g5 === 0) return isBlockedIpv4(embeddedIpv4)
  if (g0 === 0x0064 && g1 === 0xff9b) return isBlockedIpv4(embeddedIpv4)
  if ((g0 & 0xfe00) === 0xfc00) return true
  if ((g0 & 0xffc0) === 0xfe80) return true
  if ((g0 & 0xff00) === 0xff00) return true
  return false
}

export type CimdUrlVerdict = { readonly ok: true; readonly url: URL } | { readonly ok: false; readonly reason: string }

/** SSRF guard applied to the initial CIMD URL and to every redirect target. */
export function assertSafeCimdUrl(value: string, policy: CimdPolicy): CimdUrlVerdict {
  if (value.length > maximumCimdUrlLength) return { ok: false, reason: "URL exceeds the maximum length" }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return { ok: false, reason: "URL does not parse" }
  }
  if (url.username || url.password) return { ok: false, reason: "URL must not carry credentials" }
  if (url.hash) return { ok: false, reason: "URL must not carry a fragment" }
  const loopback = isLoopbackHost(url.hostname)
  if (url.protocol === "http:") {
    if (!loopback || !policy.allowLoopback) return { ok: false, reason: "HTTP is only allowed for loopback in local development" }
    return { ok: true, url }
  }
  if (url.protocol !== "https:") return { ok: false, reason: "Only HTTPS URLs are allowed" }
  if (loopback && !policy.allowLoopback) return { ok: false, reason: "Loopback hosts are not allowed" }
  const ipv4 = parseIpv4(url.hostname)
  if (ipv4 && isBlockedIpv4(ipv4) && !(policy.allowLoopback && ipv4[0] === 127)) {
    return { ok: false, reason: "Private, reserved, or multicast IPv4 hosts are not allowed" }
  }
  // WHATWG URL always brackets an IPv6 host, so this is the reliable signal for
  // "parse as IPv6" — and it keeps isBlockedIpv6's fail-closed default from ever
  // seeing an ordinary DNS name.
  if (url.hostname.startsWith("[") && isBlockedIpv6(url.hostname) && !(policy.allowLoopback && isLoopbackHost(url.hostname))) {
    return { ok: false, reason: "Private or reserved IPv6 hosts are not allowed" }
  }
  return { ok: true, url }
}

const cimdDocumentSchema = z.object({
  client_id: z.string().min(1).max(maximumCimdUrlLength),
  client_name: z.string().min(1).max(200).optional(),
  redirect_uris: z.array(z.string().min(1).max(2_048)).min(1).max(10),
  grant_types: z.array(z.enum(["authorization_code", "refresh_token"])).min(1).optional(),
  response_types: z.array(z.literal("code")).min(1).optional(),
  token_endpoint_auth_method: z.literal("none").optional(),
  scope: z.string().max(1_024).optional(),
})

export type CimdResolution =
  | { readonly ok: true; readonly document: LabCimdDocumentRecord["document"]; readonly fromCache: boolean }
  | { readonly ok: false; readonly error: "invalid_client_metadata" | "invalid_client"; readonly reason: string }

function rejected(reason: string): CimdResolution {
  return { ok: false, error: "invalid_client_metadata", reason }
}

export async function resolveClientMetadataDocument(options: {
  readonly clientIdUrl: string
  readonly fetcher: CimdFetcher
  readonly policy: CimdPolicy
  readonly store: McpLabStore
  readonly environmentId: string
  readonly nowMs: number
}): Promise<CimdResolution> {
  const { clientIdUrl, fetcher, policy, store, environmentId, nowMs } = options
  const initialVerdict = assertSafeCimdUrl(clientIdUrl, policy)
  if (!initialVerdict.ok) return rejected(`Client ID URL rejected: ${initialVerdict.reason}`)

  const urlHash = sha256Hex(clientIdUrl)
  const cached = await store.getCimdDocument(environmentId, urlHash, nowMs)
  if (cached) return { ok: true, document: cached.document, fromCache: true }

  // Never forward authorization headers or cookies to the metadata origin.
  const fetchHeaders = { accept: "application/json" } as const

  let currentUrl = initialVerdict.url
  let response: CimdFetchResult | null = null
  for (let hop = 0; hop <= policy.maxRedirects; hop += 1) {
    let fetched: CimdFetchResult
    try {
      fetched = await fetcher(currentUrl.href, {
        headers: fetchHeaders,
        maxBytes: policy.maxDocumentBytes,
        timeoutMs: policy.fetchTimeoutMs,
      })
    } catch {
      return rejected("The client metadata document could not be fetched within the configured limits")
    }
    if (fetched.status === 301 || fetched.status === 302 || fetched.status === 307 || fetched.status === 308) {
      const location = fetched.headers.location
      if (!location) return rejected("Redirect response did not include a location")
      let target: URL
      try {
        target = new URL(location, currentUrl)
      } catch {
        return rejected("Redirect target does not parse")
      }
      const verdict = assertSafeCimdUrl(target.href, policy)
      if (!verdict.ok) return rejected(`Redirect target rejected: ${verdict.reason}`)
      if (hop === policy.maxRedirects) return rejected("Too many redirects while fetching the client metadata document")
      currentUrl = verdict.url
      continue
    }
    response = fetched
    break
  }
  if (!response) return rejected("Too many redirects while fetching the client metadata document")
  if (response.status !== 200) return rejected(`The client metadata document returned HTTP ${response.status}`)
  const contentType = response.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase() ?? ""
  if (contentType !== "application/json") return rejected("The client metadata document must be application/json")
  if (Buffer.byteLength(response.body, "utf8") > policy.maxDocumentBytes) {
    return rejected("The client metadata document exceeds the size limit")
  }

  let parsedBody: unknown
  try {
    parsedBody = JSON.parse(response.body) as unknown
  } catch {
    return rejected("The client metadata document is not valid JSON")
  }
  const parsed = cimdDocumentSchema.safeParse(parsedBody)
  if (!parsed.success) {
    return rejected(`The client metadata document is malformed: ${parsed.error.issues[0]?.message ?? "invalid"}`)
  }
  if (parsed.data.client_id !== clientIdUrl) {
    return rejected("The document's client_id must exactly equal the URL it was fetched from")
  }

  const tokenEndpointAuthMethod: LabTokenEndpointAuthMethod = parsed.data.token_endpoint_auth_method ?? "none"
  const document: LabCimdDocumentRecord["document"] = {
    clientId: parsed.data.client_id,
    clientName: parsed.data.client_name ?? null,
    redirectUris: parsed.data.redirect_uris,
    grantTypes: parsed.data.grant_types ?? ["authorization_code"],
    responseTypes: parsed.data.response_types ?? ["code"],
    tokenEndpointAuthMethod,
    scopes: parsed.data.scope === undefined ? null : parsed.data.scope.split(" ").filter(Boolean),
  }
  await store.saveCimdDocument(environmentId, {
    urlHash,
    document,
    expiresAtMs: nowMs + policy.cacheTtlSeconds * 1_000,
  })
  return { ok: true, document, fromCache: false }
}

/** Default fetcher built on global fetch with manual redirects and byte/time limits. */
export function createDefaultCimdFetcher(): CimdFetcher {
  return async (url, init) => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), init.timeoutMs)
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { ...init.headers },
        redirect: "manual",
        signal: controller.signal,
      })
      const headers: Record<string, string> = {}
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value
      })
      const reader = response.body?.getReader()
      let received = 0
      const chunks: Uint8Array[] = []
      if (reader) {
        for (;;) {
          const { done, value } = await reader.read()
          if (done) break
          received += value.byteLength
          if (received > init.maxBytes) {
            await reader.cancel()
            throw new Error("cimd_document_too_large")
          }
          chunks.push(value)
        }
      }
      const body = Buffer.concat(chunks).toString("utf8")
      return { status: response.status, headers, body }
    } finally {
      clearTimeout(timer)
    }
  }
}

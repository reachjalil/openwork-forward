import type { LabApplicationType } from "../contracts/environment.js"

export type LabRedirectVerdict = { readonly ok: true } | { readonly ok: false; readonly reason: string }

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1"
}

/**
 * Application-type-aware redirect URI rules (RFC 7591 + RFC 8252):
 *
 * - `web` clients redirect to HTTPS URLs such as the shared Den callback.
 * - `native` clients redirect to loopback HTTP, private-use schemes, or
 *   HTTPS app-claimed links.
 *
 * A redirect incompatible with the declared application type is rejected as
 * `invalid_redirect_uri` during registration.
 */
export function validateLabRedirectUri(value: string, applicationType: LabApplicationType): LabRedirectVerdict {
  if (value.length > 2_048) return { ok: false, reason: "Redirect URI exceeds the maximum length" }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return { ok: false, reason: "Redirect URI does not parse" }
  }
  if (url.username || url.password) return { ok: false, reason: "Redirect URI must not carry credentials" }
  if (url.hash) return { ok: false, reason: "Redirect URI must not carry a fragment" }

  if (url.protocol === "https:") return { ok: true }
  if (url.protocol === "http:") {
    if (!isLoopbackHost(url.hostname)) return { ok: false, reason: "HTTP redirect URIs must use a loopback host" }
    if (applicationType !== "native") return { ok: false, reason: "Loopback redirects are only valid for native applications" }
    return { ok: true }
  }
  if (applicationType !== "native") {
    return { ok: false, reason: "Private-use scheme redirects are only valid for native applications" }
  }
  if (!/^[a-z][a-z0-9+.-]*:$/i.test(url.protocol) || url.protocol === "javascript:" || url.protocol === "data:" || url.protocol === "file:") {
    return { ok: false, reason: "Redirect URI scheme is not allowed" }
  }
  return { ok: true }
}

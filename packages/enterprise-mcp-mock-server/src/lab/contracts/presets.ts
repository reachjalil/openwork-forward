import { deepFreeze } from "../../immutability.js"
import { labScenarioV2Schema, type McpLabScenarioV2 } from "./scenario.js"

/**
 * The required first-wave presets for the OAuth/MCP lab. Every preset is a
 * complete, valid scenario; the dashboard offers them as starting points and
 * conformance journeys reference them by id.
 */

export type LabScenarioPresetId =
  | "stable-healthy-dcr"
  | "stable-healthy-cimd"
  | "stable-manual-client"
  | "no-registration-available"
  | "multiple-issuers"
  | "oidc-only-discovery"
  | "refresh-rotation"
  | "refresh-omission"
  | "incremental-scope"
  | "issuer-mismatch"
  | "wrong-resource"
  | "invalid-grant"
  | "draft-stateless"
  | "stable-downgrade"
  | "session-expiry"

export interface LabScenarioPreset {
  readonly presetId: LabScenarioPresetId
  readonly title: string
  readonly purpose: string
  readonly scenario: McpLabScenarioV2
}

interface PresetOverrides {
  readonly protocol?: Partial<McpLabScenarioV2["protocol"]>
  readonly authentication?: Partial<{
    -readonly [Key in keyof McpLabScenarioV2["authentication"]]: McpLabScenarioV2["authentication"][Key]
  }>
  readonly fault?: McpLabScenarioV2["fault"]
}

const placeholderSharedCallback = "https://example.invalid/oauth/callback"

function buildScenario(id: string, overrides: PresetOverrides = {}): McpLabScenarioV2 {
  return labScenarioV2Schema.parse({
    schemaVersion: 2,
    id,
    revision: 1,
    profileId: "standards-conformance",
    protocol: {
      mode: "stable-session",
      versions: ["2025-11-25", "2025-06-18", "2025-03-26"],
      responseMode: "json",
      requireStrictLifecycle: true,
      toolPageSize: 3,
      ...overrides.protocol,
    },
    authentication: {
      mode: "oauth",
      discovery: "rfc8414_then_oidc",
      registration: "dynamic",
      authorizationServers: [
        { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
      ],
      applicationTypes: ["web"],
      tokenEndpointAuthMethods: ["none"],
      requiredScopes: ["mcp:tools"],
      optionalScopes: [],
      refresh: { advertised: true, issueRefreshToken: true, rotate: false, omitReplacementOnRefresh: false },
      authorizationResponseIssuer: "correct",
      ...overrides.authentication,
    },
    fault: overrides.fault ?? null,
    lifetimeSeconds: 3_600,
  })
}

const presets: readonly LabScenarioPreset[] = deepFreeze([
  {
    presetId: "stable-healthy-dcr",
    title: "Stable healthy DCR",
    purpose: "Web dynamic client registration with PKCE, the shared HTTPS callback, and refresh tokens.",
    scenario: buildScenario("stable-healthy-dcr"),
  },
  {
    presetId: "stable-healthy-cimd",
    title: "Stable healthy CIMD",
    purpose: "Client ID Metadata Documents chosen without DCR; the registration endpoint stays disabled.",
    scenario: buildScenario("stable-healthy-cimd", {
      authentication: {
        registration: "client_metadata",
        authorizationServers: [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: true, registrationEndpointEnabled: false },
        ],
      },
    }),
  },
  {
    presetId: "stable-manual-client",
    title: "Stable manual client",
    purpose: "A pre-registered client and one-time secret entered manually into the connecting client.",
    scenario: buildScenario("stable-manual-client", {
      authentication: {
        registration: "pre_registered",
        authorizationServers: [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: false },
        ],
        tokenEndpointAuthMethods: ["client_secret_basic", "client_secret_post"],
        preRegisteredRedirectUris: [placeholderSharedCallback],
      },
    }),
  },
  {
    presetId: "no-registration-available",
    title: "No registration available",
    purpose: "Neither DCR nor CIMD is offered, so clients must surface a typed manual-configuration requirement.",
    scenario: buildScenario("no-registration-available", {
      authentication: {
        registration: "none_available",
        authorizationServers: [
          { issuerPath: "/oauth", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: false },
        ],
      },
    }),
  },
  {
    presetId: "multiple-issuers",
    title: "Multiple issuers",
    purpose: "Protected-resource metadata lists two authorization servers, forcing explicit issuer selection.",
    scenario: buildScenario("multiple-issuers", {
      authentication: {
        authorizationServers: [
          { issuerPath: "/oauth-primary", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
          { issuerPath: "/oauth-secondary", clientIdMetadataDocumentSupported: false, registrationEndpointEnabled: true },
        ],
      },
    }),
  },
  {
    presetId: "oidc-only-discovery",
    title: "OIDC-only discovery",
    purpose: "Only openid-configuration documents exist, testing RFC 8414 → OIDC fallback ordering.",
    scenario: buildScenario("oidc-only-discovery", {
      authentication: { discovery: "oidc" },
    }),
  },
  {
    presetId: "refresh-rotation",
    title: "Refresh rotation",
    purpose: "Every successful refresh returns a new refresh token; replaying the old one revokes the family.",
    scenario: buildScenario("refresh-rotation", {
      authentication: { refresh: { advertised: true, issueRefreshToken: true, rotate: true, omitReplacementOnRefresh: false } },
    }),
  },
  {
    presetId: "refresh-omission",
    title: "Refresh omission",
    purpose: "A successful refresh omits the refresh_token field, so clients must preserve the existing token.",
    scenario: buildScenario("refresh-omission", {
      authentication: { refresh: { advertised: true, issueRefreshToken: true, rotate: false, omitReplacementOnRefresh: true } },
    }),
  },
  {
    presetId: "incremental-scope",
    title: "Incremental scope",
    purpose: "An elevated tool returns an insufficient_scope challenge requiring user-confirmed step-up.",
    scenario: buildScenario("incremental-scope", {
      authentication: { optionalScopes: ["mcp:admin"] },
    }),
  },
  {
    presetId: "issuer-mismatch",
    title: "Issuer mismatch",
    purpose: "The authorization response carries a wrong iss value; clients must fail closed.",
    scenario: buildScenario("issuer-mismatch", {
      authentication: { authorizationResponseIssuer: "mismatched" },
    }),
  },
  {
    presetId: "wrong-resource",
    title: "Wrong resource",
    purpose: "Issued tokens bind to a different resource, so the MCP endpoint rejects the audience.",
    scenario: buildScenario("wrong-resource", {
      fault: { id: "wrong-resource-audience", occurrence: "always" },
    }),
  },
  {
    presetId: "invalid-grant",
    title: "Invalid grant",
    purpose: "Token exchange always fails with invalid_grant; clients must reach a clean reauthorization state.",
    scenario: buildScenario("invalid-grant", {
      fault: { id: "token-invalid-grant", occurrence: "always" },
    }),
  },
  {
    presetId: "draft-stateless",
    title: "Draft stateless",
    purpose: "server/discover with per-request metadata and no session, behind the release-candidate flag.",
    scenario: buildScenario("draft-stateless", {
      protocol: {
        mode: "stateless-draft",
        versions: ["DRAFT-2026-v1"],
        responseMode: "json",
        requireStrictLifecycle: false,
      },
    }),
  },
  {
    presetId: "stable-downgrade",
    title: "Stable downgrade",
    purpose: "A 2025-11-25 client meets a server that prefers 2025-06-18 and must accept the downgrade.",
    scenario: buildScenario("stable-downgrade", {
      protocol: { versions: ["2025-06-18", "2025-03-26"] },
    }),
  },
  {
    presetId: "session-expiry",
    title: "Session expiry",
    purpose: "One post-initialize request returns 404 so the client must recover with exactly one re-initialization.",
    scenario: buildScenario("session-expiry", {
      fault: { id: "mcp-session-expired", occurrence: "once" },
    }),
  },
]) as readonly LabScenarioPreset[]

export function listLabScenarioPresets(): readonly LabScenarioPreset[] {
  return presets
}

export function getLabScenarioPreset(presetId: LabScenarioPresetId): LabScenarioPreset {
  const preset = presets.find((candidate) => candidate.presetId === presetId)
  if (!preset) throw new Error(`Unknown lab scenario preset '${presetId}'`)
  return preset
}

import { z } from "zod"
import { deepFreeze, type DeepReadonly } from "../../immutability.js"
import { labFaultIdSchema, getLabFaultDefinition } from "../faults/catalog.js"

/**
 * Scenario schema version 2 for configurable OAuth/MCP lab environments.
 *
 * Version 1 (`contracts/scenario.ts`) describes one deployment-wide provider
 * clone. Version 2 separates provider shape, OAuth authority behavior, and
 * MCP protocol behavior so one Diagnostics deployment can host many isolated
 * synthetic environments.
 */

export const labProfileIdSchema = z.enum([
  "standards-conformance",
  "servicenow-inbound",
  "microsoft-work-iq",
  "microsoft-enterprise",
  "agent-365-mail",
])

export type LabProfileId = z.infer<typeof labProfileIdSchema>

export const stableProtocolVersions = ["2025-11-25", "2025-06-18", "2025-03-26"] as const
/**
 * The 2026-07-28 architecture is a release candidate. It stays behind the
 * explicit engine flag until the final specification is published and this
 * label is revalidated; it must never become a silent default.
 */
export const draftProtocolVersions = ["DRAFT-2026-v1"] as const
export const legacyProtocolVersions = ["2024-11-05"] as const

const issuerPathPattern = /^\/[a-z][a-z0-9-]*$/

const labAuthorizationServerSchema = z.object({
  issuerPath: z.string().regex(issuerPathPattern, "Issuer path must look like /oauth or /oauth-secondary"),
  clientIdMetadataDocumentSupported: z.boolean(),
  registrationEndpointEnabled: z.boolean(),
})

export const labProtocolModeSchema = z.enum(["stable-session", "stateless-draft", "legacy-sse"])
export const labDiscoverySchema = z.enum(["rfc8414", "oidc", "rfc8414_then_oidc"])
export const labRegistrationSchema = z.enum(["pre_registered", "client_metadata", "dynamic", "none_available"])
export const labAuthenticationModeSchema = z.enum(["oauth", "manual_bearer", "none"])
export const labApplicationTypeSchema = z.enum(["web", "native"])
export const labTokenEndpointAuthMethodSchema = z.enum(["none", "client_secret_post", "client_secret_basic"])
export const labAuthorizationResponseIssuerSchema = z.enum(["correct", "missing", "mismatched"])

export const labActiveFaultSchema = z
  .object({
    id: labFaultIdSchema,
    occurrence: z.enum(["always", "once", "nth"]),
    nth: z.number().int().min(2).max(100).optional(),
  })
  .superRefine((fault, context) => {
    if (fault.occurrence === "nth" && fault.nth === undefined) {
      context.addIssue({ code: "custom", message: "Occurrence 'nth' requires the nth request number", path: ["nth"] })
    }
    if (fault.occurrence !== "nth" && fault.nth !== undefined) {
      context.addIssue({ code: "custom", message: "nth is only valid with occurrence 'nth'", path: ["nth"] })
    }
  })

export type LabActiveFault = z.infer<typeof labActiveFaultSchema>

const scopePattern = /^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/

const rawLabScenarioSchema = z.object({
  schemaVersion: z.literal(2),
  id: z.string().regex(/^[a-z][a-z0-9-]{2,63}$/),
  revision: z.number().int().positive(),
  profileId: labProfileIdSchema,
  protocol: z.object({
    mode: labProtocolModeSchema,
    versions: z.array(z.string().min(1)).min(1).max(3),
    responseMode: z.enum(["json", "sse"]),
    requireStrictLifecycle: z.boolean(),
    toolPageSize: z.number().int().positive().max(100),
  }),
  authentication: z.object({
    mode: labAuthenticationModeSchema,
    discovery: labDiscoverySchema,
    registration: labRegistrationSchema,
    authorizationServers: z.array(labAuthorizationServerSchema).min(1).max(3),
    applicationTypes: z.array(labApplicationTypeSchema).min(1).max(2),
    tokenEndpointAuthMethods: z.array(labTokenEndpointAuthMethodSchema).min(1).max(3),
    requiredScopes: z.array(z.string().regex(scopePattern)).min(1).max(16),
    optionalScopes: z.array(z.string().regex(scopePattern)).max(16),
    /** Redirect URIs seeded onto the pre-registered manual client (for example the shared Den callback). */
    preRegisteredRedirectUris: z.array(z.string().min(1).max(2_048)).max(10).optional(),
    registrationLifetimeSeconds: z.number().int().min(60).max(86_400).optional(),
    refresh: z.object({
      advertised: z.boolean(),
      issueRefreshToken: z.boolean(),
      rotate: z.boolean(),
      omitReplacementOnRefresh: z.boolean(),
    }),
    authorizationResponseIssuer: labAuthorizationResponseIssuerSchema,
  }),
  /** At most one connection-breaking fault so the first failing phase stays deterministic. */
  fault: labActiveFaultSchema.nullable(),
  lifetimeSeconds: z.number().int().min(300).max(86_400),
})

export type McpLabScenarioV2 = DeepReadonly<z.infer<typeof rawLabScenarioSchema>>

function uniqueStrings(values: readonly string[]): boolean {
  return new Set(values).size === values.length
}

export const labScenarioV2Schema = rawLabScenarioSchema
  .superRefine((scenario, context) => {
    const allowedVersions: readonly string[] =
      scenario.protocol.mode === "stable-session"
        ? stableProtocolVersions
        : scenario.protocol.mode === "stateless-draft"
          ? draftProtocolVersions
          : legacyProtocolVersions
    for (const [index, version] of scenario.protocol.versions.entries()) {
      if (!allowedVersions.includes(version)) {
        context.addIssue({
          code: "custom",
          message: `Version '${version}' is not valid for protocol mode '${scenario.protocol.mode}'`,
          path: ["protocol", "versions", index],
        })
      }
    }
    if (!uniqueStrings(scenario.protocol.versions)) {
      context.addIssue({ code: "custom", message: "Protocol versions must be unique", path: ["protocol", "versions"] })
    }
    if (scenario.protocol.mode === "legacy-sse" && scenario.protocol.responseMode !== "sse") {
      context.addIssue({ code: "custom", message: "Legacy HTTP+SSE requires the SSE response mode", path: ["protocol", "responseMode"] })
    }
    if (scenario.protocol.mode === "stateless-draft" && scenario.protocol.responseMode !== "json") {
      context.addIssue({ code: "custom", message: "The draft stateless engine responds with JSON only", path: ["protocol", "responseMode"] })
    }

    if (
      scenario.authentication.mode === "oauth" &&
      scenario.authentication.registration === "pre_registered" &&
      (scenario.authentication.preRegisteredRedirectUris?.length ?? 0) === 0
    ) {
      context.addIssue({
        code: "custom",
        message: "Pre-registered scenarios must configure at least one manual-client redirect URI",
        path: ["authentication", "preRegisteredRedirectUris"],
      })
    }

    const issuerPaths = scenario.authentication.authorizationServers.map((server) => server.issuerPath)
    if (!uniqueStrings(issuerPaths)) {
      context.addIssue({
        code: "custom",
        message: "Authorization server issuer paths must be unique",
        path: ["authentication", "authorizationServers"],
      })
    }
    if (!uniqueStrings(scenario.authentication.tokenEndpointAuthMethods)) {
      context.addIssue({
        code: "custom",
        message: "Token endpoint auth methods must be unique",
        path: ["authentication", "tokenEndpointAuthMethods"],
      })
    }
    if (!uniqueStrings(scenario.authentication.applicationTypes)) {
      context.addIssue({ code: "custom", message: "Application types must be unique", path: ["authentication", "applicationTypes"] })
    }
    if (!uniqueStrings([...scenario.authentication.requiredScopes, ...scenario.authentication.optionalScopes])) {
      context.addIssue({
        code: "custom",
        message: "Required and optional scopes must not overlap or repeat",
        path: ["authentication", "optionalScopes"],
      })
    }

    const registration = scenario.authentication.registration
    const servers = scenario.authentication.authorizationServers
    if (registration === "dynamic" && !servers.some((server) => server.registrationEndpointEnabled)) {
      context.addIssue({
        code: "custom",
        message: "Dynamic registration requires at least one authorization server with a registration endpoint",
        path: ["authentication", "registration"],
      })
    }
    if (registration === "client_metadata" && !servers.some((server) => server.clientIdMetadataDocumentSupported)) {
      context.addIssue({
        code: "custom",
        message: "Client metadata registration requires at least one CIMD-capable authorization server",
        path: ["authentication", "registration"],
      })
    }
    if (
      registration === "none_available" &&
      servers.some((server) => server.registrationEndpointEnabled || server.clientIdMetadataDocumentSupported)
    ) {
      context.addIssue({
        code: "custom",
        message: "A none_available scenario must not advertise registration or CIMD support",
        path: ["authentication", "authorizationServers"],
      })
    }

    const refresh = scenario.authentication.refresh
    if ((refresh.rotate || refresh.omitReplacementOnRefresh) && !refresh.issueRefreshToken) {
      context.addIssue({
        code: "custom",
        message: "Refresh rotation or omission requires refresh tokens to be issued",
        path: ["authentication", "refresh"],
      })
    }
    if (refresh.rotate && refresh.omitReplacementOnRefresh) {
      context.addIssue({
        code: "custom",
        message: "Rotating while omitting the replacement would strand the client; choose one behavior",
        path: ["authentication", "refresh", "omitReplacementOnRefresh"],
      })
    }

    if (scenario.fault) {
      const definition = getLabFaultDefinition(scenario.fault.id)
      if (definition.requiresProtocolMode && definition.requiresProtocolMode !== scenario.protocol.mode) {
        context.addIssue({
          code: "custom",
          message: `Fault '${scenario.fault.id}' requires protocol mode '${definition.requiresProtocolMode}'`,
          path: ["fault", "id"],
        })
      }
      if (definition.requiresOAuth && scenario.authentication.mode !== "oauth") {
        context.addIssue({
          code: "custom",
          message: `Fault '${scenario.fault.id}' requires OAuth authentication`,
          path: ["fault", "id"],
        })
      }
    }
  })
  .transform((scenario): McpLabScenarioV2 => deepFreeze(scenario) as McpLabScenarioV2)

export function parseLabScenario(value: unknown): McpLabScenarioV2 {
  return labScenarioV2Schema.parse(value)
}

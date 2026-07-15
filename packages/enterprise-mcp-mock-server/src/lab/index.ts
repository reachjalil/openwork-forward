/**
 * OAuth/MCP conformance lab core.
 *
 * One canonical protocol engine (`core` semantics: no IncomingMessage,
 * ServerResponse, Next.js, or Redis dependency) plus a Node loopback adapter
 * and a Fetch adapter. Hosted Diagnostics supplies a Redis-backed store; local
 * development and CI use the in-memory store.
 */

export {
  labScenarioV2Schema,
  parseLabScenario,
  labProfileIdSchema,
  labActiveFaultSchema,
  labProtocolModeSchema,
  labDiscoverySchema,
  labRegistrationSchema,
  labAuthenticationModeSchema,
  labApplicationTypeSchema,
  labTokenEndpointAuthMethodSchema,
  labAuthorizationResponseIssuerSchema,
  stableProtocolVersions,
  draftProtocolVersions,
  legacyProtocolVersions,
  type McpLabScenarioV2,
  type LabProfileId,
  type LabActiveFault,
} from "./contracts/scenario.js"
export {
  listLabScenarioPresets,
  getLabScenarioPreset,
  type LabScenarioPreset,
  type LabScenarioPresetId,
} from "./contracts/presets.js"
export type {
  LabEnvironment,
  LabEnvironmentUpdate,
  LabOAuthClientRecord,
  LabAuthorizationCodeRecord,
  LabAccessTokenRecord,
  LabRefreshTokenRecord,
  LabSessionRecord,
  LabPendingAuthorizationRecord,
  LabCimdDocumentRecord,
  LabTraceEvent,
  LabApplicationType,
  LabClientSource,
  LabTokenEndpointAuthMethod,
} from "./contracts/environment.js"
export { labFaultIdSchema, getLabFaultDefinition, listLabFaultDefinitions, type LabFaultDefinition, type LabFaultId } from "./faults/catalog.js"
export {
  LabEnvironmentAlreadyExistsError,
  LabEnvironmentNotFoundError,
  LabEnvironmentRevisionConflictError,
  type LabRefreshRotationResult,
  type McpLabStore,
} from "./store/contract.js"
export { InMemoryMcpLabStore } from "./store/memory-store.js"
export { resolveLabIdentity, labIdentityFor, type LabIdentity, type ResolvedLabIssuer } from "./identity.js"
export {
  assertSafeCimdUrl,
  resolveClientMetadataDocument,
  createDefaultCimdFetcher,
  defaultCimdPolicy,
  type CimdFetcher,
  type CimdFetchResult,
  type CimdPolicy,
  type CimdResolution,
  type CimdUrlVerdict,
} from "./oauth/cimd.js"
export { validateLabRedirectUri, type LabRedirectVerdict } from "./oauth/redirects.js"
export {
  buildAuthorizationServerMetadata,
  buildProtectedResourceMetadata,
  labAccessTokenLifetimeSeconds,
  labAuthorizationCodeLifetimeSeconds,
  labPendingAuthorizationLifetimeSeconds,
  labSyntheticSubject,
} from "./oauth/authority.js"
export { labToolCatalog, syntheticToolResult, type LabTool } from "./mcp/tools.js"
export { draftReleaseCandidateVersion } from "./mcp/draft-engine.js"
export { defaultLabRuntimeEnvironment, sha256Hex, type LabRuntimeEnvironment, type LabTracer, type LabTraceInput } from "./trace.js"
export {
  createMcpLabEngine,
  LabReleaseCandidateDisabledError,
  type CreateMcpLabEngineOptions,
  type CreateLabEnvironmentOptions,
  type CreatedLabEnvironment,
  type McpLabEngine,
} from "./engine.js"
export {
  labJson,
  labSse,
  labHtml,
  labRedirect,
  labEmpty,
  labOAuthError,
  maximumLabRequestBytes,
  type LabHttpRequest,
  type LabHttpResponse,
} from "./http.js"
export { createLabFetchHandler, type LabFetchHandler } from "./adapters/fetch.js"
export { createLabNodeServer, type CreateLabNodeServerOptions, type LabNodeServer } from "./adapters/node.js"

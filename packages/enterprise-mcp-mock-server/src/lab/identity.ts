import type { LabEnvironment } from "./contracts/environment.js"
import type { McpLabScenarioV2 } from "./contracts/scenario.js"

/**
 * Deterministic URL identity for one lab environment.
 *
 * Every environment owns an MCP resource, protected-resource metadata, and
 * one issuer per configured authorization server:
 *
 *   MCP resource   {origin}/lab/{id}/mcp
 *   PRM            {origin}/.well-known/oauth-protected-resource/lab/{id}/mcp
 *   Issuer         {origin}/lab/{id}{issuerPath}
 *   RFC 8414       {origin}/.well-known/oauth-authorization-server/lab/{id}{issuerPath}
 *   OIDC           {origin}/.well-known/openid-configuration/lab/{id}{issuerPath}
 */

export interface ResolvedLabIssuer {
  readonly path: string
  readonly issuerUrl: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  readonly registrationEndpoint: string
  readonly revocationEndpoint: string
  readonly consentEndpoint: string
  readonly clientIdMetadataDocumentSupported: boolean
  readonly registrationEndpointEnabled: boolean
}

export interface LabIdentity {
  readonly origin: string
  readonly environmentId: string
  readonly basePath: string
  readonly mcpPath: string
  readonly mcpUrl: string
  readonly protectedResourceMetadataPath: string
  readonly protectedResourceMetadataUrl: string
  readonly issuers: readonly ResolvedLabIssuer[]
}

export function resolveLabIdentity(origin: string, environmentId: string, scenario: McpLabScenarioV2): LabIdentity {
  const basePath = `/lab/${environmentId}`
  const mcpPath = `${basePath}/mcp`
  const protectedResourceMetadataPath = `/.well-known/oauth-protected-resource${mcpPath}`
  return {
    origin,
    environmentId,
    basePath,
    mcpPath,
    mcpUrl: `${origin}${mcpPath}`,
    protectedResourceMetadataPath,
    protectedResourceMetadataUrl: `${origin}${protectedResourceMetadataPath}`,
    issuers: scenario.authentication.authorizationServers.map((server) => {
      const issuerPath = `${basePath}${server.issuerPath}`
      const issuerUrl = `${origin}${issuerPath}`
      return {
        path: server.issuerPath,
        issuerUrl,
        authorizationEndpoint: `${issuerUrl}/authorize`,
        tokenEndpoint: `${issuerUrl}/token`,
        registrationEndpoint: `${issuerUrl}/register`,
        revocationEndpoint: `${issuerUrl}/revoke`,
        consentEndpoint: `${issuerUrl}/consent`,
        clientIdMetadataDocumentSupported: server.clientIdMetadataDocumentSupported,
        registrationEndpointEnabled: server.registrationEndpointEnabled,
      }
    }),
  }
}

export function labIdentityFor(origin: string, environment: LabEnvironment): LabIdentity {
  return resolveLabIdentity(origin, environment.id, environment.scenario)
}

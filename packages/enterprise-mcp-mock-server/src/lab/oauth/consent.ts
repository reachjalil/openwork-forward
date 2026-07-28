import { escapeHtml, labHtml, type LabHttpResponse } from "../http.js"

export interface ConsentScreenModel {
  readonly consentEndpoint: string
  readonly requestId: string
  readonly clientDisplayName: string
  readonly callbackHostname: string
  readonly resource: string
  readonly scopes: readonly string[]
  /** Echoed through the form so the authority never stores the client's OAuth state. */
  readonly state: string | null
}

/**
 * A real synthetic consent screen: it names the client, callback host,
 * resource, and scopes, and only a POSTed decision can complete the request.
 * The page is fully self-contained (strict CSP, inline styles, no scripts).
 */
export function renderConsentScreen(model: ConsentScreenModel): LabHttpResponse {
  const scopeItems = model.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join("")
  const stateField = model.state === null ? "" : `<input type="hidden" name="state" value="${escapeHtml(model.state)}">`
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Synthetic authorization — OpenWork Diagnostics Lab</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #f6f7f9; color: #1c2733; margin: 0; }
  main { max-width: 30rem; margin: 3rem auto; background: #fff; border: 1px solid #d7dde3; border-radius: 0.75rem; padding: 2rem; }
  .banner { background: #fff7e6; border: 1px solid #e6c26e; border-radius: 0.5rem; padding: 0.75rem; font-size: 0.85rem; margin-bottom: 1.5rem; }
  dt { font-weight: 600; margin-top: 0.75rem; }
  dd { margin: 0.15rem 0 0; overflow-wrap: anywhere; }
  ul { margin: 0.25rem 0 0; padding-left: 1.25rem; }
  .actions { display: flex; gap: 0.75rem; margin-top: 1.75rem; }
  button { flex: 1; padding: 0.65rem 1rem; border-radius: 0.5rem; border: 1px solid transparent; font-size: 1rem; cursor: pointer; }
  .approve { background: #14532d; color: #fff; }
  .deny { background: #fff; color: #7f1d1d; border-color: #b91c1c; }
</style>
</head>
<body>
<main>
  <h1>Authorize synthetic access?</h1>
  <p class="banner">OpenWork Diagnostics Lab. This is a synthetic authorization server for conformance testing.
  No real identity, account, or provider data is involved.</p>
  <dl>
    <dt>Client</dt><dd>${escapeHtml(model.clientDisplayName)}</dd>
    <dt>Redirects back to</dt><dd>${escapeHtml(model.callbackHostname)}</dd>
    <dt>MCP resource</dt><dd>${escapeHtml(model.resource)}</dd>
    <dt>Requested scopes</dt><dd><ul>${scopeItems}</ul></dd>
  </dl>
  <form method="post" action="${escapeHtml(model.consentEndpoint)}">
    <input type="hidden" name="request_id" value="${escapeHtml(model.requestId)}">
    ${stateField}
    <div class="actions">
      <button class="approve" type="submit" name="decision" value="approve">Approve</button>
      <button class="deny" type="submit" name="decision" value="deny">Deny</button>
    </div>
  </form>
</main>
</body>
</html>`
  return labHtml(200, html)
}

export function renderConsentError(status: number, title: string, detail: string): LabHttpResponse {
  const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>${escapeHtml(title)}</title>
<style>body{font-family:ui-sans-serif,system-ui,sans-serif;background:#f6f7f9;color:#1c2733;margin:0}main{max-width:30rem;margin:3rem auto;background:#fff;border:1px solid #d7dde3;border-radius:.75rem;padding:2rem}</style>
</head>
<body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(detail)}</p></main></body>
</html>`
  return labHtml(status, html)
}

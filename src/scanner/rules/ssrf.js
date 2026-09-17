/**
 * A10 - Server-Side Request Forgery Rules
 *
 * RETIRED FROM ACTIVE BROWSER SCANNING (Phase 01)
 *
 * SSRF (Server-Side Request Forgery) is a server-side vulnerability where
 * a server makes outbound HTTP requests to internal resources on behalf of
 * an attacker. It requires server execution context.
 *
 * JSentinel scans browser-side JavaScript. A browser making fetch(url)
 * or axios.get(url) is a normal client HTTP call, not SSRF. Flagging these
 * as SSRF produced false positives that mislabeled every dynamic API call
 * as a server-side attack vector.
 *
 * The rule ID and guidance entry are retained so that historical scan
 * results that reference OWASP-A10-001 can still resolve guidance.
 */

export const ssrfRules = [];

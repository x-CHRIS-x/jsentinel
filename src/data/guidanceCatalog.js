/**
 * JSentinel Canonical Guidance Catalog (ESM Target)
 * 
 * Centralized remediation guidance catalog covering all 27 OWASP Top 10:2021 rules
 * and 5 multi-scenario variants. Provides educational rationale, risk analysis,
 * static analyzer limitations, conditional remediation approaches, and verification checklists.
 * 
 * Strict safety rules:
 * - Zero replacementCode, goodSnippet, bad, or deterministic flags.
 * - Max 2 conditional approaches per entry.
 * - Non-prescriptive, guidance-only advice.
 */

export const GUIDANCE_DISCLAIMER =
  "Guidance only — not a drop-in replacement. Choose an approach that preserves your code's intended behavior.";

export const EDUCATIONAL_DISCLAIMER = GUIDANCE_DISCLAIMER;

export const FALLBACK_GUIDANCE = {
  guidanceId: 'UNKNOWN',
  ruleId: 'UNKNOWN',
  variant: null,
  title: 'Security Review Recommendation',
  category: 'General Security Practice',
  categoryUrl: 'https://owasp.org/',
  shortAction: 'Review the flagged code against project security requirements.',
  recommendedAction: 'Review the flagged code against project security requirements.',
  summary: 'Review the flagged code against project security requirements.',
  risk: 'Static analysis flagged an unclassified code pattern that may warrant security review.',
  cannotInfer: 'JSentinel cannot determine application intent, runtime context, or environmental security controls.',
  scope: 'cross-boundary',
  approaches: [
    'Architecture Review: Review code behavior with development and security team members to ensure safe handling.',
    'Defensive Controls: Apply least-privilege principles and input validation tailored to the application architecture.'
  ],
  verifySteps: [
    'Verify that the flagged pattern adheres to application security policies.',
    'Test edge cases and unexpected inputs in automated test suites.'
  ],
  references: [
    {
      title: 'OWASP Top 10 Security Risks',
      url: 'https://owasp.org/www-project-top-ten/'
    }
  ]
};

export const guidanceCatalog = {
  // =========================================================================
  // A01:2021 - Broken Access Control
  // =========================================================================
  'OWASP-A01-001': {
    guidanceId: 'OWASP-A01-001',
    ruleId: 'OWASP-A01-001',
    variant: null,
    title: 'Open Redirect Navigation Target',
    category: 'A01:2021-Broken Access Control',
    categoryUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    shortAction: 'Allow only configured, trusted destinations.',
    recommendedAction: 'Allow only configured, trusted destinations.',
    summary: 'Allow only configured, trusted destinations.',
    risk: 'Assigning dynamic or user-controlled input directly to window.location or location.replace() allows attackers to construct phishing links that redirect users to malicious domains while appearing to originate from the trusted application.',
    cannotInfer: 'JSentinel cannot determine valid application routes, allowed external hosts, backend redirect policies, or intended navigation flows from static syntax alone.',
    scope: 'browser',
    approaches: [
      'Relative Route Navigation: Restrict navigation strictly to internal relative paths (e.g. paths beginning with a single forward slash "/" and not "//") to reject external scheme or host prefixes.',
      'Allowlist Destination Matching: Validate destination URLs against an explicit allowlist of authorized hostnames and protocols before triggering navigation.'
    ],
    verifySteps: [
      'Test navigation with external targets (e.g. https://malicious.example.com) to confirm the application blocks redirection.',
      'Test protocol-relative URLs (e.g. //malicious.example.com) and encoded bypass strings (e.g. %2f%2f) to verify rejection.',
      'Verify that valid internal relative application routes navigate correctly.'
    ],
    references: [
      { title: 'OWASP A01:2021 – Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { title: 'OWASP Unvalidated Redirects and Forwards Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'window.location.href = userProvidedRedirectUrl;'
  },

  'OWASP-A01-002': {
    guidanceId: 'OWASP-A01-002',
    ruleId: 'OWASP-A01-002',
    variant: null,
    title: 'Client-Side Role Authorization Guard',
    category: 'A01:2021-Broken Access Control',
    categoryUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    shortAction: 'Enforce authorization for every protected action on the server or API layer.',
    recommendedAction: 'Enforce authorization for every protected action on the server or API layer.',
    summary: 'Enforce authorization for every protected action on the server or API layer.',
    risk: 'Client-side role and permission checks control only visual presentation. Attackers can modify local JavaScript variables or DOM state using browser developer tools to bypass UI gates and invoke privileged application endpoints.',
    cannotInfer: 'JSentinel cannot inspect backend permission matrices, session token claims, API gateway policies, or server-side authorization middleware.',
    scope: 'cross-boundary',
    approaches: [
      'Server-Side Authorization Enforcement: Enforce permission checks and role verification on every API endpoint handling sensitive operations or data.',
      'Defensive UI Presentation: Use client role state solely for UI rendering decisions while treating all backend responses as the authoritative source of truth.'
    ],
    verifySteps: [
      'Send direct HTTP requests to protected endpoints without admin credentials to verify the server returns 401/403 status codes.',
      'Attempt parameter tampering in browser developer tools to confirm the server enforces authorization independently of UI state.',
      'Verify that unprivileged users cannot execute administrative operations through direct API calls.'
    ],
    references: [
      { title: 'OWASP A01:2021 – Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { title: 'OWASP Authorization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html' }
    ],
    illustrativePattern: "if (userData.role === 'admin') { performPrivilegedAction(); }"
  },

  // =========================================================================
  // A02:2021 - Cryptographic Failures
  // =========================================================================
  'OWASP-A02-001': {
    guidanceId: 'OWASP-A02-001',
    ruleId: 'OWASP-A02-001',
    variant: null,
    title: 'Hardcoded Credentials in Source Code',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Revoke or rotate exposed credentials and move real secrets to a server-side secret store.',
    recommendedAction: 'Revoke or rotate exposed credentials and move real secrets to a server-side secret store.',
    summary: 'Revoke or rotate exposed credentials and move real secrets to a server-side secret store.',
    risk: 'Hardcoded passwords and secrets in source code are visible to anyone with repository read access and remain stored in Git commit history even after code edits.',
    cannotInfer: 'JSentinel cannot determine whether the hardcoded string is an active production secret, an expired key, or a mock value in a local test fixture.',
    scope: 'server',
    approaches: [
      'Environment Variable Configuration: Inject credentials at server startup from environment variables or a key vault service rather than embedding them in code.',
      'Secret Manager Integration: Retrieve sensitive secrets dynamically from a dedicated secrets management service at server runtime.'
    ],
    verifySteps: [
      'Revoke and rotate any credentials that were committed to source control.',
      'Verify that historical Git commits and pull request records no longer expose the secret.',
      'Confirm that the application loads credentials correctly from environment configuration or secret vaults.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'const dbPassword = "super_secret_password_123";'
  },

  'OWASP-A02-002': {
    guidanceId: 'OWASP-A02-002',
    ruleId: 'OWASP-A02-002',
    variant: null,
    title: 'Insecure Cookie Configuration',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Have the server issue the session cookie with the appropriate secure attributes.',
    recommendedAction: 'Have the server issue the session cookie with the appropriate secure attributes.',
    summary: 'Have the server issue the session cookie with the appropriate secure attributes.',
    risk: 'Cookies set without the HttpOnly attribute can be read and stolen by client-side scripts during XSS attacks. Cookies lacking the Secure attribute can be intercepted in transit over unencrypted connections.',
    cannotInfer: 'JSentinel cannot inspect server response headers; client-side JavaScript running in the browser cannot create or attach the HttpOnly attribute to cookies.',
    scope: 'cross-boundary',
    approaches: [
      'Server-Side Set-Cookie Header: Configure the backend server or API to issue session cookies via the Set-Cookie HTTP header with Secure, HttpOnly, and SameSite flags.',
      'Session Framework Cookie Policy: Define cookie security settings globally in backend session management middleware.'
    ],
    verifySteps: [
      'Inspect HTTP response headers in browser developer tools to verify the Set-Cookie header includes HttpOnly, Secure, and SameSite directives.',
      'Execute document.cookie in browser console to confirm session cookies are not readable by client-side JavaScript.',
      'Test cross-origin requests to verify SameSite policy enforces intended cookie isolation.'
    ],
    references: [
      { title: 'MDN Set-Cookie Header Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie' },
      { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'document.cookie = "sessionId=" + token;'
  },

  'OWASP-A02-003': {
    guidanceId: 'OWASP-A02-003',
    ruleId: 'OWASP-A02-003',
    variant: null,
    title: 'Insecure Pseudo-Random Number Generator',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Use a cryptographically strong generator appropriate to the token\'s security purpose.',
    recommendedAction: 'Use a cryptographically strong generator appropriate to the token\'s security purpose.',
    summary: 'Use a cryptographically strong generator appropriate to the token\'s security purpose.',
    risk: 'Math.random() is a deterministic pseudo-random number generator designed for speed, not cryptographic entropy. Attackers can observe sequences of generated numbers to predict future values, compromising generated tokens or identifiers.',
    cannotInfer: 'JSentinel cannot determine whether the generated value is used for security-critical functions (such as tokens or nonces) or non-security purposes (such as UI animation or layout).',
    scope: 'browser',
    approaches: [
      'Web Crypto API (Client): Use window.crypto.getRandomValues() or crypto.randomUUID() in browser contexts requiring cryptographically secure random data.',
      'Node.js Crypto Module (Server): Use the Node.js crypto module for server-side cryptographically secure random bytes or UUID generation.'
    ],
    verifySteps: [
      'Confirm that non-security random generation (e.g. UI layout) does not require cryptographic guarantees.',
      'Verify that security tokens, nonces, and session identifiers use cryptographically secure APIs in HTTPS secure contexts.',
      'Confirm random values exhibit sufficient entropy and length for their intended purpose.'
    ],
    references: [
      { title: 'MDN Web Crypto API', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Window/crypto' },
      { title: 'OWASP Cryptographic Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'const token = Math.random().toString(36).substring(2);'
  },

  'OWASP-A02-004': {
    guidanceId: 'OWASP-A02-004',
    ruleId: 'OWASP-A02-004',
    variant: null,
    title: 'Plaintext HTTP Endpoint Communication',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Migrate only to a TLS endpoint that the service actually supports.',
    recommendedAction: 'Migrate only to a TLS endpoint that the service actually supports.',
    summary: 'Migrate only to a TLS endpoint that the service actually supports.',
    risk: 'Unencrypted HTTP traffic transmits data in plaintext over the network. Intermediaries such as network proxies, rogue Wi-Fi access points, and ISPs can inspect or modify payloads in transit.',
    cannotInfer: 'JSentinel cannot determine whether the remote host supports TLS, possesses a valid certificate, or requires specific port routing.',
    scope: 'cross-boundary',
    approaches: [
      'HTTPS Endpoint Migration: Update target service endpoints to HTTPS URLs after verifying valid SSL/TLS certificate configuration on the destination server.',
      'Environment-Driven Endpoint Configuration: Define API endpoint URLs in environment configuration to manage TLS hosts across staging and production environments.'
    ],
    verifySteps: [
      'Send a test request over HTTPS to verify that the remote service responds with a valid TLS certificate.',
      'Verify that the browser console reports no mixed content warnings when making network requests.',
      'Confirm automated redirects from HTTP to HTTPS are enforced on the server where applicable.'
    ],
    references: [
      { title: 'OWASP Transport Layer Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
      { title: 'MDN HTTPS Security', url: 'https://developer.mozilla.org/en-US/docs/Glossary/HTTPS' }
    ],
    illustrativePattern: "fetch('http://api.internal.service/auth');"
  },

  'OWASP-A02-005': {
    guidanceId: 'OWASP-A02-005',
    ruleId: 'OWASP-A02-005',
    variant: null,
    title: 'Hardcoded Secret Patterns',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    recommendedAction: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    summary: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    risk: 'Hardcoded secret patterns (such as JWT tokens, API keys, or infrastructure IPs) embedded in source code are committed to repositories and exposed in client bundles.',
    cannotInfer: 'JSentinel cannot determine whether the matched literal is an active production credential, a private network address, or dummy test data.',
    scope: 'server',
    approaches: [
      'Environment Variable Management: Extract sensitive secrets and endpoint configuration into server environment variables or a secrets manager.',
      'Secret Rotation and Revocation: Rotate exposed credentials in the provider dashboard and purge committed values from repository history.'
    ],
    verifySteps: [
      'Rotate any exposed credentials with the issuing provider.',
      'Verify that secrets are absent from version control commit history.',
      'Confirm the application loads secrets from runtime configuration.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'Vite Environment Variables & Modes', url: 'https://vite.dev/guide/env-and-mode' }
    ],
    illustrativePattern: 'const secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";'
  },

  'OWASP-A02-005:credential': {
    guidanceId: 'OWASP-A02-005:credential',
    ruleId: 'OWASP-A02-005',
    variant: 'credential',
    title: 'Hardcoded Credential or Token',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    recommendedAction: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    summary: 'Revoke, rotate, and move genuine secrets out of source and client bundles.',
    risk: 'Authentication tokens, JWTs, and cloud provider access keys embedded in source code grant unauthorized access to services and data if exposed in repositories or client bundles.',
    cannotInfer: 'JSentinel cannot determine if the detected token is an active credential or a test mock; client-side environment variables prefixed for Vite or Webpack are bundled into public client assets and are not secret.',
    scope: 'server',
    approaches: [
      'Server Secret Storage: Store production access keys and signing secrets in server environment variables or secret vaults, never in client-facing bundles.',
      'Backend Token Issuance: Generate and sign authorization tokens dynamically on backend servers rather than hardcoding static tokens.'
    ],
    verifySteps: [
      'Revoke exposed tokens or cloud keys in the corresponding provider management console.',
      'Inspect build output and source history to confirm secrets are not bundled into public client files.',
      'Verify runtime application authentication functions correctly with newly rotated credentials.'
    ],
    references: [
      { title: 'OWASP Secrets Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html' },
      { title: 'Vite Environment Variables & Modes', url: 'https://vite.dev/guide/env-and-mode' }
    ],
    illustrativePattern: 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";'
  },

  'OWASP-A02-005:network-address': {
    guidanceId: 'OWASP-A02-005:network-address',
    ruleId: 'OWASP-A02-005',
    variant: 'network-address',
    title: 'Static Network IP Address Literal',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Review whether the endpoint address is sensitive configuration before changing it.',
    recommendedAction: 'Review whether the endpoint address is sensitive configuration before changing it.',
    summary: 'Review whether the endpoint address is sensitive configuration before changing it.',
    risk: 'Hardcoded IP addresses may reveal internal network topology, staging infrastructure, or private subnets. Static IPs also create operational fragility when network configurations change.',
    cannotInfer: 'JSentinel cannot determine network topology, access controls, routing policies, or whether the IP represents an internal private service versus a public endpoint.',
    scope: 'cross-boundary',
    approaches: [
      'Domain Name and DNS Configuration: Use DNS domain names with TLS instead of literal IP addresses to support certificate verification and dynamic routing.',
      'Externalized Network Configuration: Extract host addresses into deployment environment variables to allow per-environment configuration.'
    ],
    verifySteps: [
      'Review whether the hardcoded address points to an internal private subnet or sensitive server.',
      'Verify that communication with the endpoint is authenticated and encrypted.',
      'Test endpoint resolution across staging and production environments.'
    ],
    references: [
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
      { title: 'RFC 1918 Private Address Allocation', url: 'https://datatracker.ietf.org/doc/html/rfc1918' }
    ],
    illustrativePattern: 'const serviceIp = "192.168.1.100";'
  },

  'OWASP-A02-006': {
    guidanceId: 'OWASP-A02-006',
    ruleId: 'OWASP-A02-006',
    variant: null,
    title: 'Exposed API Key in Variable Declaration',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Determine whether the key is public/restricted or secret, then protect and rotate it accordingly.',
    recommendedAction: 'Determine whether the key is public/restricted or secret, then protect and rotate it accordingly.',
    summary: 'Determine whether the key is public/restricted or secret, then protect and rotate it accordingly.',
    risk: 'Hardcoding API keys in variable declarations risks exposing privileged access to third-party services. If shipped in client bundles, keys can be extracted and abused by unauthorized parties.',
    cannotInfer: 'JSentinel cannot determine API key permission scopes, provider rate limits, domain restrictions, or backend proxy architectures.',
    scope: 'cross-boundary',
    approaches: [
      'Backend Proxy Architecture: Route third-party API calls through a backend proxy service that securely holds the privileged API key away from client code.',
      'Restricted Client Keys: For keys that must reside on clients (e.g. mapping services), apply strict HTTP referrer and API rate restrictions in the provider console.'
    ],
    verifySteps: [
      'Verify that no privileged API secrets are included in client build bundles.',
      'Confirm public keys configured for client applications have domain restrictions and minimal required scopes.',
      'Test that backend proxy routes authenticate client requests before forwarding to third-party APIs.'
    ],
    references: [
      { title: 'OWASP Key Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html' },
      { title: 'OWASP A02:2021 – Cryptographic Failures', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' }
    ],
    illustrativePattern: 'const apiKey = "sec_key_xyz123456789abc";'
  },

  'OWASP-A02-007': {
    guidanceId: 'OWASP-A02-007',
    ruleId: 'OWASP-A02-007',
    variant: null,
    title: 'Sensitive Credentials in URL Query String',
    category: 'A02:2021-Cryptographic Failures',
    categoryUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    shortAction: 'Remove credentials from URLs and use the protocol\'s secure body/header mechanism over TLS.',
    recommendedAction: 'Remove credentials from URLs and use the protocol\'s secure body/header mechanism over TLS.',
    summary: 'Remove credentials from URLs and use the protocol\'s secure body/header mechanism over TLS.',
    risk: 'URL query parameters are recorded in plain text in browser history, web server access logs, network proxy caches, and HTTP Referer headers sent to external links.',
    cannotInfer: 'JSentinel cannot modify backend routing parameter contracts or determine whether an external API mandates query parameter authentication.',
    scope: 'cross-boundary',
    approaches: [
      'Authorization Header Transmission: Send credentials and bearer tokens via standard HTTP Authorization headers over HTTPS.',
      'HTTP Request Body Transmission: Transmit sensitive authentication payloads (such as passwords) within POST request bodies over HTTPS.'
    ],
    verifySteps: [
      'Inspect outgoing HTTP requests to verify sensitive credentials do not appear in the URL query string.',
      'Check server access logs and browser history to confirm passwords and tokens are not logged in URL paths.',
      'Verify that authentication endpoints accept credentials via request headers or body over HTTPS.'
    ],
    references: [
      { title: 'OWASP REST Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html' },
      { title: 'RFC 6750 Bearer Token Usage', url: 'https://datatracker.ietf.org/doc/html/rfc6750' }
    ],
    illustrativePattern: "const url = '/api/login?password=' + encodeURIComponent(userPassword);"
  },

  // =========================================================================
  // A03:2021 - Injection
  // =========================================================================
  'OWASP-A03-001': {
    guidanceId: 'OWASP-A03-001',
    ruleId: 'OWASP-A03-001',
    variant: null,
    title: 'Dynamic Code Evaluation (eval)',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Remove dynamic evaluation and choose a parser or fixed behavior that matches the intended input format.',
    recommendedAction: 'Remove dynamic evaluation and choose a parser or fixed behavior that matches the intended input format.',
    summary: 'Remove dynamic evaluation and choose a parser or fixed behavior that matches the intended input format.',
    risk: 'The eval() function executes arbitrary strings with full privileges in the calling context. If input contains unvalidated user data, attackers can execute malicious JavaScript to steal session tokens, alter application state, or compromise the client.',
    cannotInfer: 'JSentinel cannot determine the schema, intended format, or mathematical purpose of the dynamically evaluated expression.',
    scope: 'browser',
    approaches: [
      'Structured Data Deserialization: Use JSON.parse() when the input represents structured JSON data rather than executable JavaScript code.',
      'Static Dispatch or Dedicated Evaluator: Replace dynamic code execution with an object mapping or a dedicated, sandboxed mathematical expression parser.'
    ],
    verifySteps: [
      'Test input with malicious JavaScript payloads (e.g. alert(1) or process.exit()) to verify code does not execute.',
      'Test malformed and invalid inputs to confirm the parser handles errors safely without crashing.',
      'Verify intended data processing continues to work correctly under the safe parsing implementation.'
    ],
    references: [
      { title: 'MDN eval() Reference and Security Risks', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: 'const result = eval("data." + userInputProperty);'
  },

  'OWASP-A03-002': {
    guidanceId: 'OWASP-A03-002',
    ruleId: 'OWASP-A03-002',
    variant: null,
    title: 'String Code Execution in Timers',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Replace runtime code strings with a function or closure that preserves intended arguments and timing.',
    recommendedAction: 'Replace runtime code strings with a function or closure that preserves intended arguments and timing.',
    summary: 'Replace runtime code strings with a function or closure that preserves intended arguments and timing.',
    risk: 'Passing strings to setTimeout or setInterval causes the JavaScript runtime to interpret the string via dynamic code evaluation. If any part of the string contains untrusted data, it can lead to arbitrary code execution.',
    cannotInfer: 'JSentinel cannot infer variable scoping, closure captures, execution intervals, or timing requirements of the scheduled callback.',
    scope: 'browser',
    approaches: [
      'Function Reference Callback: Pass a direct function identifier as the callback parameter to timer APIs.',
      'Arrow Function / Closure Callback: Wrap code and parameters in an arrow function closure instead of constructing executable code strings.'
    ],
    verifySteps: [
      'Verify that timer callbacks execute with expected arguments and variable scoping.',
      'Confirm no dynamic string concatenation or templating is passed into setTimeout or setInterval.',
      'Test cancellation mechanisms (clearTimeout, clearInterval) to ensure proper timer lifecycle management.'
    ],
    references: [
      { title: 'MDN setTimeout() Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/API/setTimeout' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: 'setTimeout("processUserData(\'" + userId + "\')", 1000);'
  },

  'OWASP-A03-003': {
    guidanceId: 'OWASP-A03-003',
    ruleId: 'OWASP-A03-003',
    variant: null,
    title: 'Unsafe Function Constructor Dynamic Code',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Redesign dynamic code execution into fixed functions, a restricted interpreter, or structured input.',
    recommendedAction: 'Redesign dynamic code execution into fixed functions, a restricted interpreter, or structured input.',
    summary: 'Redesign dynamic code execution into fixed functions, a restricted interpreter, or structured input.',
    risk: 'The Function constructor compiles and executes strings as code in the global scope. If any portion of the constructor arguments is influenced by user input, attackers can execute arbitrary code.',
    cannotInfer: 'JSentinel cannot determine the mini-language, mathematical formula, or business rules intended by the dynamic Function construction.',
    scope: 'browser',
    approaches: [
      'Predefined Function Map: Map allowed operation identifiers to static functions using an allowlisted dictionary.',
      'Structured Expression Parser: Use a dedicated, sandboxed AST expression parser for user-defined mathematical or logical formulas.'
    ],
    verifySteps: [
      'Verify that arbitrary JavaScript statements cannot execute through user-supplied formula inputs.',
      'Test with non-standard characters and operators to confirm parsing constraints are enforced.',
      'Confirm supported operations produce valid calculations without code generation.'
    ],
    references: [
      { title: 'MDN Function Constructor Security Considerations', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: "const dynamicFn = new Function('a', 'b', 'return ' + userExpression);"
  },

  'OWASP-A03-004': {
    guidanceId: 'OWASP-A03-004',
    ruleId: 'OWASP-A03-004',
    variant: null,
    title: 'Dynamic innerHTML Template Literal',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Use DOM/text rendering when markup is unnecessary; otherwise sanitize under a defined HTML policy.',
    recommendedAction: 'Use DOM/text rendering when markup is unnecessary; otherwise sanitize under a defined HTML policy.',
    summary: 'Use DOM/text rendering when markup is unnecessary; otherwise sanitize under a defined HTML policy.',
    risk: 'Interpolating variables into innerHTML template literals allows attackers to inject malicious HTML elements and JavaScript event handlers if variables contain unescaped user input.',
    cannotInfer: 'JSentinel cannot determine whether interpolated variables contain intentional rich text markup or plain text data.',
    scope: 'browser',
    approaches: [
      'Safe DOM Text Assignment: Use textContent or DOM node creation methods when the interpolated content is plain text.',
      'HTML Sanitization Policy: Sanitize dynamic HTML template strings using a vetted library like DOMPurify before assigning to innerHTML.'
    ],
    verifySteps: [
      'Test inputs containing XSS payloads (e.g. <img src=x onerror=alert(1)>) to verify script execution is blocked.',
      'Verify that intentional rich text formatting renders correctly while dangerous elements are stripped.',
      'Confirm plain text inputs display properly without interpreting HTML tags.'
    ],
    references: [
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
      { title: 'DOMPurify Security Library', url: 'https://github.com/cure53/DOMPurify' }
    ],
    illustrativePattern: 'element.innerHTML = `<div class="user-card">${userName}</div>`;'
  },

  'OWASP-A03-005': {
    guidanceId: 'OWASP-A03-005',
    ruleId: 'OWASP-A03-005',
    variant: null,
    title: 'Function Return Assigned to innerHTML',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Trace the returned data and use safe rendering or context-appropriate sanitization.',
    recommendedAction: 'Trace the returned data and use safe rendering or context-appropriate sanitization.',
    summary: 'Trace the returned data and use safe rendering or context-appropriate sanitization.',
    risk: 'Assigning the return value of a function call directly to innerHTML is dangerous if that function processes untrusted inputs or external data without escaping.',
    cannotInfer: 'JSentinel cannot trace function return values across files or determine if the called function implements internal HTML sanitization.',
    scope: 'browser',
    approaches: [
      'Safe Text Rendering: Assign function return values to textContent when the returned data represents text content.',
      'Sanitized HTML Assignment: Pass function output through an HTML sanitizer before innerHTML insertion if the function generates intentional markup.'
    ],
    verifySteps: [
      'Trace data flows into the function to verify whether untrusted parameters can influence output.',
      'Test the function with HTML control characters and script tags to verify output is safely encoded.',
      'Verify UI rendering across browsers with malicious payload test cases.'
    ],
    references: [
      { title: 'OWASP DOM-based XSS Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: 'container.innerHTML = renderUserProfile(userData);'
  },

  'OWASP-A03-006': {
    guidanceId: 'OWASP-A03-006',
    ruleId: 'OWASP-A03-006',
    variant: null,
    title: 'Direct innerHTML Assignment',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Prefer safe text/DOM APIs unless a documented HTML policy requires markup.',
    recommendedAction: 'Prefer safe text/DOM APIs unless a documented HTML policy requires markup.',
    summary: 'Prefer safe text/DOM APIs unless a documented HTML policy requires markup.',
    risk: 'Assigning variables directly to innerHTML causes the browser to parse strings as HTML markup. If any part of the string originates from user input or external APIs, attackers can execute arbitrary scripts.',
    cannotInfer: 'JSentinel cannot determine if the assigned variable is guaranteed static or contains user-supplied data.',
    scope: 'browser',
    approaches: [
      'Text Content Assignment: Use textContent for plain text data, which avoids HTML parsing and treats all input as literal text.',
      'Explicit HTML Sanitization: Sanitize untrusted HTML markup using DOMPurify before assigning to innerHTML when rich markup is necessary.'
    ],
    verifySteps: [
      'Inject script tags and event handlers into the assigned variable to confirm they do not execute.',
      'Verify that special characters like <, >, and & display correctly without breaking layout.',
      'Confirm that safe HTML formatting elements are preserved only when explicit sanitization policies allow them.'
    ],
    references: [
      { title: 'MDN Element.innerHTML Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML' },
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'contentDiv.innerHTML = untrustedContent;'
  },

  'OWASP-A03-007': {
    guidanceId: 'OWASP-A03-007',
    ruleId: 'OWASP-A03-007',
    variant: null,
    title: 'Document Stream Injection (document.write)',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Replace the page-writing strategy according to load timing and intended output.',
    recommendedAction: 'Replace the page-writing strategy according to load timing and intended output.',
    summary: 'Replace the page-writing strategy according to load timing and intended output.',
    risk: 'document.write() writes raw markup directly into the document stream. It disables browser HTML pre-parsers, can overwrite entire page contents if called after load, and enables cross-site scripting when handling dynamic values.',
    cannotInfer: 'JSentinel cannot determine document parsing lifecycle timing, script execution order, or whether layout depends on synchronous stream insertion.',
    scope: 'browser',
    approaches: [
      'Standard DOM API Element Creation: Create and insert DOM elements using document.createElement() and appendChild().',
      'Framework Component Rendering: Render dynamic UI elements using declarative templates or component state in modern front-end frameworks.'
    ],
    verifySteps: [
      'Verify that dynamic scripts or content load asynchronously without blocking page parsing.',
      'Confirm that UI elements render into targeted container elements without calling document.write.',
      'Test page load behavior in modern browsers to confirm no console warnings regarding synchronous document writes.'
    ],
    references: [
      { title: 'MDN document.write() Reference and Deprecation Warning', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Document/write' },
      { title: 'OWASP A03:2021 – Injection', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
    ],
    illustrativePattern: "document.write('<script src=\"' + scriptUrl + '\"></script>');"
  },

  'OWASP-A03-008': {
    guidanceId: 'OWASP-A03-008',
    ruleId: 'OWASP-A03-008',
    variant: null,
    title: 'React dangerouslySetInnerHTML Property',
    category: 'A03:2021-Injection',
    categoryUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    shortAction: 'Prefer React\'s normal escaped rendering; use a vetted sanitizer only for intentional HTML.',
    recommendedAction: 'Prefer React\'s normal escaped rendering; use a vetted sanitizer only for intentional HTML.',
    summary: 'Prefer React\'s normal escaped rendering; use a vetted sanitizer only for intentional HTML.',
    risk: 'dangerouslySetInnerHTML bypasses React\'s built-in XSS protection. If the supplied __html property contains unvalidated user input, malicious code will execute in users\' browsers.',
    cannotInfer: 'JSentinel cannot determine whether the markup originates from a trusted internal source, a Markdown converter, or an unauthenticated user submission.',
    scope: 'browser',
    approaches: [
      'Standard Escaped JSX Rendering: Render content as regular React JSX children, which automatically escapes strings and prevents HTML injection.',
      'DOMPurify Sanitization in React: Sanitize untrusted HTML with DOMPurify before passing it to the __html property when rich HTML rendering is required.'
    ],
    verifySteps: [
      'Pass malicious HTML strings with event handlers (e.g. <img src=x onerror=alert(1)>) to verify scripts are stripped.',
      'Verify that permitted rich text tags (such as <b> or <i>) render as intended.',
      'Confirm that non-rich-text content uses standard React JSX expressions instead of dangerouslySetInnerHTML.'
    ],
    references: [
      { title: 'React Documentation: dangerouslySetInnerHTML', url: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html' },
      { title: 'OWASP Cross-Site Scripting (XSS) Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: '<div dangerouslySetInnerHTML={{ __html: dynamicMarkup }} />'
  },

  // =========================================================================
  // A05:2021 - Security Misconfiguration
  // =========================================================================
  'OWASP-A05-001': {
    guidanceId: 'OWASP-A05-001',
    ruleId: 'OWASP-A05-001',
    variant: null,
    title: 'Sensitive Variable Logging to Console',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'Remove or redact sensitive values before logging.',
    recommendedAction: 'Remove or redact sensitive values before logging.',
    summary: 'Remove or redact sensitive values before logging.',
    risk: 'Logging passwords, tokens, or personal data exposes sensitive information in browser developer consoles, server terminal logs, and third-party monitoring aggregation tools.',
    cannotInfer: 'JSentinel cannot determine whether log outputs are restricted to local development debugging or sent to production log aggregation platforms.',
    scope: 'cross-boundary',
    approaches: [
      'Non-Sensitive Status Logging: Log operational lifecycle indicators, timestamps, and status messages without including raw credential variables.',
      'Structured Masking / Redaction: Apply a redaction helper to mask sensitive fields before sending objects to logging pipelines.'
    ],
    verifySteps: [
      'Inspect development and production logs to verify passwords, secrets, and auth tokens are omitted.',
      'Verify that error handling blocks do not dump sensitive authentication parameters to the console.',
      'Confirm logging utilities strip or mask confidential data before forwarding to log collectors.'
    ],
    references: [
      { title: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { title: 'OWASP A05:2021 – Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
    ],
    illustrativePattern: 'console.log("User login credential: ", userPassword);'
  },

  'OWASP-A05-002': {
    guidanceId: 'OWASP-A05-002',
    ruleId: 'OWASP-A05-002',
    variant: null,
    title: 'Wildcard CORS Access-Control-Allow-Origin',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'Configure server CORS for the actual trusted origins and credential policy.',
    recommendedAction: 'Configure server CORS for the actual trusted origins and credential policy.',
    summary: 'Configure server CORS for the actual trusted origins and credential policy.',
    risk: 'Setting Access-Control-Allow-Origin to wildcard (*) allows any external domain to make cross-origin requests to the endpoint, risking data exposure for authenticated or private APIs.',
    cannotInfer: 'JSentinel cannot determine whether the API endpoint is intentionally public (such as an open data feed) or serves confidential, tenant-specific resources.',
    scope: 'server',
    approaches: [
      'Explicit Origin Safelist: Configure CORS middleware to accept requests only from designated, trusted origin domains.',
      'Per-Route CORS Policy: Apply restrictive CORS policies individually to authenticated routes while leaving truly public static assets accessible.'
    ],
    verifySteps: [
      'Send OPTIONS preflight requests with unauthorized Origin headers to verify the server rejects them.',
      'Verify that authenticated API routes return specific allowed origin headers rather than wildcard asterisks.',
      'Test cross-origin requests from authorized front-end origins to ensure legitimate traffic is accepted.'
    ],
    references: [
      { title: 'MDN Cross-Origin Resource Sharing (CORS)', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
      { title: 'OWASP HTML5 Security Cheat Sheet - CORS', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing' }
    ],
    illustrativePattern: 'response.setHeader("Access-Control-Allow-Origin", "*");'
  },

  'OWASP-A05-003': {
    guidanceId: 'OWASP-A05-003',
    ruleId: 'OWASP-A05-003',
    variant: null,
    title: 'Sensitive Object Logging (req/session/user)',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'Log an allowlisted, non-sensitive subset rather than whole request/session objects.',
    recommendedAction: 'Log an allowlisted, non-sensitive subset rather than whole request/session objects.',
    summary: 'Log an allowlisted, non-sensitive subset rather than whole request/session objects.',
    risk: 'Logging complete request, session, or user objects risks serializing sensitive nested properties (such as authorization headers, cookies, passwords, and tokens) into log streams.',
    cannotInfer: 'JSentinel cannot determine the nested property structure of complex runtime objects or the sensitivity of dynamic object keys.',
    scope: 'cross-boundary',
    approaches: [
      'Explicit Property Allowlist: Extract and log only the specific, safe properties necessary for operational diagnostics.',
      'Custom Log Serializer: Configure logging serializers (e.g. Pino or Winston serializers) to strip headers, tokens, and secret fields automatically.'
    ],
    verifySteps: [
      'Inspect server log outputs to confirm nested headers and body credentials are not written to disk or console.',
      'Verify that error logging does not serialize unredacted session structures.',
      'Confirm diagnostic log events contain only defined telemetry fields.'
    ],
    references: [
      { title: 'OWASP Logging Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html' },
      { title: 'OWASP A05:2021 – Security Misconfiguration', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
    ],
    illustrativePattern: 'console.log("Full request context: ", requestContext);'
  },

  'OWASP-A05-004': {
    guidanceId: 'OWASP-A05-004',
    ruleId: 'OWASP-A05-004',
    variant: null,
    title: 'Missing Express Security Header Middleware',
    category: 'A05:2021-Security Misconfiguration',
    categoryUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    shortAction: 'Review server response-header policy and apply the appropriate Express/server hardening.',
    recommendedAction: 'Review server response-header policy and apply the appropriate Express/server hardening.',
    summary: 'Review server response-header policy and apply the appropriate Express/server hardening.',
    risk: 'Express applications without security header middleware omit standard HTTP defense headers (such as Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, and X-Frame-Options), increasing vulnerability to clickjacking, MIME sniffing, and cross-site attacks.',
    cannotInfer: 'JSentinel cannot determine whether upstream reverse proxies, CDNs, or API gateways (e.g. Nginx, Cloudflare) already inject security headers.',
    scope: 'server',
    approaches: [
      'Express Helmet Middleware: Add the Helmet middleware package to the Express application instance to set secure default HTTP headers.',
      'Custom Security Header Configuration: Configure specific Content-Security-Policy and header directives tailored to application resource requirements.'
    ],
    verifySteps: [
      'Inspect HTTP response headers using curl -I or browser developer tools to verify headers like X-Content-Type-Options and Strict-Transport-Security are present.',
      'Verify that Content-Security-Policy directives do not block legitimate application scripts or assets.',
      'Test iframe embedding to confirm X-Frame-Options or frame-ancestors prevents unauthorized framing.'
    ],
    references: [
      { title: 'Helmet.js Security Documentation', url: 'https://helmetjs.github.io/' },
      { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' }
    ],
    illustrativePattern: 'const app = express();\napp.listen(3000);'
  },

  // =========================================================================
  // A06:2021 - Vulnerable and Outdated Components
  // =========================================================================
  'OWASP-A06-001': {
    guidanceId: 'OWASP-A06-001',
    ruleId: 'OWASP-A06-001',
    variant: null,
    title: 'Vulnerable and Outdated Component Import',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'Review package version against current security advisories and update to supported releases.',
    recommendedAction: 'Review package version against current security advisories and update to supported releases.',
    summary: 'Review package version against current security advisories and update to supported releases.',
    risk: 'Third-party packages with unpatched vulnerabilities or known security risks can introduce remote code execution, prototype pollution, or denial of service into applications.',
    cannotInfer: 'JSentinel cannot determine package versions from import statements alone without analyzing lockfiles (package-lock.json, yarn.lock).',
    scope: 'cross-boundary',
    approaches: [
      'Dependency Audit and Upgrade: Run automated package audit tools to check dependency versions against the National Vulnerability Database and upgrade to patched releases.',
      'Alternative Maintained Libraries: Replace unmaintained or vulnerable packages with actively maintained alternatives or native language APIs.'
    ],
    verifySteps: [
      'Run npm audit or yarn audit to identify known CVEs in project dependencies.',
      'Review package changelogs and security advisories before upgrading.',
      'Execute automated test suites after updating dependencies to verify backward compatibility.'
    ],
    references: [
      { title: 'OWASP Vulnerable Dependency Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html' },
      { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' }
    ],
    illustrativePattern: "import lodash from 'lodash';"
  },

  'OWASP-A06-001:component-review': {
    guidanceId: 'OWASP-A06-001:component-review',
    ruleId: 'OWASP-A06-001',
    variant: 'component-review',
    title: 'Third-Party Component Advisory Review',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'Identify the exact package version and applicable current advisory, then update or replace with compatibility tests.',
    recommendedAction: 'Identify the exact package version and applicable current advisory, then update or replace with compatibility tests.',
    summary: 'Identify the exact package version and applicable current advisory, then update or replace with compatibility tests.',
    risk: 'Importing packages with historical vulnerabilities (such as prototype pollution in legacy utilities or sandbox escapes in expression parsers) increases the attack surface if dependencies remain unpatched.',
    cannotInfer: 'JSentinel cannot determine installed dependency versions from code imports alone; an import statement does not prove a vulnerability is actively exploitable in your specific usage.',
    scope: 'cross-boundary',
    approaches: [
      'Targeted Dependency Upgrade: Check package-lock.json for the resolved package version and upgrade to a version containing the security patch.',
      'Native API Replacement: Replace utility libraries with modern native JavaScript features (e.g. structuredClone, Object.assign, optional chaining) where applicable.'
    ],
    verifySteps: [
      'Inspect package-lock.json or yarn.lock to verify the resolved version is not subject to known CVEs.',
      'Run npm audit to confirm zero high or critical vulnerabilities in the dependency tree.',
      'Run unit tests to ensure application logic remains functional with the updated package or native replacement.'
    ],
    references: [
      { title: 'OWASP Vulnerable Dependency Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html' },
      { title: 'NIST National Vulnerability Database', url: 'https://nvd.nist.gov/' }
    ],
    illustrativePattern: "import lodash from 'lodash'; // Review package version against advisories"
  },

  'OWASP-A06-001:express-headers': {
    guidanceId: 'OWASP-A06-001:express-headers',
    ruleId: 'OWASP-A06-001',
    variant: 'express-headers',
    title: 'Express Instance Missing Security Headers',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'Review the Express header-hardening configuration.',
    recommendedAction: 'Review the Express header-hardening configuration.',
    summary: 'Review the Express header-hardening configuration.',
    risk: 'Express does not include security headers by default. Without dedicated header middleware, web applications lack basic protection against clickjacking, cross-site scripting, and MIME confusion.',
    cannotInfer: 'JSentinel cannot determine if response headers are set by external reverse proxies (such as Nginx, AWS ALB, or Cloudflare) in production deployments.',
    scope: 'server',
    approaches: [
      'Apply Helmet Middleware: Integrate the Helmet package on the root Express application to attach security headers to all HTTP responses.',
      'Custom Express Header Middleware: Set essential HTTP security headers explicitly in a custom middleware function if third-party packages cannot be added.'
    ],
    verifySteps: [
      'Inspect HTTP response headers with curl -I http://localhost:PORT to confirm security headers are returned.',
      'Verify that X-Content-Type-Options: nosniff and X-Frame-Options headers appear on all API and HTML routes.',
      'Confirm application routing and static asset delivery operate properly after applying header middleware.'
    ],
    references: [
      { title: 'Helmet.js Documentation', url: 'https://helmetjs.github.io/' },
      { title: 'Express Production Security Best Practices', url: 'https://expressjs.com/en/advanced/best-practice-security.html' }
    ],
    illustrativePattern: 'const app = express(); // Express instance without Helmet security headers'
  },

  'OWASP-A06-001:dynamic-request-target': {
    guidanceId: 'OWASP-A06-001:dynamic-request-target',
    ruleId: 'OWASP-A06-001',
    variant: 'dynamic-request-target',
    title: 'Dynamic HTTP Client Request Target',
    category: 'A06:2021-Vulnerable and Outdated Components',
    categoryUrl: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
    shortAction: 'Restrict outbound request targets using the application\'s approved destination policy.',
    recommendedAction: 'Restrict outbound request targets using the application\'s approved destination policy.',
    summary: 'Restrict outbound request targets using the application\'s approved destination policy.',
    risk: 'Passing dynamic, unvalidated URL parameters to HTTP clients like Axios allows attackers to redirect requests, tamper with destination parameters, or probe internal networks.',
    cannotInfer: 'JSentinel cannot determine allowed API hostnames, valid route endpoints, or backend request forwarding configurations.',
    scope: 'cross-boundary',
    approaches: [
      'Strict Destination Safelist: Validate dynamic target URLs against an explicit allowlist of authorized hostnames and paths before dispatching requests.',
      'Fixed Base URL Client Instance: Create dedicated Axios client instances with predefined, static baseURL configurations to restrict request destinations.'
    ],
    verifySteps: [
      'Test requests with unauthorized external URLs to confirm the validation logic rejects them.',
      'Test requests with internal IP addresses (e.g. 127.0.0.1, 169.254.169.254) to ensure they are blocked.',
      'Verify valid API requests succeed with properly formatted paths and parameters.'
    ],
    references: [
      { title: 'OWASP Server-Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'Axios Instance Config Documentation', url: 'https://axios-http.com/docs/instance' }
    ],
    illustrativePattern: 'axios.get(userProvidedUrl);'
  },

  // =========================================================================
  // A07:2021 - Identification and Authentication Failures
  // =========================================================================
  'OWASP-A07-001': {
    guidanceId: 'OWASP-A07-001',
    ruleId: 'OWASP-A07-001',
    variant: null,
    title: 'Insecure Token Storage in localStorage',
    category: 'A07:2021-Identification and Authentication Failures',
    categoryUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    shortAction: 'Design the authentication flow so scripts cannot read long-lived credentials where possible.',
    recommendedAction: 'Design the authentication flow so scripts cannot read long-lived credentials where possible.',
    summary: 'Design the authentication flow so scripts cannot read long-lived credentials where possible.',
    risk: 'Browser localStorage and sessionStorage are accessible to any JavaScript running within the same origin. In the event of a Cross-Site Scripting (XSS) vulnerability, an attacker can extract all stored authentication tokens immediately.',
    cannotInfer: 'JSentinel cannot determine your cross-origin API architecture, native mobile client requirements, token expiration lifecycles, or backend cookie capabilities.',
    scope: 'cross-boundary',
    approaches: [
      'HttpOnly Session Cookies (Server-Issued): Have the backend authentication server issue tokens inside HttpOnly, Secure, SameSite cookies that JavaScript cannot read.',
      'Short-Lived In-Memory Token with Secure Refresh: Hold access tokens purely in JavaScript memory (closure or state) and use a secure HttpOnly cookie endpoint for token refresh.'
    ],
    verifySteps: [
      'Verify that authentication tokens are not stored in localStorage or sessionStorage.',
      'Confirm authentication cookies possess the HttpOnly and Secure flags via browser developer tools.',
      'Test that client-side scripts (document.cookie) cannot read the authentication cookie.'
    ],
    references: [
      { title: 'OWASP HTML5 Security Cheat Sheet - Local Storage', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage' },
      { title: 'MDN Web Storage API Security', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API' }
    ],
    illustrativePattern: "localStorage.setItem('authToken', jwtToken);"
  },

  // =========================================================================
  // A08:2021 - Software and Data Integrity Failures
  // =========================================================================
  'OWASP-A08-001': {
    guidanceId: 'OWASP-A08-001',
    ruleId: 'OWASP-A08-001',
    variant: null,
    title: 'Unsafe JSON Deserialization Without Validation',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'Validate untrusted parsed data against the expected structure before sensitive use.',
    recommendedAction: 'Validate untrusted parsed data against the expected structure before sensitive use.',
    summary: 'Validate untrusted parsed data against the expected structure before sensitive use.',
    risk: 'Parsing untrusted JSON without schema validation can inject unexpected data types, missing properties, or prototype manipulation payloads that cause runtime errors or logical bypasses in downstream application code.',
    cannotInfer: 'JSentinel cannot determine the expected object shape, schema definitions, type constraints, or downstream property expectations.',
    scope: 'browser',
    approaches: [
      'Schema Validation Post-Parse: Validate parsed JSON structures against an explicit schema (using libraries like Zod, Joi, or custom type assertions) before using properties.',
      'Defensive Try-Catch and Property Verification: Wrap JSON.parse in try-catch blocks and verify expected property types before processing data.'
    ],
    verifySteps: [
      'Test the parser with malformed JSON strings to confirm errors are caught without unhandled exceptions.',
      'Pass JSON with unexpected types (e.g. array instead of object, integer instead of string) to verify validation catches anomalies.',
      'Test with oversized payloads to verify memory and parsing limits.'
    ],
    references: [
      { title: 'OWASP Deserialization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html' },
      { title: 'OWASP A08:2021 – Software and Data Integrity Failures', url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' }
    ],
    illustrativePattern: 'const parsedData = JSON.parse(untrustedJsonInput);'
  },

  'OWASP-A08-002': {
    guidanceId: 'OWASP-A08-002',
    ruleId: 'OWASP-A08-002',
    variant: null,
    title: 'Prototype Mutation and Pollution',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'Stop direct prototype mutation and reject dangerous property names in untrusted data.',
    recommendedAction: 'Stop direct prototype mutation and reject dangerous property names in untrusted data.',
    summary: 'Stop direct prototype mutation and reject dangerous property names in untrusted data.',
    risk: 'Mutating __proto__ or Object.prototype alters properties for all objects in the JavaScript runtime. Attackers can exploit prototype pollution to override default methods, bypass security checks, or trigger denial of service.',
    cannotInfer: 'JSentinel cannot determine if the application intentionally extends prototypes or processes untrusted dictionary keys.',
    scope: 'browser',
    approaches: [
      'Prototype-Free Object Creation: Create lookup maps and dictionaries using Object.create(null) or Map instances that have no prototype chain.',
      'Key Allowlisting and Key Rejection: Explicitly reject dangerous property keys (__proto__, constructor, prototype) before setting object properties dynamically.'
    ],
    verifySteps: [
      'Attempt setting __proto__.polluted = true with untrusted input to verify {}[polluted] remains undefined.',
      'Test dynamic property setting functions with constructor and prototype keys to confirm rejection.',
      'Confirm legitimate object property access continues to function normally.'
    ],
    references: [
      { title: 'MDN Object.prototype.__proto__', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/proto' },
      { title: 'OWASP Prototype Pollution Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'targetObject.__proto__.polluted = true;'
  },

  'OWASP-A08-003': {
    guidanceId: 'OWASP-A08-003',
    ruleId: 'OWASP-A08-003',
    variant: null,
    title: 'Dynamic Object Merging (Object.assign)',
    category: 'A08:2021-Software and Data Integrity Failures',
    categoryUrl: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
    shortAction: 'Construct or merge only allowlisted data into an appropriate target object.',
    recommendedAction: 'Construct or merge only allowlisted data into an appropriate target object.',
    summary: 'Construct or merge only allowlisted data into an appropriate target object.',
    risk: 'Merging unvalidated user-controlled objects with Object.assign() or spread operators can overwrite critical internal properties, leading to prototype pollution or authorization bypasses.',
    cannotInfer: 'JSentinel cannot determine the valid property schema, permitted field definitions, or target object inheritance requirements.',
    scope: 'browser',
    approaches: [
      'Explicit Property Whitelisting: Construct target objects by selecting only known, permitted properties rather than merging entire raw payloads.',
      'Safe Deep Merge with Key Filtering: Use a validated merge utility that strips forbidden prototype properties (__proto__, constructor, prototype) during recursive merges.'
    ],
    verifySteps: [
      'Attempt merging a payload containing __proto__ or prototype properties to verify the prototype is not polluted.',
      'Test merging extra unexpected properties to confirm unallowed fields are ignored.',
      'Verify that expected valid object properties merge correctly without corruption.'
    ],
    references: [
      { title: 'MDN Object.assign() Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign' },
      { title: 'OWASP Prototype Pollution Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html' }
    ],
    illustrativePattern: 'Object.assign(targetObject, JSON.parse(userInputPayload));'
  },

  // =========================================================================
  // A10:2021 - Server-Side Request Forgery (SSRF)
  // =========================================================================
  'OWASP-A10-001': {
    guidanceId: 'OWASP-A10-001',
    ruleId: 'OWASP-A10-001',
    variant: null,
    title: 'Server-Side Request Forgery (SSRF)',
    category: 'A10:2021-Server-Side Request Forgery (SSRF)',
    categoryUrl: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
    shortAction: 'On the server, enforce a destination policy before making outbound requests.',
    recommendedAction: 'On the server, enforce a destination policy before making outbound requests.',
    summary: 'On the server, enforce a destination policy before making outbound requests.',
    risk: 'When server-side code makes outbound HTTP requests to user-supplied URLs, attackers can target internal services, loopback interfaces (localhost), private subnets, or cloud metadata endpoints (169.254.169.254) that are inaccessible from the public internet.',
    cannotInfer: 'JSentinel cannot determine server network infrastructure, internal IP ranges, private VPC DNS policies, or cloud provider metadata configurations.',
    scope: 'server',
    approaches: [
      'Strict Scheme and Host Safelist: Enforce an allowlist of permitted destination domains and protocols before initiating outbound server requests.',
      'Private IP and DNS Resolution Filtering: Resolve hostnames and reject requests targeting private, loopback, or link-local IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16).'
    ],
    verifySteps: [
      'Test outbound request handlers with localhost, 127.0.0.1, and [::1] to verify requests are blocked.',
      'Test with cloud metadata IPs (http://169.254.169.254/latest/meta-data/) to confirm protection against credential theft.',
      'Verify that requests to authorized external domains succeed over HTTPS.'
    ],
    references: [
      { title: 'OWASP Server-Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { title: 'OWASP A10:2021 – Server-Side Request Forgery (SSRF)', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' }
    ],
    illustrativePattern: 'axios.get(userSuppliedUrl);'
  }
};

// Non-enumerable property for legacy __disclaimer lookups
Object.defineProperty(guidanceCatalog, '__disclaimer', {
  value: GUIDANCE_DISCLAIMER,
  enumerable: false,
  writable: false
});

/**
 * Retrieves the matching GuidanceRecord for a finding issue object or rule ID string.
 * Returns FALLBACK_GUIDANCE on null/undefined/unknown inputs.
 *
 * @param {Object|string} issue - Finding issue object or rule ID string
 * @returns {Object} Guidance record
 */
export function getGuidance(issue) {
  if (!issue) return FALLBACK_GUIDANCE;

  // Case 1: Direct string input (e.g. 'OWASP-A01-001' or 'OWASP-A02-005:credential')
  if (typeof issue === 'string') {
    const trimmed = issue.trim();
    if (!trimmed) return FALLBACK_GUIDANCE;

    if (Object.prototype.hasOwnProperty.call(guidanceCatalog, trimmed)) {
      return guidanceCatalog[trimmed];
    }
    const baseId = trimmed.split(':')[0];
    if (Object.prototype.hasOwnProperty.call(guidanceCatalog, baseId)) {
      return guidanceCatalog[baseId];
    }
    return FALLBACK_GUIDANCE;
  }

  // Case 2: Finding issue object (e.g. { id: 'OWASP-A02-005', guidanceId: 'OWASP-A02-005:credential' })
  if (typeof issue === 'object') {
    const targetId = issue.guidanceId || issue.id;
    if (targetId && typeof targetId === 'string') {
      const trimmedTarget = targetId.trim();
      if (Object.prototype.hasOwnProperty.call(guidanceCatalog, trimmedTarget)) {
        return guidanceCatalog[trimmedTarget];
      }
      const baseId = trimmedTarget.split(':')[0];
      if (Object.prototype.hasOwnProperty.call(guidanceCatalog, baseId)) {
        return guidanceCatalog[baseId];
      }
    }

    if (issue.id && typeof issue.id === 'string') {
      const trimmedId = issue.id.trim();
      if (Object.prototype.hasOwnProperty.call(guidanceCatalog, trimmedId)) {
        return guidanceCatalog[trimmedId];
      }
    }

    return FALLBACK_GUIDANCE;
  }

  return FALLBACK_GUIDANCE;
}

/**
 * Returns all guidance records in the catalog as a key-value record map.
 *
 * @returns {Record<string, Object>}
 */
export function getAllGuidance() {
  return { ...guidanceCatalog };
}

/**
 * Returns all guidance records associated with a specific base rule ID.
 *
 * @param {string} ruleId - Base rule ID (e.g. 'OWASP-A06-001')
 * @returns {Object[]} Array of matching guidance records
 */
export function getGuidanceByRuleId(ruleId) {
  if (!ruleId || typeof ruleId !== 'string') return [];
  const trimmed = ruleId.trim();
  if (!trimmed) return [];
  return Object.values(guidanceCatalog).filter((record) => record && record.ruleId === trimmed);
}

export default guidanceCatalog;

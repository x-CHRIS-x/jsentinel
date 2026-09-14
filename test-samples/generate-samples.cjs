/**
 * JSentinel Test Samples Generator (Phase 04 Batch B Version)
 * 
 * Programmatically generates the 108 controlled benchmark samples:
 * - 54 Vulnerable samples (V-*.js) illustrating browser security vulnerabilities.
 * - 54 Clean samples (C-*.js) illustrating secure client remediations.
 * 
 * Eight simulated browser application scenarios remain preserved separately (pending Batch C).
 */

const fs = require('fs');
const path = require('path');

// CLI options
const args = process.argv.slice(2);
const isPilotMode = args.includes('--pilot');
const isCheckMode = args.includes('--check') || args.includes('--dry-run');
const outputDirIndex = args.indexOf('--output');
const targetOutputDir = (outputDirIndex !== -1 && args[outputDirIndex + 1])
  ? path.resolve(args[outputDirIndex + 1])
  : path.join(__dirname, 'samples');

const PILOT_FILES = new Set([
  'V-A5-027.js', 'C-A5-027.js',
  'V-A3-023.js', 'C-A3-023.js',
  'V-A1-007.js', 'C-A1-007.js',
  'V-A1-009.js', 'C-A1-009.js',
  'V-A7-039.js', 'C-A7-039.js',
  'V-A8-049.js', 'C-A8-049.js'
]);

const EOL = '\r\n';

// 54 Controlled Benchmark Pairs (108 Files)
const controlledPairs = [
  // A1: Injection & Dynamic Code (10 pairs: 001 - 010)
  {
    cat: 'A1', id: '001', varSig: 1,
    vCode: `// Vulnerable: eval usage (OWASP-A1-001)
function executeCode(userInput) {
    eval("console.log('Result: ' + " + userInput + ");");
}`,
    cCode: `// Clean: safe function parsing
function executeCodeSecure(userInput) {
    try {
        const parsed = JSON.parse(userInput);
        console.log('Result:', parsed);
    } catch (e) {
        console.error('Invalid input');
    }
}`
  },
  {
    cat: 'A1', id: '002', varSig: 2,
    vCode: `// Vulnerable: dynamic arithmetic expression evaluated via eval (OWASP-A1-001)
function calculateFormula(userFormula) {
    return eval("3 * (" + userFormula + ")");
}`,
    cCode: `// Clean: safe mathematical formula parsing using tokenized arithmetic evaluator
function calculateFormulaSecure(baseValue, multiplier) {
    const safeBase = Number(baseValue) || 0;
    const safeMult = Number(multiplier) || 1;
    return 3 * (safeBase * safeMult);
}`
  },
  {
    cat: 'A1', id: '003', varSig: 1,
    vCode: `// Vulnerable: string in setTimeout (OWASP-A1-002)
function scheduleTask(callbackStr, delay) {
    setTimeout(callbackStr + "()", delay);
}`,
    cCode: `// Clean: passing callback function reference to setTimeout
function scheduleTaskSecure(taskFn, delay) {
    if (typeof taskFn === 'function') {
        setTimeout(taskFn, delay);
    }
}`
  },
  {
    cat: 'A1', id: '004', varSig: 2,
    vCode: `// Vulnerable: dynamic string code in setInterval (OWASP-A1-002)
function startPollingTimer(actionCode, intervalMs) {
    return setInterval(actionCode + "()", intervalMs);
}`,
    cCode: `// Clean: setInterval passing callback function closure
function startPollingTimerSecure(actionCallback, intervalMs) {
    if (typeof actionCallback === 'function') {
        return setInterval(() => actionCallback(), intervalMs);
    }
    return null;
}`
  },
  {
    cat: 'A1', id: '005', varSig: 1,
    vCode: `// Vulnerable: new Function with dynamic argument (OWASP-A1-003)
function compileExpression(dynamicFormula) {
    const fn = new Function("x", "return " + dynamicFormula);
    return fn(10);
}`,
    cCode: `// Clean: predefined operator lookup table instead of dynamic code compilation
const operators = {
    double: (x) => x * 2,
    square: (x) => x * x,
    increment: (x) => x + 1
};
function compileExpressionSecure(operatorName, value) {
    const op = operators[operatorName] || ((x) => x);
    return op(value);
}`
  },
  {
    cat: 'A1', id: '006', varSig: 2,
    vCode: `// Vulnerable: dynamic filter predicate compiled via new Function (OWASP-A1-003)
function buildFilterPredicate(userPredicateStr) {
    const filterFn = new Function("item", "return " + userPredicateStr);
    return [1, 2, 3, 4, 5].filter(filterFn);
}`,
    cCode: `// Clean: parameterized array filtering using standard callback functions
function buildFilterPredicateSecure(items, threshold) {
    const minVal = Number(threshold) || 0;
    return items.filter(item => typeof item === 'number' && item >= minVal);
}`
  },
  {
    cat: 'A1', id: '007', varSig: 1, // PILOT
    vCode: `// Vulnerable: innerHTML with template literal interpolation (OWASP-A1-004)
function renderGreeting(element, username) {
    element.innerHTML = \`<div>Hello, \${username}!</div>\`;
}`,
    cCode: `// Clean: textContent sanitizes values safely
function renderGreetingSecure(element, username) {
    element.textContent = "Hello, " + username + "!";
}`
  },
  {
    cat: 'A1', id: '008', varSig: 2,
    vCode: `// Vulnerable: innerHTML template literal with user profile markup (OWASP-A1-004)
function renderUserProfile(container, bioText) {
    container.innerHTML = \`<span class="bio-display">\${bioText}</span>\`;
}`,
    cCode: `// Clean: DOM element creation and textContent assignment for user profile
function renderUserProfileSecure(container, bioText) {
    const span = document.createElement("span");
    span.className = "bio-display";
    span.textContent = bioText;
    container.replaceChildren(span);
}`
  },
  {
    cat: 'A1', id: '009', varSig: 1, // PILOT
    vCode: `// Simulated endpoint helper returning attacker-controlled markup
function getRawHtmlFromEndpoint(source) {
    return (source && source.htmlContent) || "<img src=x onerror=alert(1)>";
}

// Vulnerable: function call returned value assigned to innerHTML (OWASP-A1-005)
function updateContent(container, apiSource) {
    container.innerHTML = getRawHtmlFromEndpoint(apiSource);
}`,
    cCode: `// Helper returning plain text string from data source
function getCleanTextFromEndpoint(source) {
    return (source && source.textContent) || "Safe notification text";
}

// Clean: textContent assignment renders plain text without HTML interpretation
function updateContentSecure(container, apiSource) {
    container.textContent = getCleanTextFromEndpoint(apiSource);
}`
  },
  {
    cat: 'A1', id: '010', varSig: 2,
    vCode: `// Helper returning raw notification markup from external feed
function fetchNotificationMarkup(notificationFeed) {
    return (notificationFeed && notificationFeed.body) || "<b onmouseover=alert(1)>Notice</b>";
}

// Vulnerable: function return value assigned directly to innerHTML (OWASP-A1-005)
function displayNotificationBanner(bannerElement, feedSource) {
    bannerElement.innerHTML = fetchNotificationMarkup(feedSource);
}`,
    cCode: `// Helper returning plain text notification message
function fetchNotificationText(notificationFeed) {
    return (notificationFeed && notificationFeed.message) || "Standard notification";
}

// Clean: plain text notification assigned to textContent
function displayNotificationBannerSecure(bannerElement, feedSource) {
    bannerElement.textContent = fetchNotificationText(feedSource);
}`
  },

  // A2: Cryptographic Failures & Sensitive Data (10 pairs: 011 - 020)
  {
    cat: 'A2', id: '011', varSig: 1,
    vCode: `// Vulnerable: hardcoded credential variables (OWASP-A2-001)
const adminAuthPassword = "SuperSecretFallbackPassword2026!";
function loginMaster(pwd) {
    return pwd === adminAuthPassword;
}`,
    cCode: `// Clean: passwords verified server-side via authentication endpoint
async function loginMasterSecure(username, pwd) {
    const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, pwd })
    });
    return res.ok;
}`
  },
  {
    cat: 'A2', id: '012', varSig: 2,
    vCode: `// Vulnerable: hardcoded recovery secret password (OWASP-A2-001)
const recoveryAuthKey = "EmergencyRestoreKey#9876543210";
function verifyEmergencyAccess(providedKey) {
    return providedKey === recoveryAuthKey;
}`,
    cCode: `// Clean: emergency access verification delegated to secure server challenge
async function verifyEmergencyAccessSecure(challengeResponse) {
    const res = await fetch("/api/auth/emergency-verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeResponse })
    });
    return res.ok;
}`
  },
  {
    cat: 'A2', id: '013', varSig: 1,
    vCode: `// Vulnerable: localStorage token caching (OWASP-A2-002)
function cacheSessionToken(jwtToken) {
    localStorage.setItem("session_token", jwtToken);
}`,
    cCode: `// Clean: transient session token stored in module-scoped memory closure
let sessionTokenMemory = null;
function cacheSessionTokenSecure(jwtToken) {
    sessionTokenMemory = jwtToken;
}
function getSessionTokenSecure() {
    return sessionTokenMemory;
}`
  },
  {
    cat: 'A2', id: '014', varSig: 2,
    vCode: `// Vulnerable: localStorage auth credential storage (OWASP-A2-002)
function persistAuthCredentials(authToken) {
    localStorage.setItem("user_auth_credential", authToken);
}`,
    cCode: `// Clean: session state managed via server-issued session cookie without client storage
async function persistAuthCredentialsSecure(credentials) {
    const res = await fetch("/api/auth/session-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
        credentials: "same-origin"
    });
    return res.ok;
}`
  },
  {
    cat: 'A2', id: '015', varSig: 1,
    vCode: `// Vulnerable: insecure cookie properties (OWASP-A2-003)
function createSessionCookie(userId) {
    document.cookie = "session=" + userId + "; path=/;";
}`,
    cCode: `// Clean: session cookie issued by server Set-Cookie header rather than client script
async function createSessionCookieSecure(userId) {
    const res = await fetch("/api/auth/create-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
        credentials: "same-origin"
    });
    return res.ok;
}`
  },
  {
    cat: 'A2', id: '016', varSig: 2,
    vCode: `// Vulnerable: storing authentication credentials directly in document.cookie without HttpOnly protection (OWASP-A2-003)
function storeAuthCookie(authToken) {
    document.cookie = "auth_token=" + authToken + "; path=/;";
}`,
    cCode: `// Clean: auth token storage delegated to server Set-Cookie response header via token exchange endpoint
async function storeAuthCookieSecure(authToken) {
    const res = await fetch("/api/auth/token-exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: authToken }),
        credentials: "same-origin"
    });
    return res.ok;
}`
  },
  {
    cat: 'A2', id: '017', varSig: 1,
    vCode: `// Vulnerable: Math.random for security tokens (OWASP-A2-004)
function generateUserOtpSecret() {
    const otp = Math.random().toString().substring(2, 8);
    const otp_key = "secret_" + Math.random().toString(36);
    return { otp, otp_key };
}`,
    cCode: `// Clean: cryptographically secure random values via Web Crypto API with 256-bit secret key
function generateUserOtpSecretSecure() {
    // 6-digit numeric OTP generated using crypto.getRandomValues (uniform 20-bit numeric range)
    const otpBytes = new Uint32Array(1);
    crypto.getRandomValues(otpBytes);
    const otp = String(otpBytes[0] % 1000000).padStart(6, '0');

    // Cryptographic secret key using 256 bits (32 bytes) of cryptographic entropy
    const secretBytes = new Uint8Array(32);
    crypto.getRandomValues(secretBytes);
    const otp_key = "secure_" + Array.from(secretBytes, b => b.toString(16).padStart(2, '0')).join('');

    return { otp, otp_key };
}`
  },
  {
    cat: 'A2', id: '018', varSig: 2,
    vCode: `// Vulnerable: Math.random used for CSRF nonce generation (OWASP-A2-004)
function generateCsrfNonce() {
    const nonceVal = "nonce_" + Math.random().toString(36).substring(2);
    const sessionNonce = Math.random().toString(16);
    return { nonceVal, sessionNonce };
}`,
    cCode: `// Clean: standard cryptographically secure random UUID for nonce generation
function generateCsrfNonceSecure() {
    const nonceVal = "nonce_" + crypto.randomUUID();
    const sessionNonce = crypto.randomUUID();
    return { nonceVal, sessionNonce };
}`
  },
  {
    cat: 'A2', id: '019', varSig: 1,
    vCode: `// Vulnerable: Plain http URLs used for communication (OWASP-A2-005)
const defaultApiUrl = "http://unencrypted.internal-services.com/v1/auth";
function fetchPayload() {
    return fetch(defaultApiUrl + "/data");
}`,
    cCode: `// Clean: secure SSL HTTPS protocols used
const defaultApiUrl = "https://encrypted.internal-services.com/v1/auth";
function fetchPayloadSecure() {
    return fetch(defaultApiUrl + "/data");
}`
  },
  {
    cat: 'A2', id: '020', varSig: 2,
    vCode: `// Vulnerable: unencrypted HTTP telemetry reporting endpoint (OWASP-A2-005)
const telemetryEndpoint = "http://telemetry.logging-service.net/events";
function sendTelemetry(eventData) {
    return fetch(telemetryEndpoint, {
        method: "POST",
        body: JSON.stringify(eventData)
    });
}`,
    cCode: `// Clean: encrypted HTTPS telemetry reporting endpoint
const telemetryEndpointSecure = "https://telemetry.logging-service.net/events";
function sendTelemetrySecure(eventData) {
    return fetch(telemetryEndpointSecure, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(eventData)
    });
}`
  },

  // A3: Cryptographic Token Signatures & API Secrets (6 pairs: 021 - 026)
  {
    cat: 'A3', id: '021', varSig: 1,
    vCode: `// Vulnerable: hardcoded cryptographic token signatures (OWASP-A3-001)
const AWS_ACCESS_SECRET = "AKIAIOSFODNN7EXAMPLE";
const STATIC_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";`,
    cCode: `// Clean: cloud storage operations dispatched through authenticated backend endpoint
async function uploadToCloudStorageSecure(fileBlob) {
    const res = await fetch("/api/cloud/upload", {
        method: "POST",
        body: fileBlob
    });
    return res.json();
}`
  },
  {
    cat: 'A3', id: '022', varSig: 2,
    vCode: `// Vulnerable: hardcoded payment gateway secret keys (OWASP-A3-001)
const STRIPE_SECRET_KEY = "sk_live_51Abc123Def456Ghi789Jkl012Mno345";
const PRIVATE_JWT_SIGNATURE = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.ab12cd34ef56gh78";`,
    cCode: `// Clean: payment creation handled server-side; client uses restricted publishable token
async function createPaymentIntentSecure(orderId) {
    const res = await fetch("/api/checkout/create-intent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ orderId })
    });
    return res.json();
}`
  },
  {
    cat: 'A3', id: '023', varSig: 1, // PILOT
    vCode: `// Vulnerable: hardcoded API keys (OWASP-A3-002)
const application_secret_key = "apikey_development_credential_987654321";
const gatewayToken = "token_prod_abc123xyz789";
`,
    cCode: `// Clean: API requests dispatched through backend proxy without client-exposed secrets
async function callGatewayService(payload) {
    const response = await fetch("/api/gateway/dispatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    return response.json();
}`
  },
  {
    cat: 'A3', id: '024', varSig: 2,
    vCode: `// Vulnerable: hardcoded database service key (OWASP-A3-002)
const databaseServiceApiKey = "apikey_production_db_key_555444332211";
const clientSecretToken = "token_prod_webhook_secret_9988776655";`,
    cCode: `// Clean: database operations proxied through backend API route
async function queryDatabaseServiceSecure(queryPayload) {
    const response = await fetch("/api/data/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(queryPayload)
    });
    return response.json();
}`
  },
  {
    cat: 'A3', id: '025', varSig: 1,
    vCode: `// Vulnerable: sensitive tokens exposed in query URL parameters (OWASP-A3-003)
function constructRedirectUrl(username, pwdVal) {
    return "/auth/callback?user=" + username + "&password=" + pwdVal;
}`,
    cCode: `// Clean: credentials sent in HTTP POST body rather than query URL parameters
async function submitLoginCredentialsSecure(username, password) {
    const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });
    return res.ok;
}`
  },
  {
    cat: 'A3', id: '026', varSig: 2,
    vCode: `// Vulnerable: password reset token exposed in query string (OWASP-A3-003)
function buildPasswordResetUrl(accountEmail, resetToken) {
    return "/auth/reset?email=" + accountEmail + "&token=" + resetToken;
}`,
    cCode: `// Clean: reset token submitted via secure POST request body
async function submitPasswordResetSecure(accountEmail, resetToken, newPassword) {
    const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: accountEmail, token: resetToken, newPassword })
    });
    return res.ok;
}`
  },

  // A5: Broken Access Control (4 pairs: 027 - 030)
  {
    cat: 'A5', id: '027', varSig: 1, // PILOT
    vCode: `// Vulnerable: Open redirect path assignment (OWASP-A5-001)
function redirectToExternal(targetUrl) {
    window.location.href = targetUrl;
}`,
    cCode: `// Clean: safelist checked redirects
const allowedDomains = ["https://app.example.com", "https://api.example.com"];
function redirectToExternalSecure(targetUrl) {
    if (allowedDomains.includes(targetUrl)) {
        window.location.href = targetUrl;
    }
}`
  },
  {
    cat: 'A5', id: '028', varSig: 2,
    vCode: `// Vulnerable: open redirect via window.location.replace (OWASP-A5-001)
function navigateToPartnerSite(partnerUrl) {
    window.location.replace(partnerUrl);
}`,
    cCode: `// Clean: domain allowlist verification before location.replace
const trustedPartnerDomains = ["https://partner.example.com", "https://auth.example.com"];
function navigateToPartnerSiteSecure(partnerUrl) {
    if (trustedPartnerDomains.includes(partnerUrl)) {
        window.location.replace(partnerUrl);
    }
}`
  },
  {
    cat: 'A5', id: '029', varSig: 1,
    vCode: `// Vulnerable: client-side role check guarding access to privileged administrative endpoint (OWASP-A5-002)
function executeAdministrativeAction(userContext, targetUserId) {
    if (userContext.role === "admin" || userContext.isAdmin === true) {
        return fetch("/api/v1/users/" + targetUserId + "/grant-superuser", {
            method: "POST"
        });
    }
    return Promise.reject(new Error("Unauthorized"));
}`,
    cCode: `// Clean: administrative action authorization enforced by backend API rather than client checks
async function executeAdministrativeActionSecure(targetUserId) {
    const res = await fetch("/api/v1/users/" + targetUserId + "/grant-superuser", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin"
    });
    if (!res.ok) {
        throw new Error("Server rejected unauthorized administrative action");
    }
    return res.json();
}`
  },
  {
    cat: 'A5', id: '030', varSig: 2,
    vCode: `function triggerSystemPurge() {
    return fetch("/api/admin/purge", { method: "POST" });
}

// Vulnerable: client-side permission flag guarding destructive action (OWASP-A5-002)
function executePurgeOperation(userState) {
    if (userState.role === "admin" || userState.hasPurgePermission === true) {
        return triggerSystemPurge();
    }
    return Promise.reject(new Error("Unauthorized"));
}`,
    cCode: `function triggerSystemPurge() {
    return fetch("/api/admin/purge", { method: "POST" });
}

// Clean: destructive action authorized server-side before execution
async function executePurgeOperationSecure() {
    const res = await fetch("/api/admin/purge-authorized", {
        method: "POST",
        credentials: "same-origin"
    });
    if (res.ok) {
        return triggerSystemPurge();
    }
    throw new Error("Server rejected purge operation");
}`
  },

  // A6: Security Misconfiguration & Logging (8 pairs: 031 - 038)
  {
    cat: 'A6', id: '031', varSig: 1,
    vCode: `// Vulnerable: sensitive password name logged in console (OWASP-A6-001)
function authenticateCredentials(user, password) {
    console.log("Validating login for user: " + user + " with password: " + password);
}`,
    cCode: `// Clean: logging benign information logs
function authenticateCredentialsSecure(user) {
    console.log("Validating login request signature for user: " + user);
}`
  },
  {
    cat: 'A6', id: '032', varSig: 2,
    vCode: `// Vulnerable: sensitive authentication secret printed to console (OWASP-A6-001)
function recordAuthSession(user, secretKey) {
    console.warn("Session established for: " + user + " secret: " + secretKey);
}`,
    cCode: `// Clean: logging non-sensitive status message
function recordAuthSessionSecure(user) {
    console.warn("Session established for: " + user);
}`
  },
  {
    cat: 'A6', id: '033', varSig: 1, // REASSIGNED BROWSER WEAKNESS (former CORS wildcard)
    vCode: `// Vulnerable: cross-window postMessage with wildcard target origin (OWASP-A01-001)
function broadcastSessionToken(authToken) {
    window.parent.postMessage({ sessionToken: authToken }, "*");
}`,
    cCode: `// Clean: cross-window postMessage with strict target origin restriction
function broadcastSessionTokenSecure(authToken) {
    window.parent.postMessage({ sessionToken: authToken }, "https://portal.trusted.domain");
}`
  },
  {
    cat: 'A6', id: '034', varSig: 2, // REASSIGNED BROWSER WEAKNESS (former CORS wildcard var 2)
    vCode: `// Vulnerable: cross-window message handler executing code without origin validation (OWASP-A03-001)
function listenForRemoteCommands() {
    window.addEventListener("message", function(event) {
        eval(event.data.command);
    });
}`,
    cCode: `// Clean: cross-window message handler validating event origin before processing
const allowedActions = {
    refresh: () => { window.location.reload(); },
    ping: () => { window.parent.postMessage({ status: "pong" }, "https://trusted.portal.example.com"); }
};
function handleSafeAction(action) {
    if (Object.prototype.hasOwnProperty.call(allowedActions, action)) {
        allowedActions[action]();
    }
}

const trustedOrigins = ["https://trusted.portal.example.com"];
function listenForRemoteCommandsSecure() {
    window.addEventListener("message", function(event) {
        if (!trustedOrigins.includes(event.origin)) return;
        if (event.data && typeof event.data.action === "string") {
            handleSafeAction(event.data.action);
        }
    });
}`
  },
  {
    cat: 'A6', id: '035', varSig: 1,
    vCode: `// Vulnerable: full request or session objects printed to logging endpoints (OWASP-A6-003)
function debugGateway(req) {
    console.log("Full request:", req);
}`,
    cCode: `// Clean: logging specific properties
function debugGatewaySecure(req) {
    console.log("Request incoming path:", req.path);
}`
  },
  {
    cat: 'A6', id: '036', varSig: 2,
    vCode: `// Vulnerable: logging full user authentication context object (OWASP-A6-003)
function auditLoginContext(authContext) {
    console.error("Authentication context failure:", authContext);
}`,
    cCode: `// Clean: logging only specific non-sensitive status code
function auditLoginContextSecure(statusCode) {
    console.error("Authentication failure error code:", statusCode);
}`
  },
  {
    cat: 'A6', id: '037', varSig: 1, // REASSIGNED BROWSER WEAKNESS (former Express helmet)
    vCode: `// Vulnerable: unencrypted WebSocket connection transmitting sensitive telemetry (OWASP-A02-004)
const telemetryWsUrl = "ws://telemetry.unencrypted.internal-services.com/stream";
function connectTelemetryStream() {
    return new WebSocket(telemetryWsUrl);
}`,
    cCode: `// Clean: encrypted WebSocket connection using wss protocol
const telemetryWsUrlSecure = "wss://telemetry.encrypted.internal-services.com/stream";
function connectTelemetryStreamSecure() {
    return new WebSocket(telemetryWsUrlSecure);
}`
  },
  {
    cat: 'A6', id: '038', varSig: 2, // REASSIGNED BROWSER WEAKNESS (former Express helmet var 2)
    vCode: `// Vulnerable: unencrypted HTTP script source URL (OWASP-A02-004)
const scriptSourceUrl = "http://cdn.unencrypted.internal-services.com/library.js";
function injectExternalScript() {
    const s = document.createElement("script");
    s.src = scriptSourceUrl;
    document.head.appendChild(s);
}`,
    cCode: `// Clean: encrypted HTTPS script source URL
const scriptSourceUrlSecure = "https://cdn.encrypted.internal-services.com/library.js";
function injectExternalScriptSecure() {
    const s = document.createElement("script");
    s.src = scriptSourceUrlSecure;
    document.head.appendChild(s);
}`
  },

  // A7: XSS & Direct DOM Injection (6 pairs: 039 - 044)
  {
    cat: 'A7', id: '039', varSig: 1, // PILOT
    vCode: `// Vulnerable: direct innerHTML assignments (OWASP-A7-001)
function loadUserBadge(element, badgeHtml) {
    element.innerHTML = badgeHtml;
}`,
    cCode: `// Clean: textContent prevents HTML execution injections
function loadUserBadgeSecure(element, badgeHtml) {
    element.textContent = badgeHtml;
}`
  },
  {
    cat: 'A7', id: '040', varSig: 2,
    vCode: `// Vulnerable: direct innerHTML assignment with user comment markup (OWASP-A7-001)
function renderUserComment(container, commentMarkup) {
    container.innerHTML = commentMarkup;
}`,
    cCode: `// Clean: safe DOM node creation with textContent assignment
function renderUserCommentSecure(container, commentText) {
    const p = document.createElement("p");
    p.textContent = commentText;
    container.replaceChildren(p);
}`
  },
  {
    cat: 'A7', id: '041', varSig: 1,
    vCode: `// Vulnerable: document.write calls (OWASP-A7-002)
function writeOutputSnippet(content) {
    document.write(content);
}`,
    cCode: `// Clean: standard text nodes created safely
function writeOutputSnippetSecure(content) {
    const node = document.createTextNode(content);
    document.body.appendChild(node);
}`
  },
  {
    cat: 'A7', id: '042', varSig: 2,
    vCode: `// Vulnerable: document.writeln with dynamic user status message (OWASP-A7-002)
function outputUserStatus(statusText) {
    document.writeln("<div>Status: " + statusText + "</div>");
}`,
    cCode: `// Clean: safe DOM element insertion with textContent
function outputUserStatusSecure(statusText) {
    const div = document.createElement("div");
    div.textContent = "Status: " + statusText;
    document.body.appendChild(div);
}`
  },
  {
    cat: 'A7', id: '043', varSig: 1,
    vCode: `// Vulnerable: dangerouslySetInnerHTML React properties (OWASP-A7-003)
function renderDynamicPost(contentStr) {
    return <div dangerouslySetInnerHTML={{ __html: contentStr }} />;
}`,
    cCode: `// Clean: standard React templating values
function renderDynamicPostSecure(contentStr) {
    return <div>{contentStr}</div>;
}`
  },
  {
    cat: 'A7', id: '044', varSig: 2,
    vCode: `// Vulnerable: dangerouslySetInnerHTML React properties in article banner (OWASP-A7-003)
function renderArticleBanner(bannerHtml) {
    return <section dangerouslySetInnerHTML={{ __html: bannerHtml }} className="banner" />;
}`,
    cCode: `// Clean: React element children safely interpolating text
function renderArticleBannerSecure(bannerText) {
    return <section className="banner">{bannerText}</section>;
}`
  },

  // A8: Software and Data Integrity Failures (6 pairs: 045 - 050)
  {
    cat: 'A8', id: '045', varSig: 1,
    vCode: `function enableAdminPrivileges() {
    window.__adminMode = true;
}

// Vulnerable: parsing untrusted serialized session state and trusting unvalidated properties for authorization decisions (OWASP-A8-001)
function loadSessionState(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (session.isAdmin) {
        enableAdminPrivileges();
    }
    return session;
}`,
    cCode: `// Clean: strict schema validation function verifying expected structure and rejecting unverified privileges
function validateSessionSchema(data) {
    if (!data || typeof data !== 'object') return false;
    return typeof data.userId === 'string' && typeof data.role === 'string';
}

function loadSessionStateSecure(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (!validateSessionSchema(session)) {
        throw new Error('Invalid session payload schema');
    }
    return {
        userId: session.userId,
        role: 'standard_user' // Never grant elevated privileges from untrusted client JSON
    };
}`
  },
  {
    cat: 'A8', id: '046', varSig: 2,
    vCode: `// Vulnerable: parsing untrusted configuration JSON where unvalidated properties control security behavior (OWASP-A8-001)
function loadAppConfig(rawConfig) {
    const config = JSON.parse(rawConfig);
    // Unsafe context: dispatching fetch to arbitrary unvalidated endpoint URL from parsed JSON
    return fetch(config.endpointUrl);
}`,
    cCode: `// Clean: JSON parsing followed by explicit schema verification and endpoint allowlisting
function verifyAppConfig(config) {
    if (!config || typeof config !== 'object') return null;
    const allowedEndpoints = ['/api/v1/feed', '/api/v1/profile'];
    if (typeof config.endpointUrl === 'string' && allowedEndpoints.includes(config.endpointUrl)) {
        return { endpointUrl: config.endpointUrl };
    }
    return { endpointUrl: '/api/v1/feed' };
}

function loadAppConfigSecure(rawConfig) {
    const config = JSON.parse(rawConfig);
    const verified = verifyAppConfig(config);
    return fetch(verified.endpointUrl);
}`
  },
  {
    cat: 'A8', id: '047', varSig: 1,
    vCode: `// Vulnerable: constructor prototype overrides (OWASP-A8-002)
function pollutePrototype(target, customKey, value) {
    target.__proto__[customKey] = value;
}`,
    cCode: `// Clean: creating clean object interfaces
function createCleanProperties() {
    const targetObj = Object.create(null);
    targetObj.safe = true;
    return targetObj;
}`
  },
  {
    cat: 'A8', id: '048', varSig: 2,
    vCode: `// Vulnerable: constructor prototype pollution via constructor attribute (OWASP-A8-002)
function updateConstructorPrototype(targetObj, propName, propValue) {
    targetObj.constructor.prototype[propName] = propValue;
}`,
    cCode: `// Clean: Map data structure avoiding Object.prototype pollution
function createPropertyMapSecure() {
    const map = new Map();
    map.set("safe", true);
    return map;
}`
  },
  {
    cat: 'A8', id: '049', varSig: 1, // PILOT
    vCode: `// Vulnerable: Object.assign with untrusted second argument parameters (OWASP-A8-003)
function mergeConfigurations(defaultConfig, userPayload) {
    return Object.assign(defaultConfig, userPayload);
}`,
    cCode: `// Clean: safe mapping copy operations with prototype property filtering
function sanitizeInputProperties(obj) {
    if (!obj || typeof obj !== 'object') return {};
    const clean = {};
    for (const key of Object.keys(obj)) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            clean[key] = obj[key];
        }
    }
    return clean;
}

function mergeConfigurationsSecure(defaultConfig, userPayload) {
    const sanitizedPayload = sanitizeInputProperties(userPayload);
    return Object.assign({}, defaultConfig, sanitizedPayload);
}`
  },
  {
    cat: 'A8', id: '050', varSig: 2,
    vCode: `// Vulnerable: Object.assign copying untrusted options to settings object (OWASP-A8-003)
function applyUserThemeSettings(baseSettings, untrustedOptions) {
    return Object.assign(baseSettings, untrustedOptions);
}`,
    cCode: `// Clean: strict property picking allowlist preventing prototype pollution
function applyUserThemeSettingsSecure(baseSettings, untrustedOptions) {
    const safeOptions = {};
    const allowedKeys = ['theme', 'accentColor', 'layoutMode'];
    if (untrustedOptions && typeof untrustedOptions === 'object') {
        for (const key of allowedKeys) {
            if (Object.prototype.hasOwnProperty.call(untrustedOptions, key)) {
                safeOptions[key] = untrustedOptions[key];
            }
        }
    }
    return Object.assign({}, baseSettings, safeOptions);
}`
  },

  // A9: Reassigned Browser Weaknesses (former package import advisories) (2 pairs: 051 - 052)
  {
    cat: 'A9', id: '051', varSig: 1, // REASSIGNED BROWSER WEAKNESS (former serialize-javascript/yaml import)
    vCode: `// Vulnerable: storing sensitive bearer token in sessionStorage (CWE-922)
function persistBearerToken(token) {
    sessionStorage.setItem("bearer_token", token);
}`,
    cCode: `// Clean: transient in-memory token storage preventing persistent web storage exposure
let memoryBearerToken = null;
function persistBearerTokenSecure(token) {
    memoryBearerToken = token;
}
function getBearerTokenSecure() {
    return memoryBearerToken;
}`
  },
  {
    cat: 'A9', id: '052', varSig: 2, // REASSIGNED BROWSER WEAKNESS (former lodash import)
    vCode: `// Vulnerable: sensitive authentication token exposed in window URL fragment (CWE-598)
function publishAccessTokenInUrl(userToken) {
    window.location.hash = "access_token=" + userToken;
}`,
    cCode: `// Clean: token transmitted in memory via authorization request header
async function requestUserDataSecure(userToken) {
    const res = await fetch("/api/user/profile", {
        headers: { "Authorization": "Bearer " + userToken }
    });
    return res.json();
}`
  },

  // A10: Reassigned Browser Weaknesses (former server-side SSRF) (2 pairs: 053 - 054)
  {
    cat: 'A10', id: '053', varSig: 1, // REASSIGNED BROWSER WEAKNESS (former axios.get SSRF)
    vCode: `// Vulnerable: client-side fetch to arbitrary user-supplied URL with ambient credentials (CWE-20)
function fetchRemoteData(userProvidedUrl) {
    return fetch(userProvidedUrl, { credentials: "include" });
}`,
    cCode: `// Clean: destination domain verified against allowlist before sending credentials
const trustedOrigins = ["https://api.verified.com", "https://auth.verified.com"];
function fetchRemoteDataSecure(targetUrl) {
    const parsed = new URL(targetUrl, window.location.href);
    if (trustedOrigins.includes(parsed.origin)) {
        return fetch(targetUrl, { credentials: "include" });
    }
    throw new Error("Untrusted destination origin");
}`
  },
  {
    cat: 'A10', id: '054', varSig: 2, // REASSIGNED BROWSER WEAKNESS (former axios.get SSRF var 2)
    vCode: `// Vulnerable: dynamic script inclusion from arbitrary user-controlled URL (CWE-829)
function loadExternalPlugin(untrustedScriptUrl) {
    const script = document.createElement("script");
    script.src = untrustedScriptUrl;
    document.head.appendChild(script);
}`,
    cCode: `// Clean: dynamic script loaded only from trusted CDN with Subresource Integrity verification
const approvedPluginUrl = "https://cdn.verified.com/plugins/editor.v1.js";
function loadExternalPluginSecure() {
    const script = document.createElement("script");
    script.src = approvedPluginUrl;
    script.integrity = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";
    script.crossOrigin = "anonymous";
    document.head.appendChild(script);
}`
  }
];

// Helper to format sample file content
function formatFileContent(type, cat, id, varSig, rawCode) {
  const isV = type === 'V';
  const label = isV ? 'Vulnerable' : 'Clean';
  const subDesc = isV ? 'Demonstrates OWASP vulnerabilities.' : 'Safe, compliant implementations.';
  const normCode = rawCode.replace(/\r?\n/g, EOL);
  return `/**${EOL} * Test ${label} Sample ${id} (${cat})${EOL} * ${subDesc}${EOL} */${EOL}${EOL}${normCode}${EOL}${EOL}// Variation signature: #${varSig}${EOL}`;
}

// Generate or check files
if (!fs.existsSync(targetOutputDir) && !isCheckMode) {
  fs.mkdirSync(targetOutputDir, { recursive: true });
}

let generatedCount = 0;
let matchCount = 0;
let mismatchCount = 0;

for (const pair of controlledPairs) {
  const vFileName = `V-${pair.cat}-${pair.id}.js`;
  const cFileName = `C-${pair.cat}-${pair.id}.js`;

  const shouldProcessV = !isPilotMode || PILOT_FILES.has(vFileName);
  const shouldProcessC = !isPilotMode || PILOT_FILES.has(cFileName);

  if (shouldProcessV) {
    const vContent = formatFileContent('V', pair.cat, pair.id, pair.varSig, pair.vCode);
    const vPath = path.join(targetOutputDir, vFileName);

    if (isCheckMode) {
      if (fs.existsSync(vPath) && fs.readFileSync(vPath, 'utf8') === vContent) {
        matchCount++;
      } else {
        mismatchCount++;
      }
    } else {
      fs.writeFileSync(vPath, vContent);
      generatedCount++;
    }
  }

  if (shouldProcessC) {
    const cContent = formatFileContent('C', pair.cat, pair.id, pair.varSig, pair.cCode);
    const cPath = path.join(targetOutputDir, cFileName);

    if (isCheckMode) {
      if (fs.existsSync(cPath) && fs.readFileSync(cPath, 'utf8') === cContent) {
        matchCount++;
      } else {
        mismatchCount++;
      }
    } else {
      fs.writeFileSync(cPath, cContent);
      generatedCount++;
    }
  }
}

if (isCheckMode) {
  console.log(`Check Mode: ${matchCount} matches, ${mismatchCount} mismatches out of ${matchCount + mismatchCount} checked.`);
} else if (isPilotMode) {
  console.log(`Pilot Mode: successfully generated ${generatedCount} pilot files.`);
} else {
  console.log(`Batch B: successfully generated ${generatedCount} controlled files (54 V, 54 C). Eight scenario files untouched.`);
}

module.exports = { controlledPairs, PILOT_FILES, formatFileContent };

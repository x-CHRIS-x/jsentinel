/**
 * JSentinel Test Samples Generator (CommonJS Version)
 * 
 * Programmatically generates ~100 realistic JavaScript and React files:
 * - 50 Vulnerable files (V-*.js) illustrating all 27 detection rules across 9 OWASP categories.
 * - 50 Clean files (C-*.js) illustrating secure remediations of the same features.
 */

const fs = require('fs');
const path = require('path');

const outputDir = path.join(__dirname, 'samples');

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

// 1. Templates for Vulnerable Samples (V-*.js)
const vulnerableTemplates = {
  'A1': [
    {
      id: '01',
      code: `// Vulnerable: eval usage (OWASP-A1-001)
function executeCode(userInput) {
    eval("console.log('Result: ' + " + userInput + ");");
}`
    },
    {
      id: '02',
      code: `// Vulnerable: string in setTimeout (OWASP-A1-002)
function scheduleTask(callbackStr, delay) {
    setTimeout(callbackStr + "()", delay);
}`
    },
    {
      id: '03',
      code: `// Vulnerable: new Function with dynamic argument (OWASP-A1-003)
function compileExpression(dynamicFormula) {
    const fn = new Function("x", "return " + dynamicFormula);
    return fn(10);
}`
    },
    {
      id: '04',
      code: `// Vulnerable: innerHTML with template literal interpolation (OWASP-A1-004)
function renderGreeting(element, username) {
    element.innerHTML = \`<div>Hello, \${username}!</div>\`;
}`
    },
    {
      id: '05',
      code: `// Simulated endpoint helper returning attacker-controlled markup
function getRawHtmlFromEndpoint(source) {
    return (source && source.htmlContent) || "<img src=x onerror=alert(1)>";
}

// Vulnerable: function call returned value assigned to innerHTML (OWASP-A1-005)
function updateContent(container, apiSource) {
    container.innerHTML = getRawHtmlFromEndpoint(apiSource);
}`
    }
  ],
  'A2': [
    {
      id: '01',
      code: `// Vulnerable: hardcoded credential variables (OWASP-A2-001)
const adminAuthPassword = "SuperSecretFallbackPassword2026!";
function loginMaster(pwd) {
    return pwd === adminAuthPassword;
}`
    },
    {
      id: '02',
      code: `// Vulnerable: localStorage token caching (OWASP-A2-002)
function cacheSessionToken(jwtToken) {
    localStorage.setItem("session_token", jwtToken);
}`
    },
    {
      id: '03',
      code: `// Vulnerable: insecure cookie properties (OWASP-A2-003)
function createSessionCookie(userId) {
    document.cookie = "session=" + userId + "; path=/;";
}`
    },
    {
      id: '04',
      code: `// Vulnerable: Math.random for security tokens (OWASP-A2-004)
function generateUserOtpSecret() {
    const otp = Math.random().toString().substring(2, 8);
    const otp_key = "secret_" + Math.random().toString(36);
    return { otp, otp_key };
}`
    },
    {
      id: '05',
      code: `// Vulnerable: Plain http URLs used for communication (OWASP-A2-005)
const defaultApiUrl = "http://unencrypted.internal-services.com/v1/auth";
function fetchPayload() {
    return fetch(defaultApiUrl + "/data");
}`
    }
  ],
  'A3': [
    {
      id: '01',
      code: `// Vulnerable: hardcoded cryptographic token signatures (OWASP-A3-001)
const AWS_ACCESS_SECRET = "AKIAIOSFODNN7EXAMPLE";
const STATIC_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
`
    },
    {
      id: '02',
      code: `// Vulnerable: hardcoded API keys (OWASP-A3-002)
const application_secret_key = "apikey_development_credential_987654321";
const gatewayToken = "token_prod_abc123xyz789";
`
    },
    {
      id: '03',
      code: `// Vulnerable: sensitive tokens exposed in query URL parameters (OWASP-A3-003)
function constructRedirectUrl(username, pwdVal) {
    return "/auth/callback?user=" + username + "&password=" + pwdVal;
}`
    }
  ],
  'A5': [
    {
      id: '01',
      code: `// Vulnerable: Open redirect path assignment (OWASP-A5-001)
function redirectToExternal(targetUrl) {
    window.location.href = targetUrl;
}`
    },
    {
      id: '02',
      code: `// Vulnerable: Client-side role checking guarding access (OWASP-A5-002)
function renderSecureComponents(userContext) {
    if (userContext.role === "admin" || userContext.isAdmin === true) {
        showSpecialSuperAdminMenu();
    }
}`
    }
  ],
  'A6': [
    {
      id: '01',
      code: `// Vulnerable: sensitive password name logged in console (OWASP-A6-001)
function authenticateCredentials(user, password) {
    console.log("Validating payload info for secret: " + password);
}`
    },
    {
      id: '02',
      code: `// Vulnerable: CORS wildcards configured (OWASP-A6-002)
function setupCorsHeaders(res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
}`
    },
    {
      id: '03',
      code: `// Vulnerable: full request or session objects printed to logging endpoints (OWASP-A6-003)
function debugGateway(req) {
    console.log("Full request context logs:", req);
}`
    },
    {
      id: '04',
      code: `// Vulnerable: express initialization without helmet middleware (OWASP-A6-004)
const express = require('express');
const app = express();
app.listen(3002);
`
    }
  ],
  'A7': [
    {
      id: '01',
      code: `// Vulnerable: direct innerHTML assignments (OWASP-A7-001)
function loadUserBadge(element, badgeHtml) {
    element.innerHTML = badgeHtml;
}`
    },
    {
      id: '02',
      code: `// Vulnerable: document.write calls (OWASP-A7-002)
function writeOutputSnippet(content) {
    document.write("<div>" + content + "</div>");
}`
    },
    {
      id: '03',
      code: `// Vulnerable: dangerouslySetInnerHTML React properties (OWASP-A7-003)
function renderDynamicPost(contentStr) {
    return <div dangerouslySetInnerHTML={{ __html: contentStr }} />;
}`
    }
  ],
  'A8': [
    {
      id: '01',
      code: `// Vulnerable: general JSON parsing flagged for safety inspections (OWASP-A8-001)
function loadSerializedPayload(jsonInput) {
    return JSON.parse(jsonInput);
}`
    },
    {
      id: '02',
      code: `// Vulnerable: constructor prototype overrides (OWASP-A8-002)
function pollutePrototype(target, customKey, value) {
    target.__proto__[customKey] = value;
}`
    },
    {
      id: '03',
      code: `// Vulnerable: Object.assign with untrusted second argument parameters (OWASP-A8-003)
function mergeConfigurations(defaultConfig, userPayload) {
    return Object.assign(defaultConfig, userPayload);
}`
    }
  ],
  'A9': [
    {
      id: '01',
      code: `// Vulnerable: importing outdated packages (OWASP-A9-001)
const serialize = require("serialize-javascript");
const yaml = require("js-yaml");
const lodash = require("lodash");
`
    }
  ],
  'A10': [
    {
      id: '01',
      code: `// Vulnerable: dynamic SSRF connection endpoints (OWASP-A10-001)
const axios = require('axios');
function proxyRemoteResource(targetUri) {
    return axios.get(targetUri);
}`
    }
  ]
};

// 2. Templates for Clean/Secure Samples (C-*.js)
const cleanTemplates = {
  'A1': [
    {
      id: '01',
      code: `// Clean: safe function parsing
function executeCodeSecure(userInput) {
    const val = Number(userInput);
    console.log('Result: ' + val);
}`
    },
    {
      id: '02',
      code: `// Clean: passing callback reference directly
function scheduleTaskSecure(callbackFn, delay) {
    setTimeout(callbackFn, delay);
}`
    },
    {
      id: '03',
      code: `// Clean: structured formula invocation
function compileExpressionSecure(staticFormula) {
    const allowedFormulas = { 'add': (a) => a + 5 };
    return allowedFormulas[staticFormula]?.(10) || 0;
}`
    },
    {
      id: '04',
      code: `// Clean: textContent sanitizes values safely
function renderGreetingSecure(element, username) {
    element.textContent = "Hello, " + username + "!";
}`
    },
    {
      id: '05',
      code: `// Helper returning plain text string from data source
function getCleanTextFromEndpoint(source) {
    return (source && source.textContent) || "Safe notification text";
}

// Clean: textContent assignment renders plain text without HTML interpretation
function updateContentSecure(container, apiSource) {
    container.textContent = getCleanTextFromEndpoint(apiSource);
}`
    }
  ],
  'A2': [
    {
      id: '01',
      code: `// Clean: passwords loaded from environment variables
const adminAuthPassword = process.env.ADMIN_FALLBACK_PASSWORD;
function loginMasterSecure(pwd) {
    return pwd === adminAuthPassword;
}`
    },
    {
      id: '02',
      code: `// Clean: secure session cookie state management
function cacheSessionTokenSecure(jwtToken) {
    document.cookie = "session_token=" + jwtToken + "; Secure; HttpOnly; SameSite=Strict";
}`
    },
    {
      id: '03',
      code: `// Clean: cookies configured with secure properties
function createSessionCookieSecure(userId) {
    document.cookie = "session=" + userId + "; path=/; Secure; HttpOnly; SameSite=Strict;";
}`
    },
    {
      id: '04',
      code: `// Clean: secure random number generation
function generateUserOtpSecretSecure() {
    const array = new Uint32Array(2);
    window.crypto.getRandomValues(array);
    const otp = array[0].toString().substring(2, 8);
    const otp_key = "secure_" + array[1].toString(36);
    return { otp, otp_key };
}`
    },
    {
      id: '05',
      code: `// Clean: secure SSL HTTPS protocols used
const defaultApiUrl = "https://encrypted.internal-services.com/v1/auth";
function fetchPayloadSecure() {
    return fetch(defaultApiUrl + "/data");
}`
    }
  ],
  'A3': [
    {
      id: '01',
      code: `// Clean: cryptographic settings loaded from environment
const AWS_ACCESS_SECRET = process.env.AWS_SECRET_ACCESS_KEY;
const STATIC_JWT_TOKEN = process.env.AUTH_JWT_PRIVATE_SIGNATURE;
`
    },
    {
      id: '02',
      code: `// Clean: API requests dispatched through backend proxy without client-exposed secrets
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
      id: '03',
      code: `// Clean: passing values in HTTP post bodies safely
function constructRedirectUrlSecure(username) {
    return "/auth/callback?user=" + encodeURIComponent(username);
}`
    }
  ],
  'A5': [
    {
      id: '01',
      code: `// Clean: safelist checked redirects
const allowedDomains = ["https://app.example.com", "https://api.example.com"];
function redirectToExternalSecure(targetUrl) {
    if (allowedDomains.includes(targetUrl)) {
        window.location.href = targetUrl;
    }
}`
    },
    {
      id: '02',
      code: `// Clean: authorization checks validated on the server API side
function renderSecureComponentsSecure(userContext) {
    // Only query client UI components: server enforces real validation
    if (userContext.isAuthenticated) {
        showSuperUserMenu();
    }
}`
    }
  ],
  'A6': [
    {
      id: '01',
      code: `// Clean: logging benign information logs
function authenticateCredentialsSecure(user) {
    console.log("Validating login request signature for user: " + user);
}`
    },
    {
      id: '02',
      code: `// Clean: restrictive CORS configuration policies
function setupCorsHeadersSecure(res) {
    res.setHeader("Access-Control-Allow-Origin", "https://trusted.production.domain");
}`
    },
    {
      id: '03',
      code: `// Clean: logging specific properties
function debugGatewaySecure(req) {
    console.log("Request incoming path:", req.path);
}`
    },
    {
      id: '04',
      code: `// Clean: express loaded with helmet protection headers
const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.listen(3002);
`
    }
  ],
  'A7': [
    {
      id: '01',
      code: `// Clean: textContent prevents HTML execution injections
function loadUserBadgeSecure(element, badgeHtml) {
    element.textContent = badgeHtml;
}`
    },
    {
      id: '02',
      code: `// Clean: standard text nodes created safely
function writeOutputSnippetSecure(content) {
    const node = document.createTextNode(content);
    document.body.appendChild(node);
}`
    },
    {
      id: '03',
      code: `// Clean: standard React templating values
function renderDynamicPostSecure(contentStr) {
    return <div>{contentStr}</div>;
}`
    }
  ],
  'A8': [
    {
      id: '01',
      code: `// Clean: schema verified parsing processes
function loadSerializedPayloadSecure(jsonInput) {
    const parsed = JSON.parse(jsonInput);
    return validateSchema(parsed);
}`
    },
    {
      id: '02',
      code: `// Clean: creating clean object interfaces
function createCleanProperties() {
    const targetObj = Object.create(null);
    targetObj.safe = true;
    return targetObj;
}`
    },
    {
      id: '03',
      code: `// Clean: safe mapping copy operations with prototype property filtering
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
    }
  ],
  'A9': [
    {
      id: '01',
      code: `// Clean: importing safe or patched libraries
const lodashEs = require("lodash-es");
const safeParser = require("safe-yaml-parser");
`
    }
  ],
  'A10': [
    {
      id: '01',
      code: `// Clean: validated remote SSFR calls
const axios = require('axios');
const safelistEndpoints = ["https://api.verified.com/v1", "https://api.verified.com/v2"];
function proxyRemoteResourceSecure(targetUri) {
    if (safelistEndpoints.includes(targetUri)) {
        return axios.get(targetUri);
    }
}`
    }
  ]
};

// 3. Generate files
const isAllMode = process.argv.includes('--all');
const isPilotMode = process.argv.includes('--pilot') || !isAllMode;

const PILOT_FILES = new Set([
  'V-A5-027.js', 'C-A5-027.js',
  'V-A3-023.js', 'C-A3-023.js',
  'V-A1-007.js', 'C-A1-007.js',
  'V-A1-009.js', 'C-A1-009.js',
  'V-A7-039.js', 'C-A7-039.js',
  'V-A8-049.js', 'C-A8-049.js'
]);

// Determine line ending (preserve CRLF on Windows or existing samples)
const EOL = '\r\n';

let vulnerableGeneratedCount = 0;
let cleanGeneratedCount = 0;
let pilotWrittenCount = 0;

// Loop over templates and duplicate with numbering variations to reach ~50 vulnerable and ~50 clean files
const categories = ['A1', 'A2', 'A3', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10'];
const filesPerTemplate = 2; // With 28 vulnerable templates * 2 = 56 files, and 28 clean templates * 2 = 56 files.

categories.forEach(cat => {
  const vList = vulnerableTemplates[cat] || [];
  const cList = cleanTemplates[cat] || [];

  // Generate Vulnerable variations
  vList.forEach(template => {
    for (let i = 1; i <= filesPerTemplate; i++) {
      const padNum = String(vulnerableGeneratedCount + 1).padStart(3, '0');
      const filename = `V-${cat}-${padNum}.js`;
      const normalizedCode = template.code.replace(/\r?\n/g, EOL);
      const finalCode = `/**${EOL} * Test Vulnerable Sample ${padNum} (${cat})${EOL} * Demonstrates OWASP vulnerabilities.${EOL} */${EOL}${EOL}${normalizedCode}${EOL}${EOL}// Variation signature: #${i}${EOL}`;

      if (!isPilotMode || PILOT_FILES.has(filename)) {
        fs.writeFileSync(path.join(outputDir, filename), finalCode);
        if (PILOT_FILES.has(filename)) pilotWrittenCount++;
      }
      vulnerableGeneratedCount++;
    }
  });

  // Generate Clean variations
  cList.forEach(template => {
    for (let i = 1; i <= filesPerTemplate; i++) {
      const padNum = String(cleanGeneratedCount + 1).padStart(3, '0');
      const filename = `C-${cat}-${padNum}.js`;
      const normalizedCode = template.code.replace(/\r?\n/g, EOL);
      const finalCode = `/**${EOL} * Test Clean Sample ${padNum} (${cat})${EOL} * Safe, compliant implementations.${EOL} */${EOL}${EOL}${normalizedCode}${EOL}${EOL}// Variation signature: #${i}${EOL}`;

      if (!isPilotMode || PILOT_FILES.has(filename)) {
        fs.writeFileSync(path.join(outputDir, filename), finalCode);
        if (PILOT_FILES.has(filename)) pilotWrittenCount++;
      }
      cleanGeneratedCount++;
    }
  });
});

if (isPilotMode) {
  console.log(`Phase 04 Batch A Pilot Mode: generated ${pilotWrittenCount} pilot files (6 V/C pairs).`);
  console.log(`Other 104 files remain unchanged.`);
} else {
  console.log(`Successfully generated ${vulnerableGeneratedCount} vulnerable samples.`);
  console.log(`Successfully generated ${cleanGeneratedCount} clean samples.`);
  console.log(`Total samples generated: ${vulnerableGeneratedCount + cleanGeneratedCount}`);
}

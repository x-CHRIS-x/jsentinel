/**
 * Test Vulnerable Sample 033 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: cross-window postMessage with wildcard target origin (OWASP-A01-001)
function broadcastSessionToken(authToken) {
    window.parent.postMessage({ sessionToken: authToken }, "*");
}

// Variation signature: #1

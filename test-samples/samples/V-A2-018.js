/**
 * Test Vulnerable Sample 018 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Math.random used for CSRF nonce generation (OWASP-A2-004)
function generateCsrfNonce() {
    const nonceVal = "nonce_" + Math.random().toString(36).substring(2);
    const sessionNonce = Math.random().toString(16);
    return { nonceVal, sessionNonce };
}

// Variation signature: #2

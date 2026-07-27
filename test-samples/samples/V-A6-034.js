/**
 * Test Vulnerable Sample 034 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: CORS wildcards configured (OWASP-A6-002)
function setupCorsHeaders(res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
}

// Variation signature: #2

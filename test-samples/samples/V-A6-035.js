/**
 * Test Vulnerable Sample 035 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: full request or session objects printed to logging endpoints (OWASP-A6-003)
function debugGateway(req) {
    console.log("Full request context logs:", req);
}

// Variation signature: #1

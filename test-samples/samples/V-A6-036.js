/**
 * Test Vulnerable Sample 036 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: logging full user authentication context object (OWASP-A6-003)
function auditLoginContext(authContext) {
    console.error("Authentication context failure:", authContext);
}

// Variation signature: #2

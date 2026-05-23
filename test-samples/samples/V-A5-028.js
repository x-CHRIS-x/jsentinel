/**
 * Test Vulnerable Sample 028 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Open redirect path assignment (OWASP-A5-001)
function redirectToExternal(targetUrl) {
    window.location.href = targetUrl;
}

// Variation signature: #2

/**
 * Test Vulnerable Sample 053 (A10)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: client-side fetch to arbitrary user-supplied URL with ambient credentials (CWE-20)
function fetchRemoteData(userProvidedUrl) {
    return fetch(userProvidedUrl, { credentials: "include" });
}

// Variation signature: #1

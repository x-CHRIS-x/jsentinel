/**
 * Test Vulnerable Sample 019 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Plain http URLs used for communication (OWASP-A2-005)
const defaultApiUrl = "http://unencrypted.internal-services.com/v1/auth";
function fetchPayload() {
    return fetch(defaultApiUrl + "/data");
}

// Variation signature: #1

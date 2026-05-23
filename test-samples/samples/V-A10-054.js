/**
 * Test Vulnerable Sample 054 (A10)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dynamic SSRF connection endpoints (OWASP-A10-001)
const axios = require('axios');
function proxyRemoteResource(targetUri) {
    return axios.get(targetUri);
}

// Variation signature: #2

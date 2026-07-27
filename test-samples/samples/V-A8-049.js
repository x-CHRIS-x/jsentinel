/**
 * Test Vulnerable Sample 049 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Object.assign with untrusted second argument parameters (OWASP-A8-003)
function mergeConfigurations(defaultConfig, userPayload) {
    return Object.assign(defaultConfig, userPayload);
}

// Variation signature: #1

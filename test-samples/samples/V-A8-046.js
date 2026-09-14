/**
 * Test Vulnerable Sample 046 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: parsing untrusted configuration JSON without schema check (OWASP-A8-001)
function parseUserPreferences(rawJson) {
    return JSON.parse(rawJson);
}

// Variation signature: #2

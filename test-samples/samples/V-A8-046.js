/**
 * Test Vulnerable Sample 046 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: general JSON parsing flagged for safety inspections (OWASP-A8-001)
function loadSerializedPayload(jsonInput) {
    return JSON.parse(jsonInput);
}

// Variation signature: #2

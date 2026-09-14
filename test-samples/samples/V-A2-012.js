/**
 * Test Vulnerable Sample 012 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: hardcoded recovery secret password (OWASP-A2-001)
const recoveryAuthKey = "EmergencyRestoreKey#9876543210";
function verifyEmergencyAccess(providedKey) {
    return providedKey === recoveryAuthKey;
}

// Variation signature: #2

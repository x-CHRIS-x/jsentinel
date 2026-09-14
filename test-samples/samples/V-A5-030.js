/**
 * Test Vulnerable Sample 030 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: client-side permission flag guarding destructive action (OWASP-A5-002)
function executePurgeOperation(userState) {
    if (userState.role === "admin" || userState.hasPurgePermission === true) {
        triggerSystemPurge();
    }
}

// Variation signature: #2

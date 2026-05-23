/**
 * Test Vulnerable Sample 003 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: string in setTimeout (OWASP-A1-002)
function scheduleTask(callbackStr, delay) {
    setTimeout(callbackStr + "()", delay);
}

// Variation signature: #1

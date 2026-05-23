/**
 * Test Vulnerable Sample 004 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: string in setTimeout (OWASP-A1-002)
function scheduleTask(callbackStr, delay) {
    setTimeout(callbackStr + "()", delay);
}

// Variation signature: #2

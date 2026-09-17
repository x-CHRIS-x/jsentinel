/**
 * Test Vulnerable Sample 004 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dynamic string code in setInterval (OWASP-A1-002)
function startPollingTimer(actionCode, intervalMs) {
    return setInterval(actionCode + "()", intervalMs);
}

// Variation signature: #2

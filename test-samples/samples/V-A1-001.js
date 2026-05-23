/**
 * Test Vulnerable Sample 001 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: eval usage (OWASP-A1-001)
function executeCode(userInput) {
    eval("console.log('Result: ' + " + userInput + ");");
}

// Variation signature: #1

/**
 * Test Vulnerable Sample 002 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dynamic arithmetic expression evaluated via eval (OWASP-A1-001)
function calculateFormula(userFormula) {
    return eval("3 * (" + userFormula + ")");
}

// Variation signature: #2

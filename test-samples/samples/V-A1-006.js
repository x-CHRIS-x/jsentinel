/**
 * Test Vulnerable Sample 006 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: new Function with dynamic argument (OWASP-A1-003)
function compileExpression(dynamicFormula) {
    const fn = new Function("x", "return " + dynamicFormula);
    return fn(10);
}

// Variation signature: #2

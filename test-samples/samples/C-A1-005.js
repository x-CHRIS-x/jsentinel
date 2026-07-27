/**
 * Test Clean Sample 005 (A1)
 * Safe, compliant implementations.
 */

// Clean: structured formula invocation
function compileExpressionSecure(staticFormula) {
    const allowedFormulas = { 'add': (a) => a + 5 };
    return allowedFormulas[staticFormula]?.(10) || 0;
}

// Variation signature: #1

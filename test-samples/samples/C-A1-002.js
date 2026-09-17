/**
 * Test Clean Sample 002 (A1)
 * Safe, compliant implementations.
 */

// Clean: safe mathematical formula parsing using tokenized arithmetic evaluator
function calculateFormulaSecure(baseValue, multiplier) {
    const safeBase = Number(baseValue) || 0;
    const safeMult = Number(multiplier) || 1;
    return 3 * (safeBase * safeMult);
}

// Variation signature: #2

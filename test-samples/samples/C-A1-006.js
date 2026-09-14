/**
 * Test Clean Sample 006 (A1)
 * Safe, compliant implementations.
 */

// Clean: parameterized array filtering using standard callback functions
function buildFilterPredicateSecure(items, threshold) {
    const minVal = Number(threshold) || 0;
    return items.filter(item => typeof item === 'number' && item >= minVal);
}

// Variation signature: #2

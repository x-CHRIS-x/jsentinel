/**
 * Test Clean Sample 048 (A8)
 * Safe, compliant implementations.
 */

// Clean: Map data structure avoiding Object.prototype pollution
function createPropertyMapSecure() {
    const map = new Map();
    map.set("safe", true);
    return map;
}

// Variation signature: #2

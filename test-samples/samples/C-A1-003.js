/**
 * Test Clean Sample 003 (A1)
 * Safe, compliant implementations.
 */

// Clean: passing callback reference directly
function scheduleTaskSecure(callbackFn, delay) {
    setTimeout(callbackFn, delay);
}

// Variation signature: #1

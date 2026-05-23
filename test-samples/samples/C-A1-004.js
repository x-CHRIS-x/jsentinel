/**
 * Test Clean Sample 004 (A1)
 * Safe, compliant implementations.
 */

// Clean: passing callback reference directly
function scheduleTaskSecure(callbackFn, delay) {
    setTimeout(callbackFn, delay);
}

// Variation signature: #2

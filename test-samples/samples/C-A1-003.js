/**
 * Test Clean Sample 003 (A1)
 * Safe, compliant implementations.
 */

// Clean: passing callback function reference to setTimeout
function scheduleTaskSecure(taskFn, delay) {
    if (typeof taskFn === 'function') {
        setTimeout(taskFn, delay);
    }
}

// Variation signature: #1

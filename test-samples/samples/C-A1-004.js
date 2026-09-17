/**
 * Test Clean Sample 004 (A1)
 * Safe, compliant implementations.
 */

// Clean: setInterval passing callback function closure
function startPollingTimerSecure(actionCallback, intervalMs) {
    if (typeof actionCallback === 'function') {
        return setInterval(() => actionCallback(), intervalMs);
    }
    return null;
}

// Variation signature: #2

/**
 * Test Clean Sample 033 (A6)
 * Safe, compliant implementations.
 */

// Clean: cross-window postMessage with strict target origin restriction
function broadcastSessionTokenSecure(authToken) {
    window.parent.postMessage({ sessionToken: authToken }, "https://portal.trusted.domain");
}

// Variation signature: #1

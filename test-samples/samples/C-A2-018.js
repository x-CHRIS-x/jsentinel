/**
 * Test Clean Sample 018 (A2)
 * Safe, compliant implementations.
 */

// Clean: standard cryptographically secure random UUID for nonce generation
function generateCsrfNonceSecure() {
    const nonceVal = "nonce_" + crypto.randomUUID();
    const sessionNonce = crypto.randomUUID();
    return { nonceVal, sessionNonce };
}

// Variation signature: #2

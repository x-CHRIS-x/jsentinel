/**
 * Test Clean Sample 051 (A9)
 * Safe, compliant implementations.
 */

// Clean: transient in-memory token storage preventing persistent web storage exposure
let memoryBearerToken = null;
function persistBearerTokenSecure(token) {
    memoryBearerToken = token;
}
function getBearerTokenSecure() {
    return memoryBearerToken;
}

// Variation signature: #1

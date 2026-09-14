/**
 * Test Clean Sample 013 (A2)
 * Safe, compliant implementations.
 */

// Clean: transient session token stored in module-scoped memory closure
let sessionTokenMemory = null;
function cacheSessionTokenSecure(jwtToken) {
    sessionTokenMemory = jwtToken;
}
function getSessionTokenSecure() {
    return sessionTokenMemory;
}

// Variation signature: #1

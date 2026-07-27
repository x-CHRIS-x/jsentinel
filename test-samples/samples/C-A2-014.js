/**
 * Test Clean Sample 014 (A2)
 * Safe, compliant implementations.
 */

// Clean: secure session cookie state management
function cacheSessionTokenSecure(jwtToken) {
    document.cookie = "session_token=" + jwtToken + "; Secure; HttpOnly; SameSite=Strict";
}

// Variation signature: #2

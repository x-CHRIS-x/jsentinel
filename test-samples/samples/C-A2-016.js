/**
 * Test Clean Sample 016 (A2)
 * Safe, compliant implementations.
 */

// Clean: cookies configured with secure properties
function createSessionCookieSecure(userId) {
    document.cookie = "session=" + userId + "; path=/; Secure; HttpOnly; SameSite=Strict;";
}

// Variation signature: #2

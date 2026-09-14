/**
 * Test Clean Sample 032 (A6)
 * Safe, compliant implementations.
 */

// Clean: logging non-sensitive status message
function recordAuthSessionSecure(user) {
    console.warn("Session established for: " + user);
}

// Variation signature: #2

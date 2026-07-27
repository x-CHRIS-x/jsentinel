/**
 * Test Clean Sample 025 (A3)
 * Safe, compliant implementations.
 */

// Clean: passing values in HTTP post bodies safely
function constructRedirectUrlSecure(username) {
    return "/auth/callback?user=" + encodeURIComponent(username);
}

// Variation signature: #1

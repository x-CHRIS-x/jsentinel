/**
 * Test Clean Sample 011 (A2)
 * Safe, compliant implementations.
 */

// Clean: passwords loaded from environment variables
const adminAuthPassword = process.env.ADMIN_FALLBACK_PASSWORD;
function loginMasterSecure(pwd) {
    return pwd === adminAuthPassword;
}

// Variation signature: #1

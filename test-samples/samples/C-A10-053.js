/**
 * Test Clean Sample 053 (A10)
 * Safe, compliant implementations.
 */

// Clean: destination domain verified against allowlist before sending credentials
const trustedOrigins = ["https://api.verified.com", "https://auth.verified.com"];
function fetchRemoteDataSecure(targetUrl) {
    const parsed = new URL(targetUrl, window.location.href);
    if (trustedOrigins.includes(parsed.origin)) {
        return fetch(targetUrl, { credentials: "include" });
    }
    throw new Error("Untrusted destination origin");
}

// Variation signature: #1

/**
 * Test Clean Sample 028 (A5)
 * Safe, compliant implementations.
 */

// Clean: safelist checked redirects
const allowedDomains = ["https://app.example.com", "https://api.example.com"];
function redirectToExternalSecure(targetUrl) {
    if (allowedDomains.includes(targetUrl)) {
        window.location.href = targetUrl;
    }
}

// Variation signature: #2

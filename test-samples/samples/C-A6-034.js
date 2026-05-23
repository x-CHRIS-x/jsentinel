/**
 * Test Clean Sample 034 (A6)
 * Safe, compliant implementations.
 */

// Clean: restrictive CORS configuration policies
function setupCorsHeadersSecure(res) {
    res.setHeader("Access-Control-Allow-Origin", "https://trusted.production.domain");
}

// Variation signature: #2

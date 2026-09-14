/**
 * Test Clean Sample 036 (A6)
 * Safe, compliant implementations.
 */

// Clean: logging only specific non-sensitive status code
function auditLoginContextSecure(statusCode) {
    console.error("Authentication failure error code:", statusCode);
}

// Variation signature: #2

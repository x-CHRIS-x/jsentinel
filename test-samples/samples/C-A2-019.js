/**
 * Test Clean Sample 019 (A2)
 * Safe, compliant implementations.
 */

// Clean: secure SSL HTTPS protocols used
const defaultApiUrl = "https://encrypted.internal-services.com/v1/auth";
function fetchPayloadSecure() {
    return fetch(defaultApiUrl + "/data");
}

// Variation signature: #1

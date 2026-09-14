/**
 * Test Vulnerable Sample 046 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: parsing untrusted configuration JSON where unvalidated properties control
// destination endpoint URL for sensitive client telemetry transmission (OWASP-A08-001).
// Security context: Transmits sensitive synthetic client session credentials to an unvalidated endpoint URL.
// Under browser fetch semantics, application/json POST triggers a CORS preflight (OPTIONS); if the attacker
// server responds with permissive CORS headers, the sensitive client telemetry payload is transmitted.
function loadAppConfig(rawConfig) {
    const config = JSON.parse(rawConfig);
    const telemetryPayload = {
        sessionToken: "token_synthetic_telemetry_user_session_441",
        activeUser: "researcher@example.internal",
        metrics: { activeViews: 4 }
    };
    // Unsafe context: dispatching sensitive telemetry to arbitrary unvalidated endpoint URL from parsed JSON
    return fetch(config.endpointUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(telemetryPayload)
    });
}

// Variation signature: #2

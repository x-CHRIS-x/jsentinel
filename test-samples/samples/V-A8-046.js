/**
 * Test Vulnerable Sample 046 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: parsing untrusted configuration JSON where unvalidated properties control
// destination endpoint URL for sensitive client telemetry transmission (OWASP-A08-001).
// Security context: Transmits client session telemetry to an unvalidated endpoint URL.
// Under browser fetch semantics, if target host permits cross-origin POST or under simple-request rules,
// sensitive client telemetry payload is transmitted to an attacker-controlled origin.
function loadAppConfig(rawConfig) {
    const config = JSON.parse(rawConfig);
    const telemetryPayload = { sessionStatus: "active" };
    // Unsafe context: dispatching sensitive telemetry to arbitrary unvalidated endpoint URL from parsed JSON
    return fetch(config.endpointUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(telemetryPayload)
    });
}

// Variation signature: #2

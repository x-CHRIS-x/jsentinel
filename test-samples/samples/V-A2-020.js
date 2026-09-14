/**
 * Test Vulnerable Sample 020 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: unencrypted HTTP telemetry reporting endpoint (OWASP-A2-005)
const telemetryEndpoint = "http://telemetry.logging-service.net/events";
function sendTelemetry(eventData) {
    return fetch(telemetryEndpoint, {
        method: "POST",
        body: JSON.stringify(eventData)
    });
}

// Variation signature: #2

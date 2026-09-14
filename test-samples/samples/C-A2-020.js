/**
 * Test Clean Sample 020 (A2)
 * Safe, compliant implementations.
 */

// Clean: encrypted HTTPS telemetry reporting endpoint
const telemetryEndpointSecure = "https://telemetry.logging-service.net/events";
function sendTelemetrySecure(eventData) {
    return fetch(telemetryEndpointSecure, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(eventData)
    });
}

// Variation signature: #2

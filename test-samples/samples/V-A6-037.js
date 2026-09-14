/**
 * Test Vulnerable Sample 037 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: unencrypted WebSocket connection transmitting sensitive telemetry (OWASP-A02-004)
const telemetryWsUrl = "ws://telemetry.unencrypted.internal-services.com/stream";
function connectTelemetryStream() {
    return new WebSocket(telemetryWsUrl);
}

// Variation signature: #1

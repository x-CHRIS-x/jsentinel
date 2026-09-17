/**
 * Test Clean Sample 037 (A6)
 * Safe, compliant implementations.
 */

// Clean: encrypted WebSocket connection using wss protocol
const telemetryWsUrlSecure = "wss://telemetry.encrypted.internal-services.com/stream";
function connectTelemetryStreamSecure() {
    return new WebSocket(telemetryWsUrlSecure);
}

// Variation signature: #1

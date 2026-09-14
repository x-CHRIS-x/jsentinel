/**
 * Test Clean Sample 046 (A8)
 * Safe, compliant implementations.
 */

// Clean: JSON parsing followed by explicit schema verification and endpoint allowlisting.
// Preserves the intended benign telemetry transmission to approved application endpoints
// while blocking transmission to untrusted external destinations.
function verifyAppConfig(config) {
    const fallback = { endpointUrl: '/api/v1/feed' };
    if (!config || typeof config !== 'object') return fallback;
    const allowedEndpoints = ['/api/v1/feed', '/api/v1/profile'];
    if (typeof config.endpointUrl === 'string' && allowedEndpoints.includes(config.endpointUrl)) {
        return { endpointUrl: config.endpointUrl };
    }
    return fallback;
}

function loadAppConfigSecure(rawConfig) {
    const config = JSON.parse(rawConfig);
    const verified = verifyAppConfig(config);
    const telemetryPayload = {
        sessionToken: "token_synthetic_telemetry_user_session_441",
        activeUser: "researcher@example.internal",
        metrics: { activeViews: 4 }
    };
    return fetch(verified.endpointUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(telemetryPayload)
    });
}

// Variation signature: #2

/**
 * Test Clean Sample 046 (A8)
 * Safe, compliant implementations.
 */

// Clean: JSON parsing followed by explicit schema verification and endpoint allowlisting
function verifyAppConfig(config) {
    if (!config || typeof config !== 'object') return null;
    const allowedEndpoints = ['/api/v1/feed', '/api/v1/profile'];
    if (typeof config.endpointUrl === 'string' && allowedEndpoints.includes(config.endpointUrl)) {
        return { endpointUrl: config.endpointUrl };
    }
    return { endpointUrl: '/api/v1/feed' };
}

function loadAppConfigSecure(rawConfig) {
    const config = JSON.parse(rawConfig);
    const verified = verifyAppConfig(config);
    return fetch(verified.endpointUrl);
}

// Variation signature: #2

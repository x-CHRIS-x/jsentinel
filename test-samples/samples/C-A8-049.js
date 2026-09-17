/**
 * Test Clean Sample 049 (A8)
 * Safe, compliant implementations.
 */

// Clean: safe mapping copy operations with prototype property filtering
function sanitizeInputProperties(obj) {
    if (!obj || typeof obj !== 'object') return {};
    const clean = {};
    for (const key of Object.keys(obj)) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            clean[key] = obj[key];
        }
    }
    return clean;
}

function mergeConfigurationsSecure(defaultConfig, userPayload) {
    const sanitizedPayload = sanitizeInputProperties(userPayload);
    return Object.assign({}, defaultConfig, sanitizedPayload);
}

// Variation signature: #1

/**
 * Test Clean Sample 050 (A8)
 * Safe, compliant implementations.
 */

// Clean: safe mapping copy operations
function mergeConfigurationsSecure(defaultConfig, userPayload) {
    const sanitizedPayload = sanitizeInputProperties(userPayload);
    return Object.assign({}, defaultConfig, sanitizedPayload);
}

// Variation signature: #2

/**
 * Test Clean Sample 046 (A8)
 * Safe, compliant implementations.
 */

// Clean: JSON parsing followed by explicit property type validation
function parseUserPreferencesSecure(rawJson) {
    const data = JSON.parse(rawJson);
    return {
        theme: typeof data.theme === 'string' ? data.theme : 'light',
        fontSize: typeof data.fontSize === 'number' ? data.fontSize : 14
    };
}

// Variation signature: #2

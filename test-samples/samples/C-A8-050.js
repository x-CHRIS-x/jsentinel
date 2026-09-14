/**
 * Test Clean Sample 050 (A8)
 * Safe, compliant implementations.
 */

// Clean: strict property picking allowlist preventing prototype pollution
function applyUserThemeSettingsSecure(baseSettings, untrustedOptions) {
    const safeOptions = {};
    const allowedKeys = ['theme', 'accentColor', 'layoutMode'];
    if (untrustedOptions && typeof untrustedOptions === 'object') {
        for (const key of allowedKeys) {
            if (Object.prototype.hasOwnProperty.call(untrustedOptions, key)) {
                safeOptions[key] = untrustedOptions[key];
            }
        }
    }
    return Object.assign({}, baseSettings, safeOptions);
}

// Variation signature: #2

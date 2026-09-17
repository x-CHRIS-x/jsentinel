/**
 * Test Vulnerable Sample 050 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Object.assign copying untrusted options to settings object (OWASP-A8-003)
function applyUserThemeSettings(baseSettings, untrustedOptions) {
    return Object.assign(baseSettings, untrustedOptions);
}

// Variation signature: #2

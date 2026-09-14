/**
 * Test Vulnerable Sample 046 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: parsing untrusted configuration JSON where unvalidated properties control security behavior (OWASP-A8-001)
function loadAppConfig(rawConfig) {
    const config = JSON.parse(rawConfig);
    // Unsafe context: dispatching fetch to arbitrary unvalidated endpoint URL from parsed JSON
    return fetch(config.endpointUrl);
}

// Variation signature: #2

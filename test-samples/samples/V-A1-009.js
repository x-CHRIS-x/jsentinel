/**
 * Test Vulnerable Sample 009 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: function call returned value assigned to innerHTML (OWASP-A1-005)
function updateContent(container, apiSource) {
    container.innerHTML = getRawHtmlFromEndpoint(apiSource);
}

// Variation signature: #1

/**
 * Test Vulnerable Sample 009 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Simulated endpoint helper returning attacker-controlled markup
function getRawHtmlFromEndpoint(source) {
    return (source && source.htmlContent) || "<img src=x onerror=alert(1)>";
}

// Vulnerable: function call returned value assigned to innerHTML (OWASP-A1-005)
function updateContent(container, apiSource) {
    container.innerHTML = getRawHtmlFromEndpoint(apiSource);
}

// Variation signature: #1

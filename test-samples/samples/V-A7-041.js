/**
 * Test Vulnerable Sample 041 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: document.write calls (OWASP-A7-002)
function writeOutputSnippet(content) {
    document.write("<div>" + content + "</div>");
}

// Variation signature: #1

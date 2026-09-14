/**
 * Test Vulnerable Sample 042 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: document.writeln with dynamic user status message (OWASP-A7-002)
function outputUserStatus(statusText) {
    document.writeln("<div>Status: " + statusText + "</div>");
}

// Variation signature: #2

/**
 * Test Vulnerable Sample 007 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: innerHTML with template literal interpolation (OWASP-A1-004)
function renderGreeting(element, username) {
    element.innerHTML = `<div>Hello, ${username}!</div>`;
}

// Variation signature: #1

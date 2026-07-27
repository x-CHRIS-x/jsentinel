/**
 * Test Vulnerable Sample 039 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: direct innerHTML assignments (OWASP-A7-001)
function loadUserBadge(element, badgeHtml) {
    element.innerHTML = badgeHtml;
}

// Variation signature: #1

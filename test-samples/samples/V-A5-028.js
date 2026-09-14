/**
 * Test Vulnerable Sample 028 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: open redirect via window.location.replace (OWASP-A5-001)
function navigateToPartnerSite(partnerUrl) {
    window.location.replace(partnerUrl);
}

// Variation signature: #2

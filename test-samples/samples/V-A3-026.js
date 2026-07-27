/**
 * Test Vulnerable Sample 026 (A3)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: sensitive tokens exposed in query URL parameters (OWASP-A3-003)
function constructRedirectUrl(username, pwdVal) {
    return "/auth/callback?user=" + username + "&password=" + pwdVal;
}

// Variation signature: #2

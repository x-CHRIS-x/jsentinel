/**
 * Test Vulnerable Sample 030 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Client-side role checking guarding access (OWASP-A5-002)
function renderSecureComponents(userContext) {
    if (userContext.role === "admin" || userContext.isAdmin === true) {
        showSpecialSuperAdminMenu();
    }
}

// Variation signature: #2

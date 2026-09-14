/**
 * Test Vulnerable Sample 045 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

function enableAdminPrivileges() {
    window.__adminMode = true;
}

// Vulnerable: parsing untrusted serialized session state and trusting unvalidated properties for authorization decisions (OWASP-A8-001)
function loadSessionState(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (session.isAdmin) {
        enableAdminPrivileges();
    }
    return session;
}

// Variation signature: #1

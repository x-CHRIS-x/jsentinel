/**
 * Test Vulnerable Sample 045 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

function enableAdminPrivileges() {
    window.__adminMode = true;
}

// Concrete protected operation affected by window.__adminMode
function accessAdministrativeDiagnostics() {
    if (window.__adminMode) {
        return "DIAGNOSTIC_DATA: System internals and sensitive user session audit logs.";
    }
    return "ACCESS_DENIED: Administrator privileges required.";
}

// Vulnerable: parsing untrusted serialized session state and trusting unvalidated properties
// to grant elevated privileges and access protected diagnostics (OWASP-A08-001, OWASP-A01-002).
function loadSessionState(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (session.isAdmin) {
        enableAdminPrivileges();
    }
    return session;
}

// Variation signature: #1

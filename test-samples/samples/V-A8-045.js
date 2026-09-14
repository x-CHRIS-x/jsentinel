/**
 * Test Vulnerable Sample 045 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

function enableAdminPrivileges() {
    window.__adminMode = true;
}

// Concrete protected operation: models simulated protected-resource contract; client literals cannot assure production secrecy.
function accessAdministrativeDiagnostics() {
    if (window.__adminMode) {
        return "SIMULATED_DIAGNOSTIC_DATA: System internals and session audit logs.";
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

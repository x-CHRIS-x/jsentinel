/**
 * Test Vulnerable Sample 029 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: client-side role check guarding access to privileged administrative endpoint (OWASP-A01-002).
// System context: The backend endpoint /api/v1/users/:id/grant-superuser has assumed missing
// server-side RBAC enforcement, where client code acts as the sole authorization gate.
// Note: Client snippets alone do not prove backend configuration. Live backend enforcement was NOT RUN;
// this sample models an assumed vulnerable backend configuration.
function executeAdministrativeAction(userContext, targetUserId) {
    if (userContext.role === "admin" || userContext.isAdmin === true) {
        return fetch("/api/v1/users/" + targetUserId + "/grant-superuser", {
            method: "POST"
        });
    }
    return Promise.reject(new Error("Unauthorized"));
}

// Variation signature: #1

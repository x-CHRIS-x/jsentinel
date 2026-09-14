/**
 * Test Vulnerable Sample 029 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: client-side role check guarding access to privileged administrative endpoint (OWASP-A5-002)
function executeAdministrativeAction(userContext, targetUserId) {
    if (userContext.role === "admin" || userContext.isAdmin === true) {
        return fetch("/api/v1/users/" + targetUserId + "/grant-superuser", {
            method: "POST"
        });
    }
    return Promise.reject(new Error("Unauthorized"));
}

// Variation signature: #1

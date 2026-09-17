/**
 * Test Clean Sample 029 (A5)
 * Safe, compliant implementations.
 */

// Clean: administrative action authorization delegated to backend API rather than client checks.
// Architectural assumption: The backend endpoint /api/v1/users/:id/grant-superuser is assumed
// to enforce server-side Role-Based Access Control (RBAC) on session credentials.
// Client code dispenses with cosmetic client-side role gates. Note: Client snippets alone do not
// prove backend configuration; backend enforcement is assumed/simulated with verification NOT RUN.
async function executeAdministrativeActionSecure(targetUserId) {
    const res = await fetch("/api/v1/users/" + targetUserId + "/grant-superuser", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin"
    });
    if (!res.ok) {
        throw new Error("Server rejected unauthorized administrative action");
    }
    return res.json();
}

// Variation signature: #1

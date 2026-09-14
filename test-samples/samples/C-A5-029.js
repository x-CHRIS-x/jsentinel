/**
 * Test Clean Sample 029 (A5)
 * Safe, compliant implementations.
 */

// Clean: administrative action authorization enforced by backend API rather than client checks.
// Architectural assumption: The backend endpoint /api/v1/users/:id/grant-superuser enforces
// server-side Role-Based Access Control (RBAC) on session credentials, rejecting unauthorized users.
// Client code dispenses with cosmetic client-side role gates. Note that client snippets alone do
// not prove backend configuration; security here relies on the verified server authorization contract.
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

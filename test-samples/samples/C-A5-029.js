/**
 * Test Clean Sample 029 (A5)
 * Safe, compliant implementations.
 */

// Clean: administrative action authorization enforced by backend API rather than client checks
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

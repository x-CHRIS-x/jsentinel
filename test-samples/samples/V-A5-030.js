/**
 * Test Vulnerable Sample 030 (A5)
 * Demonstrates OWASP vulnerabilities.
 */

function triggerSystemPurge() {
    return fetch("/api/admin/purge", { method: "POST" });
}

// Vulnerable: client-side permission flag guarding destructive action (OWASP-A5-002)
function executePurgeOperation(userState) {
    if (userState.role === "admin" || userState.hasPurgePermission === true) {
        return triggerSystemPurge();
    }
    return Promise.reject(new Error("Unauthorized"));
}

// Variation signature: #2

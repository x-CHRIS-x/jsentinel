/**
 * Test Clean Sample 029 (A5)
 * Safe, compliant implementations.
 */

// Clean: authorization checks validated on the server API side
async function renderSecureComponentsSecure() {
    const res = await fetch("/api/user/authorized-components");
    if (res.ok) {
        const data = await res.json();
        if (data.canViewAdminMenu) {
            showSpecialSuperAdminMenu();
        }
    }
}

// Variation signature: #1

/**
 * Test Clean Sample 029 (A5)
 * Safe, compliant implementations.
 */

// Clean: authorization checks validated on the server API side
function renderSecureComponentsSecure(userContext) {
    // Only query client UI components: server enforces real validation
    if (userContext.isAuthenticated) {
        showSuperUserMenu();
    }
}

// Variation signature: #1

/**
 * Test Clean Sample 016 (A2)
 * Safe, compliant implementations.
 */

// Clean: non-sensitive UI preference cookie with Secure and SameSite attributes (no false HttpOnly write)
function storeUiPreferenceCookieSecure(themeName) {
    document.cookie = "ui_theme=" + encodeURIComponent(themeName) + "; path=/; Secure; SameSite=Strict;";
}

// Variation signature: #2

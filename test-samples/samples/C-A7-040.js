/**
 * Test Clean Sample 040 (A7)
 * Safe, compliant implementations.
 */

// Clean: textContent prevents HTML execution injections
function loadUserBadgeSecure(element, badgeHtml) {
    element.textContent = badgeHtml;
}

// Variation signature: #2

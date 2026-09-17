/**
 * Test Clean Sample 008 (A1)
 * Safe, compliant implementations.
 */

// Clean: DOM element creation and textContent assignment for user profile
function renderUserProfileSecure(container, bioText) {
    const span = document.createElement("span");
    span.className = "bio-display";
    span.textContent = bioText;
    container.replaceChildren(span);
}

// Variation signature: #2

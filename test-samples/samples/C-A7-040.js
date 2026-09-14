/**
 * Test Clean Sample 040 (A7)
 * Safe, compliant implementations.
 */

// Clean: safe DOM node creation with textContent assignment
function renderUserCommentSecure(container, commentText) {
    const p = document.createElement("p");
    p.textContent = commentText;
    container.replaceChildren(p);
}

// Variation signature: #2

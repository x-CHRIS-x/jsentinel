/**
 * Test Vulnerable Sample 040 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: direct innerHTML assignment with user comment markup (OWASP-A7-001)
function renderUserComment(container, commentMarkup) {
    container.innerHTML = commentMarkup;
}

// Variation signature: #2

/**
 * Test Vulnerable Sample 008 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: innerHTML template literal with user profile markup (OWASP-A1-004)
function renderUserProfile(container, bioText) {
    container.innerHTML = `<span class="bio-display">${bioText}</span>`;
}

// Variation signature: #2

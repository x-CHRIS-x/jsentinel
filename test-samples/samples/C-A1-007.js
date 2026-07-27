/**
 * Test Clean Sample 007 (A1)
 * Safe, compliant implementations.
 */

// Clean: textContent sanitizes values safely
function renderGreetingSecure(element, username) {
    element.textContent = "Hello, " + username + "!";
}

// Variation signature: #1

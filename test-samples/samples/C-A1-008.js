/**
 * Test Clean Sample 008 (A1)
 * Safe, compliant implementations.
 */

// Clean: textContent sanitizes values safely
function renderGreetingSecure(element, username) {
    element.textContent = "Hello, " + username + "!";
}

// Variation signature: #2

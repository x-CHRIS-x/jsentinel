/**
 * Test Vulnerable Sample 048 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: constructor prototype overrides (OWASP-A8-002)
function pollutePrototype(target, customKey, value) {
    target.__proto__[customKey] = value;
}

// Variation signature: #2

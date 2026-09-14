/**
 * Test Vulnerable Sample 034 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: cross-window message handler executing code without origin validation (OWASP-A03-001)
function listenForRemoteCommands() {
    window.addEventListener("message", function(event) {
        eval(event.data.command);
    });
}

// Variation signature: #2

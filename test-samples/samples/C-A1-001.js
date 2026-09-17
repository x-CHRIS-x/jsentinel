/**
 * Test Clean Sample 001 (A1)
 * Safe, compliant implementations.
 */

// Clean: safe function parsing
function executeCodeSecure(userInput) {
    try {
        const parsed = JSON.parse(userInput);
        console.log('Result:', parsed);
    } catch (e) {
        console.error('Invalid input');
    }
}

// Variation signature: #1

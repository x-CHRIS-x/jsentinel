/**
 * Test Clean Sample 005 (A1)
 * Safe, compliant implementations.
 */

// Clean: predefined operator lookup table instead of dynamic code compilation
const operators = {
    double: (x) => x * 2,
    square: (x) => x * x,
    increment: (x) => x + 1
};
function compileExpressionSecure(operatorName, value) {
    const op = operators[operatorName] || ((x) => x);
    return op(value);
}

// Variation signature: #1

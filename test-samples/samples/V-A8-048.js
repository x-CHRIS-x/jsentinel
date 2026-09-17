/**
 * Test Vulnerable Sample 048 (A8)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: constructor prototype pollution via constructor attribute (OWASP-A8-002)
function updateConstructorPrototype(targetObj, propName, propValue) {
    targetObj.constructor.prototype[propName] = propValue;
}

// Variation signature: #2

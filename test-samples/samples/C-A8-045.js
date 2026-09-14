/**
 * Test Clean Sample 045 (A8)
 * Safe, compliant implementations.
 */

// Clean: strict schema validation function verifying expected structure and rejecting unverified privileges
function validateSessionSchema(data) {
    if (!data || typeof data !== 'object') return false;
    return typeof data.userId === 'string' && typeof data.role === 'string';
}

function loadSessionStateSecure(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (!validateSessionSchema(session)) {
        throw new Error('Invalid session payload schema');
    }
    return {
        userId: session.userId,
        role: 'standard_user' // Never grant elevated privileges from untrusted client JSON
    };
}

// Variation signature: #1

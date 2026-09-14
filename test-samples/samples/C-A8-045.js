/**
 * Test Clean Sample 045 (A8)
 * Safe, compliant implementations.
 */

// Clean: strict schema validation function verifying expected structure.
// Important: Schema validation verifies data structure and types, NOT authorization.
// Real authorization must never be derived from client-controlled payload properties.
function validateSessionSchema(data) {
    if (!data || typeof data !== 'object') return false;
    return typeof data.userId === 'string' && typeof data.role === 'string';
}

function loadSessionStateSecure(untrustedState) {
    const session = JSON.parse(untrustedState);
    if (!validateSessionSchema(session)) {
        throw new Error('Invalid session payload schema');
    }
    // Authorization safety: enforce standard unprivileged role regardless of input flags.
    // Structural validation confirms schema; authorization is isolated from client state.
    return {
        userId: session.userId,
        role: 'standard_user' // Never grant elevated privileges from untrusted client JSON
    };
}

// Variation signature: #1

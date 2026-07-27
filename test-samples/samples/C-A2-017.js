/**
 * Test Clean Sample 017 (A2)
 * Safe, compliant implementations.
 */

// Clean: secure random number generation
function generateUserOtpSecretSecure() {
    const array = new Uint32Array(2);
    window.crypto.getRandomValues(array);
    const otp = array[0].toString().substring(2, 8);
    const otp_key = "secure_" + array[1].toString(36);
    return { otp, otp_key };
}

// Variation signature: #1

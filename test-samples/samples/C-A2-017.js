/**
 * Test Clean Sample 017 (A2)
 * Safe, compliant implementations.
 */

// Clean: cryptographically secure random values via Web Crypto API
function generateUserOtpSecretSecure() {
    const array = new Uint32Array(2);
    crypto.getRandomValues(array);
    const otp = String(array[0] % 1000000).padStart(6, '0');
    const otp_key = "secure_" + array[1].toString(36);
    return { otp, otp_key };
}

// Variation signature: #1

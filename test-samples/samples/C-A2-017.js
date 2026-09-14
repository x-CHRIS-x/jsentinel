/**
 * Test Clean Sample 017 (A2)
 * Safe, compliant implementations.
 */

// Clean: cryptographically secure random values via Web Crypto API with 256-bit secret key
function generateUserOtpSecretSecure() {
    // 6-digit numeric OTP generated using crypto.getRandomValues (uniform 20-bit numeric range)
    const otpBytes = new Uint32Array(1);
    crypto.getRandomValues(otpBytes);
    const otp = String(otpBytes[0] % 1000000).padStart(6, '0');

    // Cryptographic secret key using 256 bits (32 bytes) of cryptographic entropy
    const secretBytes = new Uint8Array(32);
    crypto.getRandomValues(secretBytes);
    const otp_key = "secure_" + Array.from(secretBytes, b => b.toString(16).padStart(2, '0')).join('');

    return { otp, otp_key };
}

// Variation signature: #1

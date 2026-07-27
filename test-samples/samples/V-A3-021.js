/**
 * Test Vulnerable Sample 021 (A3)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: hardcoded cryptographic token signatures (OWASP-A3-001)
const AWS_ACCESS_SECRET = "AKIAIOSFODNN7EXAMPLE";
const STATIC_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";


// Variation signature: #1

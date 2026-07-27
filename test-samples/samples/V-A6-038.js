/**
 * Test Vulnerable Sample 038 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: express initialization without helmet middleware (OWASP-A6-004)
const express = require('express');
const app = express();
app.listen(3002);


// Variation signature: #2

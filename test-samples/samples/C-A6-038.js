/**
 * Test Clean Sample 038 (A6)
 * Safe, compliant implementations.
 */

// Clean: express loaded with helmet protection headers
const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.listen(3002);


// Variation signature: #2

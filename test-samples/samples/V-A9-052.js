/**
 * Test Vulnerable Sample 052 (A9)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: importing outdated packages (OWASP-A9-001)
const serialize = require("serialize-javascript");
const yaml = require("js-yaml");
const lodash = require("lodash");


// Variation signature: #2

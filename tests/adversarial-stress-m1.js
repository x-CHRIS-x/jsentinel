/**
 * Comprehensive Adversarial Stress Test Suite for Milestone 1
 */

import parser from '@babel/parser';
import _traverse from '@babel/traverse';
const traverse = _traverse.default || _traverse;

import {
  guidanceCatalog as esmCatalog,
  getGuidance as esmGetGuidance,
  getAllGuidance as esmGetAllGuidance,
  getGuidanceByRuleId as esmGetGuidanceByRuleId,
  GUIDANCE_DISCLAIMER as esmDisclaimer,
  FALLBACK_GUIDANCE as esmFallback
} from '../src/data/guidanceCatalog.js';

import cjsModule from '../vscode-extension/src/data/guidanceCatalog.js';
const {
  guidanceCatalog: cjsCatalog,
  getGuidance: cjsGetGuidance,
  getAllGuidance: cjsGetAllGuidance,
  getGuidanceByRuleId: cjsGetGuidanceByRuleId,
  GUIDANCE_DISCLAIMER: cjsDisclaimer,
  FALLBACK_GUIDANCE: cjsFallback
} = cjsModule;

import { formatJSONReport } from '../src/utils/jsonExporter.js';

// Web Rules
import { accessControlRules } from '../src/scanner/rules/accessControl.js';
import { authRules } from '../src/scanner/rules/auth.js';
import { deserializationRules } from '../src/scanner/rules/deserialization.js';
import { injectionRules } from '../src/scanner/rules/injection.js';
import { knownVulnsRules } from '../src/scanner/rules/knownVulns.js';
import { misconfigRules } from '../src/scanner/rules/misconfig.js';
import { sensitiveDataRules } from '../src/scanner/rules/sensitiveData.js';
import { ssrfRules } from '../src/scanner/rules/ssrf.js';
import { xssRules } from '../src/scanner/rules/xss.js';

const allWebRules = [
  ...accessControlRules,
  ...authRules,
  ...deserializationRules,
  ...injectionRules,
  ...knownVulnsRules,
  ...misconfigRules,
  ...sensitiveDataRules,
  ...ssrfRules,
  ...xssRules
];

// Extension Rules & Scanner
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { allRules: allExtRules } = require('../vscode-extension/src/scanner/rules.js');
const { scanCode: extScanCode } = require('../vscode-extension/src/scanner/scannerEngine.js');

let passed = 0;
let failed = 0;
const errors = [];

function assert(condition, message) {
  if (condition) {
    passed++;
  } else {
    failed++;
    errors.push(message);
    console.error(`  ✕ FAILED: ${message}`);
  }
}

function runWebRules(code, fileName = 'test.js') {
  const issues = [];
  let ast;
  try {
    ast = parser.parse(code, {
      sourceType: 'module',
      errorRecovery: true,
      plugins: ['jsx', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator']
    });
  } catch (err) {
    return { issues: [], error: err.message };
  }

  for (const rule of allWebRules) {
    try {
      const visitorHandlers = rule.visitor(issues);
      traverse(ast, visitorHandlers);
    } catch (e) {
      // rule error
    }
  }

  const codeLines = code.split(/\r?\n/);
  issues.forEach(issue => {
    if (!issue.guidanceId) {
      issue.guidanceId = issue.id;
    }
    if (typeof issue.line === 'number' && issue.line >= 1 && issue.line <= codeLines.length) {
      issue.sourceLine = codeLines[issue.line - 1].trim();
    } else {
      issue.sourceLine = '';
    }
  });

  return { issues };
}

console.log('======================================================================');
console.log('  STARTING ADVERSARIAL STRESS TEST SUITE — MILESTONE 1');
console.log('======================================================================\n');

// -------------------------------------------------------------------
// SECTION 1: Standard & Corner-Case Inputs for getGuidance (ESM & CJS)
// -------------------------------------------------------------------
console.log('[1/8] Testing Standard & Boundary Inputs against getGuidance()...');

const implementations = [
  { name: 'ESM', fn: esmGetGuidance, fallback: esmFallback },
  { name: 'CJS', fn: cjsGetGuidance, fallback: cjsFallback }
];

const boundaryInputs = [
  { label: 'undefined', input: undefined },
  { label: 'null', input: null },
  { label: 'empty string', input: '' },
  { label: 'whitespace only', input: '   \t\n  ' },
  { label: 'number zero', input: 0 },
  { label: 'positive number', input: 42 },
  { label: 'negative number', input: -1 },
  { label: 'NaN', input: NaN },
  { label: 'Infinity', input: Infinity },
  { label: 'boolean true', input: true },
  { label: 'boolean false', input: false },
  { label: 'Symbol', input: Symbol('exploit') },
  { label: 'BigInt', input: BigInt(999999) },
  { label: 'Function', input: () => ({ id: 'OWASP-A01-001' }) },
  { label: 'Empty array', input: [] },
  { label: 'Array of strings', input: ['OWASP-A01-001', 'OWASP-A02-001'] },
  { label: 'Empty object', input: {} },
  { label: 'Object with null id', input: { id: null } },
  { label: 'Object with undefined id', input: { id: undefined } },
  { label: 'Object with empty string id', input: { id: '' } },
  { label: 'Object with whitespace id', input: { id: '   ' } },
  { label: 'Object with numeric id', input: { id: 123 } },
  { label: 'Object with boolean id', input: { id: true } },
  { label: 'Object with object id', input: { id: { nested: 'val' } } },
  { label: 'Object with array id', input: { id: ['OWASP-A01-001'] } },
  { label: 'Object with null guidanceId', input: { guidanceId: null } },
  { label: 'Object with numeric guidanceId', input: { guidanceId: 999 } },
  { label: 'Object with boolean guidanceId', input: { guidanceId: false } },
  { label: 'Object with object guidanceId', input: { guidanceId: {} } },
  { label: 'Object with empty guidanceId', input: { guidanceId: '' } },
  { label: 'Object with whitespace guidanceId', input: { guidanceId: '   ' } },
  { label: 'Object with unknown id', input: { id: 'UNKNOWN-RULE-XYZ' } },
  { label: 'Object with unknown guidanceId', input: { guidanceId: 'UNKNOWN-GUIDANCE-ABC' } },
  { label: 'Object with SQL injection pattern in id', input: { id: "' OR '1'='1" } },
  { label: 'Object with XSS in id', input: { id: '<script>alert(1)</script>' } },
  { label: 'Object with path traversal in id', input: { id: '../../../../etc/passwd' } },
  { label: 'Object with null byte in id', input: { id: 'OWASP-A01-001\0malicious' } },
  { label: 'String with null byte', input: 'OWASP-A01-001\0malicious' },
  { label: 'String with XSS', input: '<img src=x onerror=alert(1)>' },
  { label: 'Object with Object.create(null)', input: Object.create(null) }
];

for (const { name, fn } of implementations) {
  for (const { label, input } of boundaryInputs) {
    try {
      const result = fn(input);
      assert(
        result !== null && typeof result === 'object',
        `[${name}] getGuidance(${label}) must return a non-null object`
      );
      assert(
        typeof result.guidanceId === 'string' && result.guidanceId.length > 0,
        `[${name}] getGuidance(${label}) returned object must have non-empty guidanceId`
      );
      assert(
        typeof result.recommendedAction === 'string' && result.recommendedAction.length > 0,
        `[${name}] getGuidance(${label}) returned object must have non-empty recommendedAction`
      );
      assert(
        Array.isArray(result.approaches) && result.approaches.length <= 2,
        `[${name}] getGuidance(${label}) approaches must be Array of length <= 2`
      );
      assert(
        Array.isArray(result.verifySteps) && result.verifySteps.length >= 1,
        `[${name}] getGuidance(${label}) verifySteps must be Array of length >= 1`
      );
    } catch (err) {
      assert(false, `[${name}] getGuidance(${label}) threw an unexpected exception: ${err.message}`);
    }
  }
}

// Circular reference test
for (const { name, fn } of implementations) {
  const circularObj = { id: 'OWASP-A01-001' };
  circularObj.self = circularObj;
  try {
    const res = fn(circularObj);
    assert(res.guidanceId === 'OWASP-A01-001', `[${name}] getGuidance with circular object resolves correctly`);
  } catch (err) {
    assert(false, `[${name}] getGuidance with circular object threw: ${err.message}`);
  }
}

// -------------------------------------------------------------------
// SECTION 2: Prototype Pollution & Inherited Property Probing
// -------------------------------------------------------------------
console.log('[2/8] Probing Prototype Property Names against getGuidance()...');

const protoProps = ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable'];
const protoFindings = [];

for (const { name, fn } of implementations) {
  for (const prop of protoProps) {
    const resString = fn(prop);
    const isSafeString = resString && resString.guidanceId === 'UNKNOWN' && Array.isArray(resString.approaches);
    if (!isSafeString) {
      protoFindings.push({ target: name, input: prop, returned: typeof resString === 'function' ? 'function' : resString });
    }

    const resObj = fn({ id: prop });
    const isSafeObj = resObj && resObj.guidanceId === 'UNKNOWN' && Array.isArray(resObj.approaches);
    if (!isSafeObj) {
      protoFindings.push({ target: name, input: `{ id: '${prop}' }`, returned: typeof resObj === 'function' ? 'function' : resObj });
    }
  }
}

if (protoFindings.length > 0) {
  console.warn(`  ⚠️ ADVERSARIAL VULNERABILITY FOUND: Prototype property leakage in getGuidance:`);
  protoFindings.forEach(f => console.warn(`     - [${f.target}] Input '${f.input}' leaked prototype property instead of FALLBACK_GUIDANCE`));
} else {
  console.log('  ✓ getGuidance is immune to prototype property lookup leakage');
}

// -------------------------------------------------------------------
// SECTION 3: Variant Resolution & Substring Fallback Logic
// -------------------------------------------------------------------
console.log('[3/8] Testing Variant Resolution & Fallback Hierarchy...');

for (const { name, fn } of implementations) {
  // Exact variant resolution
  const r1 = fn('OWASP-A02-005:credential');
  assert(r1.guidanceId === 'OWASP-A02-005:credential', `[${name}] Exact variant 'OWASP-A02-005:credential' resolves`);
  assert(r1.variant === 'credential', `[${name}] Variant field is 'credential'`);

  const r2 = fn({ guidanceId: 'OWASP-A02-005:network-address' });
  assert(r2.guidanceId === 'OWASP-A02-005:network-address', `[${name}] Object guidanceId 'OWASP-A02-005:network-address' resolves`);

  const r3 = fn({ guidanceId: 'OWASP-A06-001:express-headers' });
  assert(r3.guidanceId === 'OWASP-A06-001:express-headers', `[${name}] Variant 'OWASP-A06-001:express-headers' resolves`);

  const r4 = fn({ guidanceId: 'OWASP-A06-001:dynamic-request-target' });
  assert(r4.guidanceId === 'OWASP-A06-001:dynamic-request-target', `[${name}] Variant 'OWASP-A06-001:dynamic-request-target' resolves`);

  const r5 = fn({ guidanceId: 'OWASP-A06-001:component-review' });
  assert(r5.guidanceId === 'OWASP-A06-001:component-review', `[${name}] Variant 'OWASP-A06-001:component-review' resolves`);

  // Non-existent variant with valid base rule -> falls back to base rule guidance!
  const rFallbackBase = fn('OWASP-A02-005:non-existent-subscenario');
  assert(rFallbackBase.guidanceId === 'OWASP-A02-005', `[${name}] Unknown variant 'OWASP-A02-005:non-existent-subscenario' safely falls back to base rule 'OWASP-A02-005'`);

  // Issue object with guidanceId unknown variant and valid id
  const rObjFallback = fn({ id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:invalid-variant' });
  assert(rObjFallback.guidanceId === 'OWASP-A06-001', `[${name}] Issue object with unknown variant falls back to base rule`);

  // Issue object with guidanceId unknown rule and valid id
  const rObjUnknownGuidance = fn({ id: 'OWASP-A01-001', guidanceId: 'INVALID:unknown' });
  assert(rObjUnknownGuidance.guidanceId === 'OWASP-A01-001', `[${name}] Issue object with invalid guidanceId falls back to valid id`);
}

// -------------------------------------------------------------------
// SECTION 4: Deep Scan for Forbidden Keys & Prescriptive Patterns
// -------------------------------------------------------------------
console.log('[4/8] Scanning Catalog for Forbidden Keys & Prescriptive Patterns...');

const FORBIDDEN_KEYS = [
  'bad', 'good', 'replacementCode', 'goodSnippet', 'badSnippet',
  'fix', 'applyFix', 'codeFix', 'deterministic', 'patch', 'autoFix', 'codeFixGuide'
];

function deepCheckKeys(obj, path = '') {
  if (!obj || typeof obj !== 'object') return;
  for (const key of Object.keys(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    assert(
      !FORBIDDEN_KEYS.includes(key),
      `Catalog entry contains forbidden key "${key}" at ${currentPath}`
    );
    deepCheckKeys(obj[key], currentPath);
  }
}

deepCheckKeys(esmCatalog, 'esmCatalog');
deepCheckKeys(cjsCatalog, 'cjsCatalog');
deepCheckKeys(esmFallback, 'esmFallback');
deepCheckKeys(cjsFallback, 'cjsFallback');

// Check approaches text for prescriptive copy-paste strings
for (const [key, record] of Object.entries(esmCatalog)) {
  for (let i = 0; i < record.approaches.length; i++) {
    const approach = record.approaches[i];
    assert(
      !approach.toLowerCase().includes('replace with:'),
      `[${key}] Approach ${i} must not contain prescriptive "replace with:"`
    );
    assert(
      !approach.toLowerCase().includes('copy and paste'),
      `[${key}] Approach ${i} must not contain "copy and paste"`
    );
    assert(
      !approach.toLowerCase().includes('auto-fix'),
      `[${key}] Approach ${i} must not contain "auto-fix"`
    );
  }
}

// -------------------------------------------------------------------
// SECTION 5: getGuidanceByRuleId Adversarial Inputs
// -------------------------------------------------------------------
console.log('[5/8] Testing getGuidanceByRuleId() Robustness...');

for (const { name } of implementations) {
  const fn = name === 'ESM' ? esmGetGuidanceByRuleId : cjsGetGuidanceByRuleId;

  assert(Array.isArray(fn(null)) && fn(null).length === 0, `[${name}] getGuidanceByRuleId(null) returns empty array`);
  assert(Array.isArray(fn(undefined)) && fn(undefined).length === 0, `[${name}] getGuidanceByRuleId(undefined) returns empty array`);
  assert(Array.isArray(fn('')) && fn('').length === 0, `[${name}] getGuidanceByRuleId("") returns empty array`);
  assert(Array.isArray(fn(123)) && fn(123).length === 0, `[${name}] getGuidanceByRuleId(123) returns empty array`);
  assert(Array.isArray(fn({})) && fn({}).length === 0, `[${name}] getGuidanceByRuleId({}) returns empty array`);
  assert(Array.isArray(fn('NON-EXISTENT')) && fn('NON-EXISTENT').length === 0, `[${name}] getGuidanceByRuleId('NON-EXISTENT') returns empty array`);

  // Substring match should NOT return partial matches
  assert(fn('OWASP').length === 0, `[${name}] getGuidanceByRuleId('OWASP') does not perform loose partial matching`);

  // Exact base rule queries
  const a06 = fn('OWASP-A06-001');
  assert(a06.length === 4, `[${name}] getGuidanceByRuleId('OWASP-A06-001') returns 4 records (base + 3 variants)`);

  const a02_005 = fn('OWASP-A02-005');
  assert(a02_005.length === 3, `[${name}] getGuidanceByRuleId('OWASP-A02-005') returns 3 records (base + 2 variants)`);

  const a01_001 = fn('OWASP-A01-001');
  assert(a01_001.length === 1, `[${name}] getGuidanceByRuleId('OWASP-A01-001') returns 1 record`);
}

// -------------------------------------------------------------------
// SECTION 6: Rule Parity Between Web and Extension Rules
// -------------------------------------------------------------------
console.log('[6/8] Verifying Web and Extension Rule Set Parity...');

assert(allWebRules.length === 27, `Web rules count is exactly 27 (found ${allWebRules.length})`);
assert(allExtRules.length === 27, `Extension rules count is exactly 27 (found ${allExtRules.length})`);

const webRuleNames = new Set(allWebRules.map(r => r.name));
const extRuleNames = new Set(allExtRules.map(r => r.name));

assert(webRuleNames.size === 27, 'Web rules has 27 unique rule names');
assert(extRuleNames.size === 27, 'Extension rules has 27 unique rule names');

for (const name of webRuleNames) {
  assert(extRuleNames.has(name), `Extension rules contain rule "${name}"`);
}

// -------------------------------------------------------------------
// SECTION 7: Scanner Engine Invariance & Multi-Scenario Attribution
// -------------------------------------------------------------------
console.log('[7/8] Testing Web and Extension Scanner Engine Multi-Scenario Routing...');

// Test 1: AWS Secret detection -> must have guidanceId "OWASP-A02-005:credential"
const awsCode = `const val = "AKIA1111111111111111";`;
const webAws = runWebRules(awsCode);
assert(webAws.issues.length >= 1, 'Web scanner finds issue in AWS credential code');
const webAwsIssue = webAws.issues.find(i => i.id === 'OWASP-A02-005');
assert(webAwsIssue !== undefined, 'Web scanner flags OWASP-A02-005');
assert(webAwsIssue.guidanceId === 'OWASP-A02-005:credential', 'Web scanner sets guidanceId to OWASP-A02-005:credential');
assert(typeof webAwsIssue.sourceLine === 'string' && webAwsIssue.sourceLine.includes('AKIA1111111111111111'), 'Web scanner attaches exact sourceLine');
assert(!FORBIDDEN_KEYS.some(k => k in webAwsIssue), 'Web scanner finding contains zero forbidden keys');

const extAws = extScanCode(awsCode, 'test-aws.js', allExtRules);
const extAwsIssue = extAws.issues.find(i => i.id === 'OWASP-A02-005');
assert(extAwsIssue !== undefined, 'Extension scanner flags OWASP-A02-005');
assert(extAwsIssue.guidanceId === 'OWASP-A02-005:credential', 'Extension scanner sets guidanceId to OWASP-A02-005:credential');

// Test 2: IP Address detection -> must have guidanceId "OWASP-A02-005:network-address"
const ipCode = `const host = "192.168.1.100";`;
const webIp = runWebRules(ipCode);
const webIpIssue = webIp.issues.find(i => i.id === 'OWASP-A02-005');
assert(webIpIssue !== undefined, 'Web scanner flags OWASP-A02-005 for IP');
assert(webIpIssue.guidanceId === 'OWASP-A02-005:network-address', 'Web scanner sets guidanceId to OWASP-A02-005:network-address');

const extIp = extScanCode(ipCode, 'test-ip.js', allExtRules);
const extIpIssue = extIp.issues.find(i => i.id === 'OWASP-A02-005');
assert(extIpIssue !== undefined, 'Extension scanner flags OWASP-A02-005 for IP');
assert(extIpIssue.guidanceId === 'OWASP-A02-005:network-address', 'Extension scanner sets guidanceId to OWASP-A02-005:network-address');

// Test 3: Express default headers -> must have guidanceId "OWASP-A06-001:express-headers"
const expressCode = `import express from 'express';\nconst app = express();`;
const webExp = runWebRules(expressCode);
const webExpIssue = webExp.issues.find(i => i.id === 'OWASP-A06-001');
assert(webExpIssue !== undefined, 'Web scanner flags OWASP-A06-001 for express without helmet');
assert(webExpIssue.guidanceId === 'OWASP-A06-001:express-headers', 'Web scanner sets guidanceId to express-headers');

const extExp = extScanCode(expressCode, 'test-exp.js', allExtRules);
const extExpIssue = extExp.issues.find(i => i.id === 'OWASP-A06-001');
assert(extExpIssue !== undefined, 'Extension scanner flags OWASP-A06-001 for express without helmet');
assert(extExpIssue.guidanceId === 'OWASP-A06-001:express-headers', 'Extension scanner sets guidanceId to express-headers');

// Test 4: Axios dynamic target -> must have guidanceId "OWASP-A06-001:dynamic-request-target"
const axiosCode = `import axios from 'axios';\naxios.get(userTargetUrl);`;
const webAxios = runWebRules(axiosCode);
const webAxiosIssue = webAxios.issues.find(i => i.id === 'OWASP-A06-001');
assert(webAxiosIssue !== undefined, 'Web scanner flags OWASP-A06-001 for dynamic axios target');
assert(webAxiosIssue.guidanceId === 'OWASP-A06-001:dynamic-request-target', 'Web scanner sets guidanceId to dynamic-request-target');

const extAxios = extScanCode(axiosCode, 'test-axios.js', allExtRules);
const extAxiosIssue = extAxios.issues.find(i => i.id === 'OWASP-A06-001');
assert(extAxiosIssue !== undefined, 'Extension scanner flags OWASP-A06-001 for dynamic axios target');
assert(extAxiosIssue.guidanceId === 'OWASP-A06-001:dynamic-request-target', 'Extension scanner sets guidanceId to dynamic-request-target');

// Test 5: Deprecated library component review -> must have guidanceId "OWASP-A06-001:component-review"
const lodashCode = `const lodash = require("lodash");`;
const webLodash = runWebRules(lodashCode);
const webLodashIssue = webLodash.issues.find(i => i.id === 'OWASP-A06-001');
assert(webLodashIssue !== undefined, 'Web scanner flags OWASP-A06-001 for lodash');
assert(webLodashIssue.guidanceId === 'OWASP-A06-001:component-review', 'Web scanner sets guidanceId to component-review');

const extLodash = extScanCode(lodashCode, 'test-lodash.js', allExtRules);
const extLodashIssue = extLodash.issues.find(i => i.id === 'OWASP-A06-001');
assert(extLodashIssue !== undefined, 'Extension scanner flags OWASP-A06-001 for lodash');
assert(extLodashIssue.guidanceId === 'OWASP-A06-001:component-review', 'Extension scanner sets guidanceId to component-review');

// -------------------------------------------------------------------
// SECTION 8: JSON Exporter Format & Disclaimer Integrity
// -------------------------------------------------------------------
console.log('[8/8] Testing JSON Exporter Resilience & Disclaimer Integrity...');

const emptyReport = formatJSONReport([], {}, []);
assert(emptyReport.meta !== null && typeof emptyReport.meta === 'object', 'formatJSONReport handles empty findings with valid meta');
assert(typeof emptyReport.meta.disclaimer === 'string' && emptyReport.meta.disclaimer.includes('Guidance only'), 'JSON report includes mandatory educational disclaimer');
assert(Array.isArray(emptyReport.issues) && emptyReport.issues.length === 0, 'formatJSONReport returns empty issues array');

const mockResults = [
  {
    fileName: 'src/test.js',
    success: true,
    issues: [
      {
        id: 'OWASP-A01-001',
        guidanceId: 'OWASP-A01-001',
        severity: 'HIGH',
        category: 'A01:2021-Broken Access Control',
        title: 'Open Redirect Navigation Target',
        message: 'Potential open redirect vulnerability detected.',
        line: 42,
        column: 5,
        sourceLine: 'window.location.href = dest;',
        suggestion: 'Allow only configured, trusted destinations.'
      },
      {
        id: 'OWASP-A02-005',
        guidanceId: 'OWASP-A02-005:credential',
        severity: 'CRITICAL',
        category: 'A02:2021-Cryptographic Failures',
        title: 'Hardcoded Secret Token or Credential',
        message: 'Hardcoded AWS credential detected.',
        line: 10,
        column: 1,
        sourceLine: 'const key = "AKIA...";',
        suggestion: 'Load credentials from secure environment secrets.'
      }
    ]
  }
];

const mockStats = {
  totalIssues: 2,
  activeIssuesCount: 1,
  criticalIssues: 1,
  highIssues: 1,
  mediumIssues: 0,
  lowIssues: 0,
  securityScore: 70
};

const mockCategories = [
  { name: 'A01:2021-Broken Access Control', count: 1, severity: 'HIGH' },
  { name: 'A02:2021-Cryptographic Failures', count: 1, severity: 'CRITICAL' }
];

const formatted = formatJSONReport(mockResults, mockStats, mockCategories, ['src/test.js:OWASP-A01-001:42:5']);
assert(formatted.issues.length === 2, 'formatJSONReport formats 2 issues');
assert(formatted.issues[0].isFalsePositive === true, 'False positive status correctly flagged on finding 0');
assert(formatted.issues[1].isFalsePositive === false, 'Finding 1 isFalsePositive is false');
assert(formatted.issues[0].guidanceId === 'OWASP-A01-001', 'Finding 0 guidanceId preserved');
assert(formatted.issues[1].guidanceId === 'OWASP-A02-005:credential', 'Finding 1 guidanceId preserved');
assert(!FORBIDDEN_KEYS.some(k => k in formatted.issues[0]), 'JSON issue 0 contains zero forbidden keys');
assert(!FORBIDDEN_KEYS.some(k => k in formatted.issues[1]), 'JSON issue 1 contains zero forbidden keys');

console.log('\n======================================================================');
console.log(`ADVERSARIAL STRESS TEST SUMMARY: ${passed} passed, ${failed} failed`);
console.log(`Prototype property leaks detected: ${protoFindings.length}`);
console.log('======================================================================\n');

if (failed > 0) {
  console.error('Failure Details:\n' + errors.map((e, idx) => `${idx + 1}. ${e}`).join('\n'));
  process.exit(1);
} else {
  console.log('✔ ALL ADVERSARIAL STRESS TESTS EXECUTED AND PASSED!');
  process.exit(0);
}

import { guidanceCatalog as esmCatalog, getGuidance as esmGetGuidance, getAllGuidance as esmGetAllGuidance, getGuidanceByRuleId as esmGetGuidanceByRuleId, GUIDANCE_DISCLAIMER as esmDisclaimer, FALLBACK_GUIDANCE as esmFallback } from '../src/data/guidanceCatalog.js';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const cjsModule = require('../vscode-extension/src/data/guidanceCatalog.js');
const { guidanceCatalog: cjsCatalog, getGuidance: cjsGetGuidance, getAllGuidance: cjsGetAllGuidance, getGuidanceByRuleId: cjsGetGuidanceByRuleId, GUIDANCE_DISCLAIMER: cjsDisclaimer, FALLBACK_GUIDANCE: cjsFallback } = cjsModule;
import { scanSourceCode } from './e2e/helpers/testUtils.js';
import { formatJSONReport } from '../src/utils/jsonExporter.js';
import * as fsLib from 'fs';

let total = 0, passed = 0, failed = 0;
const errors = [];
function check(cond, desc) {
  total++;
  if (cond) { passed++; }
  else { failed++; errors.push(desc); console.error('  [FAIL] ' + desc); }
}

console.log('======================================================================');
console.log('  CHALLENGER INDEPENDENT EMPIRICAL STRESS & ADVERSARIAL HARNESS');
console.log('======================================================================\n');

// 1. Boundary & Malformed Inputs
console.log('[1/7] Testing Extreme Boundaries & Malformed Inputs for getGuidance()...');
const malformed = [
  null, undefined, '', '   ', '\t\n\r', 123, 0, -1, NaN, Infinity, true, false,
  Symbol('test'), BigInt(9999999), () => {}, [], [1, 2, 3], ['OWASP-A01-001'],
  {}, { id: null }, { id: undefined }, { id: '' }, { id: 123 }, { id: false },
  { id: {} }, { guidanceId: null }, { guidanceId: undefined }, { guidanceId: '' },
  { guidanceId: 123 }, { id: 'NON_EXISTENT_RULE' }, { guidanceId: 'NON_EXISTENT_GUIDANCE' },
  { id: 'NON_EXISTENT', guidanceId: 'NON_EXISTENT_VARIANT' }, 'NON_EXISTENT_RULE_STRING',
  'OWASP-A02-005:unknown-variant-xyz', 'OWASP-A06-001:fake-variant-abc',
  'OWASP-A99-999:unknown', '   OWASP-A01-001   ', '   OWASP-A02-005:credential   '
];
for (const [engineName, getG, fallback] of [['ESM getGuidance', esmGetGuidance, esmFallback], ['CJS getGuidance', cjsGetGuidance, cjsFallback]]) {
  for (const input of malformed) {
    try {
      const res = getG(input);
      check(res !== null && typeof res === 'object', engineName + ' returned object for: ' + String(input));
      check(typeof res.guidanceId === 'string' && res.guidanceId.length > 0, engineName + ' has valid guidanceId for: ' + String(input));
      check(typeof res.title === 'string' && res.title.length > 0, engineName + ' has valid title');
      check(typeof res.risk === 'string' && res.risk.length > 0, engineName + ' has valid risk');
      check(typeof res.cannotInfer === 'string' && res.cannotInfer.length > 0, engineName + ' has valid cannotInfer');
      check(Array.isArray(res.approaches) && res.approaches.length > 0, engineName + ' has approaches array');
      check(Array.isArray(res.verifySteps) && res.verifySteps.length > 0, engineName + ' has verifySteps array');
      check(Array.isArray(res.references) && res.references.length > 0, engineName + ' has references array');
    } catch (err) {
      check(false, engineName + ' threw exception on input ' + String(input) + ': ' + err.message);
    }
  }
}

// 2. Prototype Property Probing vs getGuidance
console.log('[2/7] Probing Prototype Property Names against getGuidance()...');
const protoProps = ['toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'constructor', '__proto__', '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__'];
for (const [engineName, getG, fallback] of [['ESM getGuidance', esmGetGuidance, esmFallback], ['CJS getGuidance', cjsGetGuidance, cjsFallback]]) {
  for (const prop of protoProps) {
    const resString = getG(prop);
    check(resString === fallback, engineName + ' safely returned fallback for prototype string ' + prop);
    check(resString.guidanceId === 'UNKNOWN', engineName + ' ' + prop + ' returned fallback guidanceId UNKNOWN');

    const resObjId = getG({id: prop});
    check(resObjId === fallback, engineName + ' safely returned fallback for object with id ' + prop);

    const resObjGuidanceId = getG({guidanceId: prop});
    check(resObjGuidanceId === fallback, engineName + ' safely returned fallback for object with guidanceId ' + prop);

    const resVariant = getG(prop + ':variant');
    check(resVariant === fallback, engineName + ' safely returned fallback for variant with proto base ' + prop + ':variant');
  }
}
// 3. Variant Resolution & Fallback Hierarchy
console.log('[3/7] Testing Variant Resolution and Graceful Fallback Hierarchy...');
const fallbackVariant1 = esmGetGuidance('OWASP-A02-005:invalid-subvariant');
check(fallbackVariant1.guidanceId === 'OWASP-A02-005', 'OWASP-A02-005:invalid-subvariant fell back to base OWASP-A02-005 record');

const fallbackVariant2 = esmGetGuidance({ id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:unknown-sub-type' });
check(fallbackVariant2.guidanceId === 'OWASP-A06-001', 'OWASP-A06-001 with unknown guidanceId fell back to base OWASP-A06-001 record');

const validVariantA02Cred = esmGetGuidance({ id: 'OWASP-A02-005', guidanceId: 'OWASP-A02-005:credential' });
check(validVariantA02Cred.guidanceId === 'OWASP-A02-005:credential', 'Resolved OWASP-A02-005:credential variant');
check(validVariantA02Cred.title.includes('Credential'), 'OWASP-A02-005:credential title specifically addresses credentials');

const validVariantA02Net = esmGetGuidance({ id: 'OWASP-A02-005', guidanceId: 'OWASP-A02-005:network-address' });
check(validVariantA02Net.guidanceId === 'OWASP-A02-005:network-address', 'Resolved OWASP-A02-005:network-address variant');
check(validVariantA02Net.title.includes('Network IP Address'), 'OWASP-A02-005:network-address title specifically addresses IP addresses');

const validVariantA06Comp = esmGetGuidance({ id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:component-review' });
check(validVariantA06Comp.guidanceId === 'OWASP-A06-001:component-review', 'Resolved OWASP-A06-001:component-review variant');

const validVariantA06Exp = esmGetGuidance({ id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:express-headers' });
check(validVariantA06Exp.guidanceId === 'OWASP-A06-001:express-headers', 'Resolved OWASP-A06-001:express-headers variant');

const validVariantA06Dyn = esmGetGuidance({ id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:dynamic-request-target' });
check(validVariantA06Dyn.guidanceId === 'OWASP-A06-001:dynamic-request-target', 'Resolved OWASP-A06-001:dynamic-request-target variant');

// 4. Dual Catalog Schema & Zero Forbidden Keys
console.log('[4/7] Verifying Full Catalog Integrity & Strict Prohibitions...');
const esmEntries = Object.entries(esmCatalog);
const cjsEntries = Object.entries(cjsCatalog);
check(esmEntries.length === 32, 'ESM catalog has exactly 32 entries (found ' + esmEntries.length + ')');
check(cjsEntries.length === 32, 'CJS catalog has exactly 32 entries (found ' + cjsEntries.length + ')');

const forbiddenKeys = [
  'bad', 'good', 'replacementCode', 'goodSnippet', 'badSnippet',
  'fix', 'applyFix', 'codeFix', 'deterministic', 'patch', 'autoFix'
];

for (const [key, entry] of esmEntries) {
  check(entry.guidanceId === key, 'Entry [' + key + '] guidanceId matches key');
  check(typeof entry.ruleId === 'string' && entry.ruleId.startsWith('OWASP-'), 'Entry [' + key + '] ruleId is valid OWASP ID');
  check(typeof entry.title === 'string' && entry.title.length > 5, 'Entry [' + key + '] title is descriptive');
  check(typeof entry.category === 'string' && entry.category.length > 5, 'Entry [' + key + '] category is non-empty');
  check(typeof entry.categoryUrl === 'string' && entry.categoryUrl.startsWith('https://'), 'Entry [' + key + '] categoryUrl is HTTPS');
  check(typeof entry.shortAction === 'string' && entry.shortAction.length > 5, 'Entry [' + key + '] shortAction is descriptive');
  check(typeof entry.recommendedAction === 'string' && entry.recommendedAction.length > 5, 'Entry [' + key + '] recommendedAction is descriptive');
  check(typeof entry.summary === 'string' && entry.summary.length > 5, 'Entry [' + key + '] summary is descriptive');
  check(typeof entry.risk === 'string' && entry.risk.length > 10, 'Entry [' + key + '] risk analysis is thorough');
  check(typeof entry.cannotInfer === 'string' && entry.cannotInfer.length > 10, 'Entry [' + key + '] cannotInfer analysis is thorough');
  check(['browser', 'server', 'cross-boundary'].includes(entry.scope), 'Entry [' + key + '] scope is valid enum (' + entry.scope + ')');
  check(Array.isArray(entry.approaches) && entry.approaches.length >= 1 && entry.approaches.length <= 2, 'Entry [' + key + '] approaches length is 1-2 (found ' + (entry.approaches ? entry.approaches.length : 0) + ')');
  check(Array.isArray(entry.verifySteps) && entry.verifySteps.length >= 1, 'Entry [' + key + '] verifySteps has at least 1 item');
  check(Array.isArray(entry.references) && entry.references.length >= 1, 'Entry [' + key + '] references has at least 1 reference');

  for (const fk of forbiddenKeys) {
    check(!(fk in entry), 'Entry [' + key + '] strictly does not contain forbidden key "' + fk + '"');
  }

  for (const appr of entry.approaches) {
    const text = typeof appr === 'string' ? appr : (appr.title + ' ' + appr.description);
    check(!text.toLowerCase().startsWith('replace with:'), 'Entry [' + key + '] approach does not start with "replace with:"');
    check(!text.toLowerCase().includes('copy and paste'), 'Entry [' + key + '] approach does not instruct copy-pasting');
  }

  const cjsEntry = cjsCatalog[key];
  check(!!cjsEntry, 'CJS catalog has identical key [' + key + ']');
  check(JSON.stringify(entry) === JSON.stringify(cjsEntry), 'Entry [' + key + '] ESM and CJS are byte-identical');
}
// 5. UI Codebase Audit
console.log('[5/7] Auditing UI Codebase for Prohibited Elements (Diff Views, Fix/Patch Buttons)...');
const appJsx = fsLib.readFileSync('./src/App.jsx', 'utf8');

const forbiddenPatterns = [
  /apply\s+fix/i, /apply\s+patch/i, /quick\s*fix/i, /auto\s*fix/i, /replace\s+code/i,
  /<DiffViewer/i, /<ReactDiffViewer/i, /<CodeDiff/i, /diff-view/i
];

for (const pattern of forbiddenPatterns) {
  const match = appJsx.match(pattern);
  check(!match, 'App.jsx strictly does NOT contain forbidden pattern ' + pattern);
}

check(appJsx.includes('1. Detected in your code'), 'App.jsx renders Section 1: Detected in your code');
check(appJsx.includes('2. Why review this'), 'App.jsx renders Section 2: Why review this');
check(appJsx.includes('3. Recommended action'), 'App.jsx renders Section 3: Recommended action');
check(appJsx.includes('4. What JSentinel cannot determine'), 'App.jsx renders Section 4: What JSentinel cannot determine');
check(appJsx.includes('5. Possible approaches'), 'App.jsx renders Section 5: Possible approaches');
check(appJsx.includes('6. How to verify'), 'App.jsx renders Section 6: How to verify');
check(appJsx.includes('GUIDANCE_DISCLAIMER'), 'App.jsx imports and displays GUIDANCE_DISCLAIMER');

// 6. Scanner Fuzzing on Hostile Constructs
console.log('[6/7] Fuzzing and Stress-Testing Scanner Engine on Hostile Constructs...');
const hostileInputs = [
  '', '   \n\t\r   ', '// Just a single line comment', '/* Multi\nline\ncomment */',
  'console.log("hello world");', 'const a = 1; const b = 2; const c = a + b;',
  'function nested() { function deep() { function deeper() { return 42; } } }',
  'const regex = /^[a-zA-Z0-9.!#$%&*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$/;',
  'const unicodeVar = "\ud83d\udc80\ud83d\udc25\u2728\ud83d\udc80"; const \\u0061\\u0062\\u0063 = 100;',
  'const obj = { [Symbol.iterator]: function* () { yield 1; } };',
  'class CustomError extends Error { constructor(msg) { super(msg); this.name = "Custom"; } }',
  'try { throw new Error("boom"); } catch (err) { console.error(err); } finally { /* cleanup */ }',
  'async function* asyncGen() { yield await Promise.resolve(10); }',
  'const { a: [b, { c = 10 } = {}] = [] } = {};',
  'const evil = "\\u0000\\u0007\\u001b[31mRed\\u001b[0m";',
  '// Incomplete syntax handled via error recovery\nconst broken = { a: ;'
];

for (let i = 0; i < hostileInputs.length; i++) {
  const input = hostileInputs[i];
  try {
    const issues = scanSourceCode(input, 'fuzz_' + i + '.js');
    check(Array.isArray(issues), 'Scanner processed hostile input #' + i + ' safely without throwing');
    for (const issue of issues) {
      check(typeof issue.id === 'string', 'Hostile issue has id string');
      check(typeof issue.guidanceId === 'string', 'Hostile issue has guidanceId string');
      const guidance = esmGetGuidance(issue);
      check(guidance !== null && typeof guidance === 'object', 'Hostile issue resolves to guidance');
    }
  } catch (err) {
    check(false, 'Scanner threw unhandled exception on hostile input #' + i + ': ' + err.message);
  }
}

// 7. Export Integrity & False Positive Scoring Stress
console.log('[7/7] Testing Export Integrity and False Positive Scoring Stress...');
const mockScanResults = [
  {
    fileName: 'src/auth.js',
    success: true,
    hasError: false,
    issues: [
      {
        id: 'OWASP-A02-001',
        guidanceId: 'OWASP-A02-001',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        line: 12,
        column: 4,
        message: 'Hardcoded password detected in variable declaration.',
        sourceLine: 'const password = "SuperSecretAdminPassword123!";'
      },
      {
        id: 'OWASP-A02-005',
        guidanceId: 'OWASP-A02-005:credential',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        line: 25,
        column: 2,
        message: 'Math.random() used to generate security-sensitive value (token).',
        sourceLine: 'const resetToken = Math.random().toString(36);'
      }
    ]
  }
];

const fpFlags = ['src/auth.js:OWASP-A02-001:12:4'];
const exportData = formatJSONReport(mockScanResults, { totalIssues: 2, activeIssuesCount: 1, criticalIssues: 1, securityScore: 80 }, [], fpFlags);

check(exportData.meta && typeof exportData.meta.scannedAt === 'string', 'JSON export metadata contains valid scannedAt');
check(exportData.meta.disclaimer === esmDisclaimer, 'JSON export contains mandatory educational disclaimer');
check(exportData.files && exportData.files.length === 1, 'JSON export contains 1 file summary');
const file0 = exportData.files[0];
check(file0.issuesCount === 2, 'File summary reflects 2 total issues');
check(file0.activeIssuesCount === 1, 'File summary reflects 1 active issue (1 marked as FP)');
check(file0.score === 80, 'File security score reflects -20 penalty for active CRITICAL issue');

check(exportData.issues && exportData.issues.length === 2, 'JSON export contains 2 flat issue records');
const issue1 = exportData.issues.find(i => i.id === 'OWASP-A02-001');
const issue2 = exportData.issues.find(i => i.guidanceId === 'OWASP-A02-005:credential');

check(issue1 && issue1.isFalsePositive === true, 'Issue 1 correctly marked as isFalsePositive: true');
check(issue2 && issue2.isFalsePositive === false, 'Issue 2 correctly marked as isFalsePositive: false');
check(issue1 && issue1.guidanceId === 'OWASP-A02-001', 'Issue 1 maintains correct base guidanceId');
check(issue2 && issue2.guidanceId === 'OWASP-A02-005:credential', 'Issue 2 maintains correct variant guidanceId');
check(issue1 && issue1.sourceLine.includes('SuperSecretAdminPassword123'), 'Issue 1 preserves sourceLine context');

console.log('\n======================================================================');
console.log('STRESS TEST SUMMARY: ' + passed + ' passed, ' + failed + ' failed (out of ' + total + ' assertions)');
if (failed > 0) {
  console.log('FAILURES:');
  errors.forEach(f => console.log('  \u2717 ' + f));
  process.exit(1);
} else {
  console.log('\u2714 ALL INDEPENDENT CHALLENGER ASSERTIONS PASSED WITH ZERO FAILURES!');
}
console.log('======================================================================\n');

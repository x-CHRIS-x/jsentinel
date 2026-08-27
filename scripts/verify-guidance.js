#!/usr/bin/env node
/**
 * JSentinel Canonical Guidance Verification Harness
 * 
 * Validates schema, completeness, forbidden key absence, helper functions,
 * and ESM / CommonJS parity across both guidance catalogs.
 */

import { pathToFileURL } from 'url';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import process from 'node:process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

const BASE_RULES = [
  'OWASP-A01-001', 'OWASP-A01-002',
  'OWASP-A02-001', 'OWASP-A02-002', 'OWASP-A02-003', 'OWASP-A02-004', 'OWASP-A02-005', 'OWASP-A02-006', 'OWASP-A02-007',
  'OWASP-A03-001', 'OWASP-A03-002', 'OWASP-A03-003', 'OWASP-A03-004', 'OWASP-A03-005', 'OWASP-A03-006', 'OWASP-A03-007', 'OWASP-A03-008',
  'OWASP-A05-001', 'OWASP-A05-002', 'OWASP-A05-003', 'OWASP-A05-004',
  'OWASP-A06-001',
  'OWASP-A07-001',
  'OWASP-A08-001', 'OWASP-A08-002', 'OWASP-A08-003',
  'OWASP-A10-001'
];

const MULTI_SCENARIOS = [
  'OWASP-A02-005:credential',
  'OWASP-A02-005:network-address',
  'OWASP-A06-001:component-review',
  'OWASP-A06-001:express-headers',
  'OWASP-A06-001:dynamic-request-target'
];

const ALL_EXPECTED_IDS = [...BASE_RULES, ...MULTI_SCENARIOS];

const FORBIDDEN_KEYS = [
  'bad', 'good', 'replacementCode', 'goodSnippet', 'badSnippet',
  'fix', 'applyFix', 'codeFix', 'deterministic', 'patch'
];

const VALID_SCOPES = ['browser', 'server', 'cross-boundary'];

async function runVerification() {
  console.log('='.repeat(70));
  console.log('JSENTINEL GUIDANCE CATALOG VERIFICATION SUITE');
  console.log('='.repeat(70));

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      passed++;
      console.log(`  ✓ ${message}`);
    } else {
      failed++;
      console.error(`  ✗ FAIL: ${message}`);
    }
  }

  // 1. Load ESM Module
  console.log('\n[1/5] Loading ESM and CommonJS Catalogs...');
  const esmPath = pathToFileURL(path.resolve(__dirname, '../src/data/guidanceCatalog.js')).href;
  const esmMod = await import(esmPath);
  const esmCatalog = esmMod.guidanceCatalog || esmMod.default;

  // 2. Load CJS Module
  const cjsPath = path.resolve(__dirname, '../vscode-extension/src/data/guidanceCatalog.js');
  const cjsMod = require(cjsPath);
  const cjsCatalog = cjsMod.guidanceCatalog || cjsMod.default;

  assert(esmCatalog && typeof esmCatalog === 'object', 'ESM catalog exported successfully');
  assert(cjsCatalog && typeof cjsCatalog === 'object', 'CommonJS catalog exported successfully');

  // 2. Catalog Completeness and Key Validation
  console.log('\n[2/5] Verifying Catalog Key Coverage (32 total = 27 base + 5 variants)...');
  const esmKeys = Object.keys(esmCatalog);
  const cjsKeys = Object.keys(cjsCatalog);

  assert(esmKeys.length === 32, `ESM catalog has exactly 32 keys (found ${esmKeys.length})`);
  assert(cjsKeys.length === 32, `CJS catalog has exactly 32 keys (found ${cjsKeys.length})`);

  for (const id of ALL_EXPECTED_IDS) {
    assert(id in esmCatalog, `ESM catalog contains ID "${id}"`);
    assert(id in cjsCatalog, `CJS catalog contains ID "${id}"`);
  }

  // 3. Schema Structure & Safety Invariants
  console.log('\n[3/5] Verifying Record Schema and Safety Constraints...');
  for (const [id, record] of Object.entries(esmCatalog)) {
    assert(record.guidanceId === id, `Record [${id}] guidanceId matches key`);
    assert(typeof record.ruleId === 'string' && record.ruleId.length > 0, `Record [${id}] ruleId is valid string`);
    assert(typeof record.title === 'string' && record.title.length > 0, `Record [${id}] title is non-empty`);
    assert(typeof record.category === 'string' && record.category.length > 0, `Record [${id}] category is non-empty`);
    assert(typeof record.categoryUrl === 'string' && (record.categoryUrl.startsWith('http://') || record.categoryUrl.startsWith('https://')), `Record [${id}] categoryUrl is valid HTTP/HTTPS URL`);
    assert(typeof record.shortAction === 'string' && record.shortAction.length > 0, `Record [${id}] shortAction is non-empty`);
    assert(typeof record.recommendedAction === 'string' && record.recommendedAction.length > 0, `Record [${id}] recommendedAction is non-empty`);
    assert(typeof record.summary === 'string' && record.summary.length > 0, `Record [${id}] summary is non-empty`);
    assert(typeof record.risk === 'string' && record.risk.length > 0, `Record [${id}] risk is non-empty`);
    assert(typeof record.cannotInfer === 'string' && record.cannotInfer.length > 0, `Record [${id}] cannotInfer is non-empty`);
    assert(VALID_SCOPES.includes(record.scope), `Record [${id}] scope "${record.scope}" is one of [${VALID_SCOPES.join(', ')}]`);

    // Approaches check (1-2 approaches, array of strings)
    assert(Array.isArray(record.approaches), `Record [${id}] approaches is an Array`);
    assert(record.approaches.length >= 1 && record.approaches.length <= 2, `Record [${id}] approaches count is 1-2 (found ${record.approaches.length})`);
    record.approaches.forEach((appr, idx) => {
      assert(typeof appr === 'string' && appr.trim().length > 0, `Record [${id}] approach[${idx}] is non-empty string`);
      assert(!appr.toLowerCase().startsWith('replace with:'), `Record [${id}] approach[${idx}] does not start with "replace with:"`);
      assert(!appr.toLowerCase().includes('copy and paste'), `Record [${id}] approach[${idx}] does not instruct copy-pasting`);
    });

    // Verify steps check
    assert(Array.isArray(record.verifySteps), `Record [${id}] verifySteps is an Array`);
    assert(record.verifySteps.length >= 1, `Record [${id}] verifySteps has at least 1 step`);
    record.verifySteps.forEach((step, idx) => {
      assert(typeof step === 'string' && step.trim().length > 0, `Record [${id}] verifyStep[${idx}] is non-empty string`);
    });

    // References check
    assert(Array.isArray(record.references), `Record [${id}] references is an Array`);
    assert(record.references.length >= 1, `Record [${id}] references has at least 1 reference`);
    record.references.forEach((ref, idx) => {
      assert(typeof ref === 'object' && ref !== null, `Record [${id}] ref[${idx}] is an object`);
      assert(typeof ref.title === 'string' && ref.title.length > 0, `Record [${id}] ref[${idx}].title is non-empty`);
      assert(typeof ref.url === 'string' && (ref.url.startsWith('http://') || ref.url.startsWith('https://')), `Record [${id}] ref[${idx}].url is valid HTTP/HTTPS URL`);
    });

    // Forbidden keys check
    for (const forbidden of FORBIDDEN_KEYS) {
      assert(!(forbidden in record), `Record [${id}] does NOT contain forbidden key "${forbidden}"`);
    }
  }

  // 4. Helper Function Tests
  console.log('\n[4/5] Testing Helper Functions & Disclaimers...');
  assert(typeof esmMod.GUIDANCE_DISCLAIMER === 'string' && esmMod.GUIDANCE_DISCLAIMER.length > 0, 'ESM GUIDANCE_DISCLAIMER exported');
  assert(typeof cjsMod.GUIDANCE_DISCLAIMER === 'string' && cjsMod.GUIDANCE_DISCLAIMER.length > 0, 'CJS GUIDANCE_DISCLAIMER exported');
  assert(esmMod.GUIDANCE_DISCLAIMER === cjsMod.GUIDANCE_DISCLAIMER, 'Disclaimers match between ESM and CJS');

  // getGuidance lookups
  const g1 = esmMod.getGuidance('OWASP-A01-001');
  assert(g1 && g1.guidanceId === 'OWASP-A01-001', 'getGuidance string lookup returns correct record');

  const gVariant = esmMod.getGuidance('OWASP-A02-005:credential');
  assert(gVariant && gVariant.guidanceId === 'OWASP-A02-005:credential', 'getGuidance variant string lookup returns variant record');

  const gObj = esmMod.getGuidance({ id: 'OWASP-A02-005', guidanceId: 'OWASP-A02-005:network-address' });
  assert(gObj && gObj.guidanceId === 'OWASP-A02-005:network-address', 'getGuidance issue object lookup returns matching guidanceId record');

  const gFallback1 = esmMod.getGuidance('NON_EXISTENT_RULE');
  assert(gFallback1 && gFallback1.title && Array.isArray(gFallback1.approaches), 'getGuidance returns fallback record for unknown rule');

  const gFallback2 = esmMod.getGuidance(null);
  assert(gFallback2 && gFallback2.title && Array.isArray(gFallback2.approaches), 'getGuidance returns fallback record for null input');

  // getAllGuidance
  const allEsm = esmMod.getAllGuidance();
  assert(Object.keys(allEsm).length === 32, 'getAllGuidance() returns 32 records');

  // getGuidanceByRuleId
  const a06Records = esmMod.getGuidanceByRuleId('OWASP-A06-001');
  assert(Array.isArray(a06Records) && a06Records.length === 4, `getGuidanceByRuleId('OWASP-A06-001') returns 4 records (base + 3 variants)`);

  const a02Records = esmMod.getGuidanceByRuleId('OWASP-A02-005');
  assert(Array.isArray(a02Records) && a02Records.length === 3, `getGuidanceByRuleId('OWASP-A02-005') returns 3 records (base + 2 variants)`);

  // 5. Parity Test Between ESM and CJS
  console.log('\n[5/5] Verifying Full ESM and CommonJS Parity...');
  for (const key of ALL_EXPECTED_IDS) {
    const esmRec = esmCatalog[key];
    const cjsRec = cjsCatalog[key];
    assert(JSON.stringify(esmRec) === JSON.stringify(cjsRec), `ESM and CJS records match identically for "${key}"`);
  }

  console.log('\n' + '='.repeat(70));
  console.log(`SUMMARY: ${passed} passed, ${failed} failed.`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runVerification().catch(err => {
  console.error('Fatal verification failure:', err);
  process.exit(1);
});

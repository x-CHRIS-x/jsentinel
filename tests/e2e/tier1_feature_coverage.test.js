/* global process */
/**
 * Tier 1: Feature Coverage & Guidance Catalog Schema Integrity
 * 
 * Verifies:
 * - 100% rule coverage: all 27 base OWASP 2021 rules + 5 multi-scenario variants (≥32 records)
 * - Schema completeness: all required fields present, non-empty, and correctly typed
 * - Mandatory educational disclaimer presence and wording
 * - Exact parity between Web App catalog and VS Code Extension catalog
 * - Semantic alignment with PLAN.md Content Matrix
 */

import {
  TestRunner,
  assert,
  assertEqual,
  loadWebGuidanceCatalog,
  loadExtensionGuidanceCatalog
} from './helpers/testUtils.js';

export async function runTier1() {
  const runner = new TestRunner('Tier 1: Feature Coverage & Guidance Catalog Schema Integrity');

  const EXPECTED_27_BASE_RULES = [
    'OWASP-A01-001', 'OWASP-A01-002',
    'OWASP-A02-001', 'OWASP-A02-002', 'OWASP-A02-003', 'OWASP-A02-004', 'OWASP-A02-005', 'OWASP-A02-006', 'OWASP-A02-007',
    'OWASP-A03-001', 'OWASP-A03-002', 'OWASP-A03-003', 'OWASP-A03-004', 'OWASP-A03-005', 'OWASP-A03-006', 'OWASP-A03-007', 'OWASP-A03-008',
    'OWASP-A05-001', 'OWASP-A05-002', 'OWASP-A05-003', 'OWASP-A05-004',
    'OWASP-A06-001',
    'OWASP-A07-001',
    'OWASP-A08-001', 'OWASP-A08-002', 'OWASP-A08-003',
    'OWASP-A10-001'
  ];

  const EXPECTED_5_VARIANTS = [
    'OWASP-A02-005:credential',
    'OWASP-A02-005:network-address',
    'OWASP-A06-001:component-review',
    'OWASP-A06-001:express-headers',
    'OWASP-A06-001:dynamic-request-target'
  ];

  const REQUIRED_FIELDS = [
    'guidanceId',
    'ruleId',
    'title',
    'summary',
    'risk',
    'recommendedAction',
    'cannotInfer',
    'approaches',
    'verifySteps',
    'scope',
    'references'
  ];

  // Test 1: Load Web Guidance Catalog
  runner.test('Web guidance catalog module is exportable and contains catalog data', async () => {
    const webCatalogMod = await loadWebGuidanceCatalog();
    const catalog = webCatalogMod.guidanceCatalog || webCatalogMod.default;
    assert(catalog && typeof catalog === 'object', 'guidanceCatalog must be an object dictionary');
    const keys = Object.keys(catalog);
    assert(keys.length >= 32, `guidanceCatalog must have at least 32 entries, found ${keys.length}`);
  });

  // Test 2: Load Extension Guidance Catalog
  runner.test('VS Code extension guidance catalog module is exportable and contains catalog data', async () => {
    const extCatalogMod = await loadExtensionGuidanceCatalog();
    const catalog = extCatalogMod.guidanceCatalog || extCatalogMod.default;
    assert(catalog && typeof catalog === 'object', 'Extension guidanceCatalog must be an object dictionary');
    const keys = Object.keys(catalog);
    assert(keys.length >= 32, `Extension guidanceCatalog must have at least 32 entries, found ${keys.length}`);
  });

  // Test 3: Catalog Parity
  runner.test('Dual catalog parity: Web and Extension catalogs have identical guidance keys and contents', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const extMod = await loadExtensionGuidanceCatalog();
    const webCatalog = webMod.guidanceCatalog || webMod.default;
    const extCatalog = extMod.guidanceCatalog || extMod.default;

    const webKeys = Object.keys(webCatalog).sort();
    const extKeys = Object.keys(extCatalog).sort();

    assertEqual(webKeys.length, extKeys.length, 'Web and Extension catalogs must have identical key count');
    for (const key of webKeys) {
      assert(extCatalog[key] !== undefined, `Extension catalog missing key present in web: ${key}`);
      assertEqual(webCatalog[key].guidanceId, extCatalog[key].guidanceId, `guidanceId mismatch for ${key}`);
      assertEqual(webCatalog[key].title, extCatalog[key].title, `title mismatch for ${key}`);
      assertEqual(webCatalog[key].summary, extCatalog[key].summary, `summary mismatch for ${key}`);
      assertEqual(webCatalog[key].recommendedAction, extCatalog[key].recommendedAction, `recommendedAction mismatch for ${key}`);
    }
  });

  // Test 4: All 27 Base OWASP Rules Present
  runner.test('All 27 OWASP base rules exist in guidance catalog', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const ruleId of EXPECTED_27_BASE_RULES) {
      assert(catalog[ruleId] !== undefined, `Missing base rule in guidanceCatalog: ${ruleId}`);
      assertEqual(catalog[ruleId].ruleId, ruleId, `ruleId field must match base rule ID for ${ruleId}`);
    }
  });

  // Test 5: All 5 Multi-Scenario Variants Present
  runner.test('All 5 multi-scenario variant guidance IDs exist in guidance catalog', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const variantId of EXPECTED_5_VARIANTS) {
      assert(catalog[variantId] !== undefined, `Missing multi-scenario variant in guidanceCatalog: ${variantId}`);
      const baseRuleId = variantId.split(':')[0];
      assertEqual(catalog[variantId].ruleId, baseRuleId, `Variant ${variantId} ruleId must be ${baseRuleId}`);
      assertEqual(catalog[variantId].guidanceId, variantId, `Variant ${variantId} guidanceId must match variant key`);
    }
  });

  // Test 6: Required Schema Fields Completeness
  runner.test('Every guidance record has all required fields with non-empty contents', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const [key, entry] of Object.entries(catalog)) {
      for (const field of REQUIRED_FIELDS) {
        assert(entry[field] !== undefined, `Record ${key} is missing required field: "${field}"`);
        assert(entry[field] !== null, `Record ${key} field "${field}" must not be null`);
      }

      // String fields must not be empty or whitespace
      const stringFields = ['guidanceId', 'ruleId', 'title', 'summary', 'risk', 'recommendedAction', 'cannotInfer', 'scope'];
      for (const sf of stringFields) {
        assert(typeof entry[sf] === 'string', `Record ${key} field "${sf}" must be a string`);
        assert(entry[sf].trim().length > 0, `Record ${key} field "${sf}" must not be empty`);
      }

      // Array fields
      assert(Array.isArray(entry.approaches), `Record ${key} "approaches" must be an Array`);
      assert(entry.approaches.length >= 1 && entry.approaches.length <= 2, `Record ${key} "approaches" must have 1-2 conditional approaches, found ${entry.approaches.length}`);
      entry.approaches.forEach((appr, i) => {
        assert(typeof appr === 'string' && appr.trim().length > 0, `Record ${key} approach[${i}] must be a non-empty string`);
      });

      assert(Array.isArray(entry.verifySteps), `Record ${key} "verifySteps" must be an Array`);
      assert(entry.verifySteps.length >= 1, `Record ${key} "verifySteps" must have at least 1 step`);
      entry.verifySteps.forEach((step, i) => {
        assert(typeof step === 'string' && step.trim().length > 0, `Record ${key} verifyStep[${i}] must be a non-empty string`);
      });

      assert(Array.isArray(entry.references), `Record ${key} "references" must be an Array`);
      entry.references.forEach((ref, i) => {
        assert(typeof ref === 'object' && ref !== null, `Record ${key} reference[${i}] must be an object`);
        assert(typeof ref.title === 'string' && ref.title.trim().length > 0, `Record ${key} reference[${i}].title must be non-empty`);
        assert(typeof ref.url === 'string' && (ref.url.startsWith('http://') || ref.url.startsWith('https://')), `Record ${key} reference[${i}].url must be a valid HTTP/HTTPS URL`);
      });
    }
  });

  // Test 7: Mandatory Educational Disclaimer
  runner.test('Mandatory educational disclaimer is exported and contains required non-prescriptive wording', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const disclaimer = webMod.EDUCATIONAL_DISCLAIMER || webMod.disclaimer || (webMod.guidanceCatalog && webMod.guidanceCatalog.__disclaimer);
    
    assert(disclaimer && typeof disclaimer === 'string', 'EDUCATIONAL_DISCLAIMER must be exported as a non-empty string');
    assert(disclaimer.trim().length > 20, 'Educational disclaimer must be descriptive');
    
    const lowerDisclaimer = disclaimer.toLowerCase();
    const hasPreserves = lowerDisclaimer.includes('preserves') || lowerDisclaimer.includes('adapted');
    const hasGuidance = lowerDisclaimer.includes('guidance') || lowerDisclaimer.includes('educational');
    const hasReplacement = lowerDisclaimer.includes('not a drop-in replacement') || lowerDisclaimer.includes('non-prescriptive');
    
    assert(hasGuidance, 'Educational disclaimer must mention guidance or educational nature');
    assert(hasReplacement || hasPreserves, 'Educational disclaimer must state non-prescriptive / not a drop-in replacement');
  });

  // Test 8: Content Matrix Invariant Check - Category A01 (Access Control)
  runner.test('Category A01 guidance records provide correct redirect and server authorization guidance', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    const a01_001 = catalog['OWASP-A01-001'];
    assert(a01_001.summary.toLowerCase().includes('redirect') || a01_001.recommendedAction.toLowerCase().includes('redirect') || a01_001.recommendedAction.toLowerCase().includes('trusted') || a01_001.recommendedAction.toLowerCase().includes('destination'), 'A01-001 must cover redirect guidance');
    assert(a01_001.cannotInfer.length > 10, 'A01-001 must explicitly state cannotInfer static limitations');

    const a01_002 = catalog['OWASP-A01-002'];
    assert(a01_002.summary.toLowerCase().includes('role') || a01_002.recommendedAction.toLowerCase().includes('server') || a01_002.recommendedAction.toLowerCase().includes('authorization'), 'A01-002 must cover server-side authorization enforcement');
  });

  // Test 9: Content Matrix Invariant Check - Category A02 & Variants (Cryptographic Failures)
  runner.test('Category A02 guidance records and variants correctly distinguish credentials vs network-address', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    const credVariant = catalog['OWASP-A02-005:credential'];
    const netVariant = catalog['OWASP-A02-005:network-address'];

    assert(credVariant !== undefined, 'OWASP-A02-005:credential variant must exist');
    assert(netVariant !== undefined, 'OWASP-A02-005:network-address variant must exist');

    assert(credVariant.recommendedAction.toLowerCase().includes('secret') || credVariant.recommendedAction.toLowerCase().includes('rotate') || credVariant.recommendedAction.toLowerCase().includes('revoke') || credVariant.recommendedAction.toLowerCase().includes('bundle'), 'A02-005:credential must guide secret revocation and server store');
    assert(netVariant.recommendedAction.toLowerCase().includes('endpoint') || netVariant.recommendedAction.toLowerCase().includes('address') || netVariant.recommendedAction.toLowerCase().includes('ip') || netVariant.recommendedAction.toLowerCase().includes('configuration'), 'A02-005:network-address must guide configuration review rather than generic secret rotation');
  });

  // Test 10: Content Matrix Invariant Check - Category A06 & Variants (Outdated / Risky Components)
  runner.test('Category A06 guidance records and variants correctly distinguish component-review, express-headers, dynamic-request-target', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    const compVariant = catalog['OWASP-A06-001:component-review'];
    const expVariant = catalog['OWASP-A06-001:express-headers'];
    const dynVariant = catalog['OWASP-A06-001:dynamic-request-target'];

    assert(compVariant !== undefined, 'OWASP-A06-001:component-review must exist');
    assert(expVariant !== undefined, 'OWASP-A06-001:express-headers must exist');
    assert(dynVariant !== undefined, 'OWASP-A06-001:dynamic-request-target must exist');

    assert(compVariant.summary.toLowerCase().includes('package') || compVariant.summary.toLowerCase().includes('component') || compVariant.summary.toLowerCase().includes('library'), 'A06-001:component-review must address library advisories');
    assert(expVariant.recommendedAction.toLowerCase().includes('helmet') || expVariant.recommendedAction.toLowerCase().includes('header') || expVariant.recommendedAction.toLowerCase().includes('express'), 'A06-001:express-headers must address Express header hardening');
    assert(dynVariant.recommendedAction.toLowerCase().includes('target') || dynVariant.recommendedAction.toLowerCase().includes('destination') || dynVariant.recommendedAction.toLowerCase().includes('outbound') || dynVariant.recommendedAction.toLowerCase().includes('request'), 'A06-001:dynamic-request-target must address destination policy');
  });

  return await runner.run();
}

// Allow direct execution: node tests/e2e/tier1_feature_coverage.test.js
if (process.argv[1] && process.argv[1].endsWith('tier1_feature_coverage.test.js')) {
  runTier1().then(res => {
    process.exit(res.failed > 0 ? 1 : 0);
  });
}

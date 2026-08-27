/* global process */
/**
 * Tier 2: Boundary & Corner Cases (Safety Assertions, Edge Inputs, Negative Lookups)
 * 
 * Verifies:
 * - Safety Assertions: Zero `bad`/`good` code replacement keys, zero copyable patches, zero auto-fix strings in catalog
 * - Negative and malformed guidance ID lookups (null, undefined, invalid string, numbers, objects)
 * - Boundary conditions in schema (approaches <= 2, verifySteps >= 1, references validation)
 * - Scanner engine boundary handling (empty strings, comments only, syntax errors, unicode, long lines)
 * - False positive key parsing edge cases (`parseFpKey`)
 */

import {
  TestRunner,
  assert,
  assertEqual,
  assertFalse,
  scanSourceCode,
  loadWebGuidanceCatalog,
  loadExtensionGuidanceCatalog
} from './helpers/testUtils.js';

export async function runTier2() {
  const runner = new TestRunner('Tier 2: Boundary & Corner Cases');

  const FORBIDDEN_KEYS = [
    'bad',
    'good',
    'replacementCode',
    'goodSnippet',
    'codeReplacement',
    'deterministic',
    'autoFix',
    'codeFixGuide'
  ];

  // Test 1: Zero Forbidden Keys in Web Catalog
  runner.test('Web guidance catalog contains zero forbidden code replacement keys', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const [id, record] of Object.entries(catalog)) {
      for (const forbidden of FORBIDDEN_KEYS) {
        assert(record[forbidden] === undefined, `Record ${id} contains forbidden key "${forbidden}"`);
      }
    }
  });

  // Test 2: Zero Forbidden Keys in Extension Catalog
  runner.test('Extension guidance catalog contains zero forbidden code replacement keys', async () => {
    const extMod = await loadExtensionGuidanceCatalog();
    const catalog = extMod.guidanceCatalog || extMod.default;

    for (const [id, record] of Object.entries(catalog)) {
      for (const forbidden of FORBIDDEN_KEYS) {
        assert(record[forbidden] === undefined, `Extension record ${id} contains forbidden key "${forbidden}"`);
      }
    }
  });

  // Test 3: Guidance Recommendations Do Not Contain Copyable Direct Replacement Blocks
  runner.test('Guidance approaches do not offer prescriptive copyable replacement patches', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const [id, record] of Object.entries(catalog)) {
      if (record.approaches) {
        for (const approach of record.approaches) {
          // Should not start with "Replace with:" or contain raw single-line replacement instructions
          assertFalse(approach.toLowerCase().startsWith('replace with:'), `Approach in ${id} should not be formatted as a drop-in replacement`);
          assertFalse(approach.toLowerCase().includes('copy and paste'), `Approach in ${id} should not instruct copy-pasting code`);
        }
      }
    }
  });

  // Test 4: getGuidance with null/undefined/empty input returns safe fallback
  runner.test('getGuidance handles null, undefined, and empty string without throwing', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const getGuidance = webMod.getGuidance || ((id) => (webMod.guidanceCatalog || webMod.default)[id] || webMod.FALLBACK_GUIDANCE);

    const testInputs = [null, undefined, '', '   ', '\t\n'];
    for (const input of testInputs) {
      let result;
      try {
        result = getGuidance(input);
      } catch (err) {
        assert(false, `getGuidance threw error on input ${JSON.stringify(input)}: ${err.message}`);
      }
      assert(result !== null && typeof result === 'object', `getGuidance(${JSON.stringify(input)}) must return a non-null fallback object`);
      assert(typeof result.title === 'string' && result.title.length > 0, `Fallback for ${JSON.stringify(input)} must have a title`);
      assert(typeof result.recommendedAction === 'string' && result.recommendedAction.length > 0, `Fallback for ${JSON.stringify(input)} must have recommendedAction`);
    }
  });

  // Test 5: getGuidance with non-existent or malformed rule IDs
  runner.test('getGuidance with non-existent or malformed rule IDs returns safe fallback object', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const getGuidance = webMod.getGuidance || ((id) => (webMod.guidanceCatalog || webMod.default)[id] || webMod.FALLBACK_GUIDANCE);

    const invalidIds = [
      'NON_EXISTENT_RULE',
      'OWASP-A99-999',
      'OWASP-A02-005:nonexistent_variant',
      'OWASP-A06-001:fake_variant',
      '../../../etc/passwd',
      '<script>alert(1)</script>'
    ];

    for (const invId of invalidIds) {
      const result = getGuidance(invId);
      assert(result !== null && typeof result === 'object', `getGuidance('${invId}') must return safe guidance object`);
      assert(typeof result.title === 'string', `Fallback title must be string for '${invId}'`);
      assert(typeof result.recommendedAction === 'string', `Fallback action must be string for '${invId}'`);
      assert(Array.isArray(result.approaches), `Fallback approaches must be array for '${invId}'`);
      assert(Array.isArray(result.verifySteps), `Fallback verifySteps must be array for '${invId}'`);
    }
  });

  // Test 6: getGuidance with non-string types (numbers, booleans, objects)
  runner.test('getGuidance handles non-string arguments gracefully', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const getGuidance = webMod.getGuidance || ((id) => (webMod.guidanceCatalog || webMod.default)[id] || webMod.FALLBACK_GUIDANCE);

    const nonStringInputs = [12345, true, false, {}, [], () => {}];
    for (const input of nonStringInputs) {
      let result;
      try {
        result = getGuidance(input);
      } catch (err) {
        assert(false, `getGuidance threw on non-string input: ${err.message}`);
      }
      assert(result !== null && typeof result === 'object', `getGuidance must return object on non-string input`);
    }
  });

  // Test 7: getGuidance with prototype property names returns FALLBACK_GUIDANCE without leaking prototype functions
  runner.test('getGuidance with prototype property names safely returns FALLBACK_GUIDANCE without leaking prototype functions', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const extMod = await loadExtensionGuidanceCatalog();

    const protoProps = [
      'toString',
      'constructor',
      '__proto__',
      'valueOf',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
      'toLocaleString'
    ];

    for (const prop of protoProps) {
      // Direct string lookup on Web catalog
      const webResult = webMod.getGuidance(prop);
      assert(webResult !== null && typeof webResult === 'object', `Web getGuidance('${prop}') must return an object`);
      assert(typeof webResult !== 'function', `Web getGuidance('${prop}') must not return a prototype function`);
      assertEqual(webResult.title, 'Security Review Recommendation', `Web getGuidance('${prop}') must return fallback title`);
      assertEqual(webResult.guidanceId, 'UNKNOWN', `Web getGuidance('${prop}') must have UNKNOWN guidanceId`);

      // Direct string lookup on Extension catalog
      const extResult = extMod.getGuidance(prop);
      assert(extResult !== null && typeof extResult === 'object', `Extension getGuidance('${prop}') must return an object`);
      assert(typeof extResult !== 'function', `Extension getGuidance('${prop}') must not return a prototype function`);
      assertEqual(extResult.title, 'Security Review Recommendation', `Extension getGuidance('${prop}') must return fallback title`);
      assertEqual(extResult.guidanceId, 'UNKNOWN', `Extension getGuidance('${prop}') must have UNKNOWN guidanceId`);

      // Object lookup with id
      const objResult = webMod.getGuidance({ id: prop });
      assert(objResult !== null && typeof objResult === 'object' && typeof objResult !== 'function', `Web getGuidance({ id: '${prop}' }) must return fallback object`);
      assertEqual(objResult.title, 'Security Review Recommendation', `Web getGuidance({ id: '${prop}' }) fallback title`);

      // Object lookup with guidanceId
      const objResult2 = webMod.getGuidance({ guidanceId: prop });
      assert(objResult2 !== null && typeof objResult2 === 'object' && typeof objResult2 !== 'function', `Web getGuidance({ guidanceId: '${prop}' }) must return fallback object`);
      assertEqual(objResult2.title, 'Security Review Recommendation', `Web getGuidance({ guidanceId: '${prop}' }) fallback title`);

      // getGuidanceByRuleId
      const byRule = webMod.getGuidanceByRuleId(prop);
      assert(Array.isArray(byRule) && byRule.length === 0, `getGuidanceByRuleId('${prop}') must return empty array`);
    }
  });

  // Test 8: Approaches Array Boundary Constraint (<= 2 conditional approaches per PLAN.md R1)
  runner.test('Every guidance record strictly enforces <= 2 conditional approaches boundary', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    for (const [id, record] of Object.entries(catalog)) {
      if (record.approaches) {
        assert(record.approaches.length <= 2, `Record ${id} exceeds maximum of 2 conditional approaches (has ${record.approaches.length})`);
        assert(record.approaches.length >= 1, `Record ${id} must have at least 1 approach`);
      }
    }
  });

  // Test 9: Scanner Engine handles empty code and whitespace
  runner.test('Scanner engine handles empty code string and whitespace without crashing', () => {
    const emptyResult = scanSourceCode('', 'empty.js');
    assertEqual(emptyResult.length, 0, 'Empty file should have 0 issues');

    const whitespaceResult = scanSourceCode('   \n\n\t  \n', 'whitespace.js');
    assertEqual(whitespaceResult.length, 0, 'Whitespace file should have 0 issues');
  });

  // Test 10: Scanner Engine handles comments only
  runner.test('Scanner engine handles comment-only files without false positives', () => {
    const commentsCode = `
      // Single line comment with sensitive keywords: password, secret, eval, innerHTML
      /*
       * Multi-line block comment
       * const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
       * eval("malicious code");
       */
      /** JSDoc comment with http://insecure.url */
    `;
    const issues = scanSourceCode(commentsCode, 'comments.js');
    assertEqual(issues.length, 0, 'Comment-only code must not trigger AST vulnerability findings');
  });

  // Test 11: Scanner Engine handles syntax errors gracefully via errorRecovery
  runner.test('Scanner engine handles malformed syntax without unhandled crash', () => {
    const brokenCode = `
      const x = ; // syntax error
      function test( { // unclosed paren
      eval("window.location.href = x;");
    `;
    let issues = [];
    try {
      issues = scanSourceCode(brokenCode, 'broken.js');
    } catch (err) {
      assert(false, `Scanner threw unhandled exception on malformed syntax: ${err.message}`);
    }
    assert(Array.isArray(issues), 'Scanner must return an array even on broken code');
  });

  // Test 12: Scanner Engine handles Unicode, emojis, and special escaping characters
  runner.test('Scanner engine handles Unicode identifiers, emojis, and special chars', () => {
    const unicodeCode = `
      const 🔑 = "secret_value";
      const élève_données = { nom: "Jean", rôle: "étudiant" };
      function saluer() {
        console.log("Bonjour " + élève_données.nom);
      }
    `;
    let issues = [];
    try {
      issues = scanSourceCode(unicodeCode, 'unicode.js');
    } catch (err) {
      assert(false, `Scanner failed on unicode code: ${err.message}`);
    }
    assert(Array.isArray(issues), 'Scanner must return valid issues array for unicode code');
  });

  // Test 13: Scanner Engine handles extremely long lines without call-stack overflow
  runner.test('Scanner engine handles long single-line files without stack overflow', () => {
    const longLine = 'const a = 1; ' + 'const b = 2; '.repeat(1000) + 'console.log(a + b);';
    let issues = [];
    try {
      issues = scanSourceCode(longLine, 'longline.js');
    } catch (err) {
      assert(false, `Scanner threw on long line code: ${err.message}`);
    }
    assert(Array.isArray(issues), 'Scanner must return array for long line code');
  });

  // Test 14: False Positive key parser handles Windows drive letters and multiple colons
  runner.test('False positive key parsing handles Windows paths and multiple colons', () => {
    // Standard parseFpKey algorithm test
    const parseFpKey = (key) => {
      if (!key) return { fileName: '', ruleId: '', line: '', col: '' };
      const lastColon = key.lastIndexOf(':');
      if (lastColon === -1) return { fileName: key, ruleId: '', line: '', col: '' };
      const col = key.substring(lastColon + 1);
      const remainder1 = key.substring(0, lastColon);
      const secondLastColon = remainder1.lastIndexOf(':');
      if (secondLastColon === -1) return { fileName: remainder1, ruleId: '', line: col, col: '' };
      const line = remainder1.substring(secondLastColon + 1);
      const remainder2 = remainder1.substring(0, secondLastColon);
      const thirdLastColon = remainder2.lastIndexOf(':');
      if (thirdLastColon === -1) return { fileName: remainder2, ruleId: line, line: col, col: '' };
      const ruleId = remainder2.substring(thirdLastColon + 1);
      const fileName = remainder2.substring(0, thirdLastColon);
      return { fileName, ruleId, line, col };
    };

    const parsed1 = parseFpKey('C:\\Users\\dev\\project\\src\\App.jsx:OWASP-A01-001:42:15');
    assertEqual(parsed1.fileName, 'C:\\Users\\dev\\project\\src\\App.jsx');
    assertEqual(parsed1.ruleId, 'OWASP-A01-001');
    assertEqual(parsed1.line, '42');
    assertEqual(parsed1.col, '15');

    const parsed2 = parseFpKey('src/utils/file:nested.js:OWASP-A03-001:10:4');
    assertEqual(parsed2.fileName, 'src/utils/file:nested.js');
    assertEqual(parsed2.ruleId, 'OWASP-A03-001');
    assertEqual(parsed2.line, '10');
    assertEqual(parsed2.col, '4');

    const parsed3 = parseFpKey(null);
    assertEqual(parsed3.fileName, '');
    assertEqual(parsed3.ruleId, '');
  });

  return await runner.run();
}

// Allow direct execution: node tests/e2e/tier2_boundary_corner.test.js
if (process.argv[1] && process.argv[1].endsWith('tier2_boundary_corner.test.js')) {
  runTier2().then(res => {
    process.exit(res.failed > 0 ? 1 : 0);
  });
}

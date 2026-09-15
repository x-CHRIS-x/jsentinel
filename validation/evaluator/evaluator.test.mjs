import test from 'node:test';
import assert from 'node:assert/strict';

import {
  JSentinelEvaluator,
  EVALUATOR_VERSION,
  scanWithWebAdapter,
  scanWithExtensionAdapter,
  adaptSuppliedOutput,
  loadWebScanner,
  loadExtensionScanner,
  matchSampleFindings,
  calculateEvaluationMetrics,
  validateEvaluationResult,
  SCHEMA_VERSION
} from './index.mjs';

import {
  FIXTURE_CORRECT,
  FIXTURE_MISSING,
  FIXTURE_UNRELATED,
  FIXTURE_DUPLICATE,
  FIXTURE_MULTIPLE_ONLY_ONE_MATCH,
  FIXTURE_ONE_CANNOT_MATCH_TWO,
  FIXTURE_PARSE_FAILURE,
  FIXTURE_PARTIAL,
  FIXTURE_FAILED,
  FIXTURE_CLEAN_NEGATIVE,
  FIXTURE_CLEAN_FALSE_POSITIVE,
  FIXTURE_ADVISORY_ONLY,
  FIXTURE_METADATA_ERROR,
  FIXTURE_SCENARIO,
  FIXTURE_UNSUPPORTED_NULL_RULE
} from './fixtures/synthetic-cases.mjs';

test('1. Correct Match: matches expected rule and location one-to-one (TP)', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(FIXTURE_CORRECT.manifest, FIXTURE_CORRECT.scanResult);

  assert.equal(match.vulnerabilities.matchedCount, 1, 'Exactly one matched vulnerability');
  assert.equal(match.vulnerabilities.missedCount, 0, 'Zero missed vulnerabilities');
  assert.equal(match.vulnerabilities.unmatchedCount, 0, 'Zero unmatched findings');
  assert.equal(match.vulnerabilities.duplicateCount, 0, 'Zero duplicate findings');

  const m = match.vulnerabilities.matched[0];
  assert.equal(m.expected.ruleId, 'OWASP-A03-001');
  assert.equal(m.actualFinding.ruleId, 'OWASP-A03-001');
  assert.equal(m.detectionMatch, true);
  assert.equal(m.metadataChecks.categoryMatch, true);
  assert.equal(m.metadataChecks.severityMatch, true);
  assert.equal(m.metadataChecks.locationMatch, true);
  assert.equal(m.metadataChecks.metadataValid, true);
});

test('2. Missing Finding: expected vulnerability without scanner finding recorded as missed (FN)', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(FIXTURE_MISSING.manifest, FIXTURE_MISSING.scanResult);

  assert.equal(match.vulnerabilities.matchedCount, 0, 'Zero matched vulnerabilities');
  assert.equal(match.vulnerabilities.missedCount, 1, 'Exactly one missed vulnerability');
  assert.equal(match.vulnerabilities.missed[0].expected.ruleId, 'OWASP-A03-002');
  assert.equal(match.vulnerabilities.missed[0].detectionMatch, false);
});

test('3. Unrelated Alert: wrong rule/location cannot satisfy target expectation', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(FIXTURE_UNRELATED.manifest, FIXTURE_UNRELATED.scanResult);

  assert.equal(match.vulnerabilities.matchedCount, 0, 'Unrelated alert must not satisfy target');
  assert.equal(match.vulnerabilities.missedCount, 1, 'Target expectation must be missed');
  assert.equal(match.vulnerabilities.unmatchedCount, 1, 'Unrelated alert must be flagged unmatched');
  assert.equal(match.vulnerabilities.unmatched[0].adjudicationStatus, 'PENDING_MANUAL_ADJUDICATION');
});

test('4. Duplicate Findings: duplicates cannot inflate target detection matches', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(FIXTURE_DUPLICATE.manifest, FIXTURE_DUPLICATE.scanResult);

  assert.equal(match.vulnerabilities.matchedCount, 1, 'Target matched exactly once');
  assert.equal(match.vulnerabilities.duplicateCount, 1, 'Duplicate finding isolated');
  assert.equal(match.vulnerabilities.duplicateCount + match.vulnerabilities.matchedCount, 2);
  assert.equal(match.vulnerabilities.duplicates[0].adjudicationStatus, 'DUPLICATE_OF_TARGET');
});

test('5. Multiple Findings Only One Match: extra findings categorized as duplicate or unmatched', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_MULTIPLE_ONLY_ONE_MATCH.manifest,
    FIXTURE_MULTIPLE_ONLY_ONE_MATCH.scanResult
  );

  assert.equal(match.vulnerabilities.matchedCount, 1, 'Only one matching finding');
  assert.equal(match.vulnerabilities.matched[0].expected.ruleId, 'OWASP-A07-001');
  assert.equal(match.vulnerabilities.unmatchedCount, 2, 'Two remaining findings are unmatched');
});

test('6. One Actual Finding Cannot Match Two Expectations: single alert cannot satisfy two targets', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_ONE_CANNOT_MATCH_TWO.manifest,
    FIXTURE_ONE_CANNOT_MATCH_TWO.scanResult
  );

  assert.equal(match.vulnerabilities.expectedCount, 2, 'Two expected vulnerabilities');
  assert.equal(match.vulnerabilities.matchedCount, 1, 'Only one target matched');
  assert.equal(match.vulnerabilities.missedCount, 1, 'Second target remained missed');
});

test('7. Parse Failure: empty findings on parse error must NOT be inferred as clean negative', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_PARSE_FAILURE.manifest,
    FIXTURE_PARSE_FAILURE.scanResult
  );

  assert.equal(match.scanStatus, 'failed');
  assert.equal(match.hasScanError, true);

  // When evaluating a suite, parse failure must be excluded from completed matrix N
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_PARSE_FAILURE.manifest],
    scanResultsMap: { [FIXTURE_PARSE_FAILURE.manifest.fileName]: FIXTURE_PARSE_FAILURE.scanResult }
  });

  assert.equal(suiteResult.scanCompletion.failed, 1, 'Counted in scanCompletion.failed');
  assert.equal(suiteResult.scanCompletion.completed, 0, 'Zero completed scans');
  assert.equal(suiteResult.fileConfusionMatrix.N, 0, 'Excluded from matrix sample size N');
  assert.equal(suiteResult.fileConfusionMatrix.accuracy, null);
  assert.equal(suiteResult.fileConfusionMatrix.percentages.accuracy, 'N/A');
});

test('8. Partial Scan: rule execution error excluded from completed matrix N', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_PARTIAL.manifest],
    scanResultsMap: { [FIXTURE_PARTIAL.manifest.fileName]: FIXTURE_PARTIAL.scanResult }
  });

  assert.equal(suiteResult.scanCompletion.partial, 1, 'Counted in scanCompletion.partial');
  assert.equal(suiteResult.scanCompletion.completed, 0);
  assert.equal(suiteResult.fileConfusionMatrix.N, 0);
  assert.equal(suiteResult.fileConfusionMatrix.TN, 0, 'Must not count as TN clean negative');
});

test('9. Failed Scan: unhandled engine error excluded from completed matrix N', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_FAILED.manifest],
    scanResultsMap: { [FIXTURE_FAILED.manifest.fileName]: FIXTURE_FAILED.scanResult }
  });

  assert.equal(suiteResult.scanCompletion.failed, 1, 'Counted in scanCompletion.failed');
  assert.equal(suiteResult.scanCompletion.completed, 0);
  assert.equal(suiteResult.fileConfusionMatrix.N, 0);
});

test('10. Clean Negative: clean file with zero alerts correctly classified as TN', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_CLEAN_NEGATIVE.manifest],
    scanResultsMap: { [FIXTURE_CLEAN_NEGATIVE.manifest.fileName]: FIXTURE_CLEAN_NEGATIVE.scanResult }
  });

  assert.equal(suiteResult.fileConfusionMatrix.TN, 1, 'Clean file is TN');
  assert.equal(suiteResult.fileConfusionMatrix.FP, 0);
  assert.equal(suiteResult.fileConfusionMatrix.TP, 0);
  assert.equal(suiteResult.fileConfusionMatrix.FN, 0);
  assert.equal(suiteResult.fileConfusionMatrix.N, 1);
  assert.equal(suiteResult.fileConfusionMatrix.specificity, 1.0);
  assert.equal(suiteResult.fileConfusionMatrix.percentages.specificity, '100.00%');
});

test('11. Clean Unrelated False Positive: clean file with alert classified as FP', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_CLEAN_FALSE_POSITIVE.manifest],
    scanResultsMap: { [FIXTURE_CLEAN_FALSE_POSITIVE.manifest.fileName]: FIXTURE_CLEAN_FALSE_POSITIVE.scanResult }
  });

  assert.equal(suiteResult.fileConfusionMatrix.FP, 1, 'Clean file with alert is FP');
  assert.equal(suiteResult.fileConfusionMatrix.TN, 0);
  assert.equal(suiteResult.fileConfusionMatrix.N, 1);
  assert.equal(suiteResult.fileConfusionMatrix.falsePositiveRate, 1.0);
  assert.equal(suiteResult.fileConfusionMatrix.percentages.falsePositiveRate, '100.00%');
});

test('12. Advisory A06 Policy: A06 alert excluded from vulnerability metrics and retained separately', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_ADVISORY_ONLY.manifest],
    scanResultsMap: { [FIXTURE_ADVISORY_ONLY.manifest.fileName]: FIXTURE_ADVISORY_ONLY.scanResult }
  });

  // Clean file with ONLY advisory finding remains TN in vulnerability matrix
  assert.equal(suiteResult.fileConfusionMatrix.TN, 1, 'Clean file with advisory is TN');
  assert.equal(suiteResult.fileConfusionMatrix.FP, 0, 'Advisory does not cause FP');
  assert.equal(suiteResult.fileConfusionMatrix.TP, 0);
  assert.equal(suiteResult.fileConfusionMatrix.FN, 0);

  // Advisory metrics retained separately
  assert.equal(suiteResult.advisoryMetrics.totalExpectedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.detectedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.matchedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.advisoryRecall, 1.0);
  assert.equal(suiteResult.advisoryMetrics.advisoryRecallPercentage, '100.00%');
});

test('13. Zero Denominator Protection: returns null and N/A without NaN or throwing', () => {
  const evaluator = new JSentinelEvaluator();
  // Evaluate empty suite
  const emptyResult = evaluator.evaluateSuite({
    manifestFiles: [],
    scanResultsMap: {}
  });

  const cm = emptyResult.fileConfusionMatrix;
  assert.equal(cm.N, 0);
  assert.equal(cm.accuracy, null);
  assert.equal(cm.precision, null);
  assert.equal(cm.recall, null);
  assert.equal(cm.specificity, null);
  assert.equal(cm.falsePositiveRate, null);
  assert.equal(cm.falseNegativeRate, null);

  assert.equal(cm.percentages.accuracy, 'N/A');
  assert.equal(cm.percentages.precision, 'N/A');
  assert.equal(cm.percentages.recall, 'N/A');
  assert.equal(cm.percentages.specificity, 'N/A');
  assert.equal(cm.percentages.falsePositiveRate, 'N/A');
  assert.equal(cm.percentages.falseNegativeRate, 'N/A');

  assert.equal(emptyResult.expectedRuleMetrics.expectedRuleRecall, null);
  assert.equal(emptyResult.expectedRuleMetrics.expectedRuleRecallPercentage, 'N/A');
});

test('14. Metadata Error Separate from Detection: detection matches while metadata mismatch is flagged', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_METADATA_ERROR.manifest,
    FIXTURE_METADATA_ERROR.scanResult
  );

  assert.equal(match.vulnerabilities.matchedCount, 1, 'Detection match succeeds on rule and location');
  const m = match.vulnerabilities.matched[0];
  assert.equal(m.detectionMatch, true);
  assert.equal(m.metadataChecks.locationMatch, true);
  assert.equal(m.metadataChecks.categoryMatch, false, 'Category mismatch detected');
  assert.equal(m.metadataChecks.severityMatch, false, 'Severity mismatch detected');
  assert.equal(m.metadataChecks.metadataValid, false);
  assert.equal(m.metadataChecks.metadataErrors.length, 2);
  assert.equal(m.metadataChecks.semanticDescriptionStatus, 'PENDING_MANUAL_SEMANTIC_REVIEW');
});

test('15. Scenario Segregation: scenarios excluded from controlled matrix and reported separately', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_CORRECT.manifest, FIXTURE_SCENARIO.manifest],
    scanResultsMap: {
      [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult,
      [FIXTURE_SCENARIO.manifest.fileName]: FIXTURE_SCENARIO.scanResult
    }
  });

  assert.equal(suiteResult.scanCompletion.excluded, 1, 'Scenario counted in excluded');
  assert.equal(suiteResult.scanCompletion.completed, 1, 'Only controlled sample in completed');
  assert.equal(suiteResult.fileConfusionMatrix.N, 1, 'Matrix sample size includes only controlled sample');
  assert.equal(suiteResult.scenarioObservations.length, 1, 'Scenario observation retained separately');
  assert.equal(suiteResult.scenarioObservations[0].scenarioId, 'SCENARIO-SYNTH-001');
  assert.equal(suiteResult.scenarioObservations[0].vulnerabilities.matchedCount, 1);
  assert.equal(suiteResult.scenarioObservations[0].advisories.matchedCount, 1);
});

test('16. Unsupported Null-Rule Policy: null ruleId cannot be detected or matched', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_UNSUPPORTED_NULL_RULE.manifest,
    FIXTURE_UNSUPPORTED_NULL_RULE.scanResult
  );

  assert.equal(match.vulnerabilities.unsupportedCount, 1, 'Flagged as unsupported rule');
  assert.equal(match.vulnerabilities.matchedCount, 0, 'Cannot be matched by scanner alert');
  assert.equal(match.vulnerabilities.unsupported[0].status, 'UNSUPPORTED_RULE');
  assert.equal(match.vulnerabilities.unmatchedCount, 1, 'Actual alert remains unmatched');
});

test('17. Web Adapter Live Execution and Error Handling', async () => {
  // A. Valid code scanning
  const validCode = 'eval("var x = " + location.search);';
  const validResult = await scanWithWebAdapter(validCode, 'test-eval.js');

  assert.equal(validResult.status, 'completed');
  assert.equal(validResult.hasError, false);
  assert.ok(validResult.findings.length > 0, 'Should detect eval');
  assert.equal(validResult.findings[0].ruleId, 'OWASP-A03-001');
  assert.equal(validResult.findings[0].location.line, 1);

  // B. Parse failure handling (error recovery enabled in babel standalone, but severe broken tokens)
  const invalidInput = null;
  const errorResult = await scanWithWebAdapter(invalidInput, 'null.js');

  assert.equal(errorResult.status, 'failed');
  assert.equal(errorResult.hasError, true);
  assert.ok(errorResult.error.length > 0);
  assert.equal(errorResult.findings.length, 0);

  // C. Injected throwing scanner test
  const throwingEngine = {
    scanFile: async () => { throw new Error('Simulated engine explosion'); },
    rules: []
  };
  const crashedResult = await scanWithWebAdapter('const a = 1;', 'crashed.js', throwingEngine);
  assert.equal(crashedResult.status, 'failed');
  assert.equal(crashedResult.hasError, true);
  assert.equal(crashedResult.error, 'Simulated engine explosion');
});

test('18. Extension Adapter Live Execution and Error Handling', () => {
  // A. Valid code scanning
  const validCode = 'eval("var x = " + location.search);';
  const validResult = scanWithExtensionAdapter(validCode, 'test-eval.js');

  assert.equal(validResult.status, 'completed');
  assert.equal(validResult.hasError, false);
  assert.ok(validResult.findings.length > 0, 'Should detect eval');
  assert.equal(validResult.findings[0].ruleId, 'OWASP-A03-001');
  assert.equal(validResult.findings[0].location.line, 1);

  // B. Parse failure handling
  const brokenCode = 'const x = {;';
  const parseFailResult = scanWithExtensionAdapter(brokenCode, 'broken.js');
  assert.equal(parseFailResult.status, 'failed');
  assert.equal(parseFailResult.hasError, true);
  assert.ok(parseFailResult.error.includes('Unexpected token'));

  // C. Injected throwing scanner test
  const throwingEngine = {
    scanCode: () => { throw new Error('Simulated extension error'); },
    rules: []
  };
  const crashedResult = scanWithExtensionAdapter('const a = 1;', 'crashed.js', throwingEngine);
  assert.equal(crashedResult.status, 'failed');
  assert.equal(crashedResult.hasError, true);
  assert.equal(crashedResult.error, 'Simulated extension error');
});

test('19. Schema Validation and CSV/JSON Export Pipeline', () => {
  const evaluator = new JSentinelEvaluator();

  const manifestFiles = [
    FIXTURE_CORRECT.manifest,
    FIXTURE_MISSING.manifest,
    FIXTURE_CLEAN_NEGATIVE.manifest,
    FIXTURE_CLEAN_FALSE_POSITIVE.manifest,
    FIXTURE_ADVISORY_ONLY.manifest,
    FIXTURE_SCENARIO.manifest
  ];

  const scanResultsMap = {
    [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult,
    [FIXTURE_MISSING.manifest.fileName]: FIXTURE_MISSING.scanResult,
    [FIXTURE_CLEAN_NEGATIVE.manifest.fileName]: FIXTURE_CLEAN_NEGATIVE.scanResult,
    [FIXTURE_CLEAN_FALSE_POSITIVE.manifest.fileName]: FIXTURE_CLEAN_FALSE_POSITIVE.scanResult,
    [FIXTURE_ADVISORY_ONLY.manifest.fileName]: FIXTURE_ADVISORY_ONLY.scanResult,
    [FIXTURE_SCENARIO.manifest.fileName]: FIXTURE_SCENARIO.scanResult
  };

  const suiteResult = evaluator.evaluateSuite({ manifestFiles, scanResultsMap });

  // Validate output against schema
  const validation = validateEvaluationResult(suiteResult);
  assert.equal(validation.valid, true, `Result should validate against schema: ${validation.errors.join(', ')}`);

  // Verify JSON export
  const jsonExport = evaluator.exportJSON(suiteResult);
  assert.ok(typeof jsonExport === 'string' && jsonExport.length > 0);
  const parsed = JSON.parse(jsonExport);
  assert.equal(parsed.schemaVersion, SCHEMA_VERSION);
  assert.equal(parsed.fileConfusionMatrix.TP, 1);
  assert.equal(parsed.fileConfusionMatrix.FN, 1);
  assert.equal(parsed.fileConfusionMatrix.TN, 2); // Clean negative + Advisory only
  assert.equal(parsed.fileConfusionMatrix.FP, 1); // Clean false positive
  assert.equal(parsed.fileConfusionMatrix.N, 5);

  // Verify CSV exports
  const { metricsSummaryCsv, fileResultsCsv, findingsDetailsCsv } = evaluator.exportCSV(suiteResult);
  assert.ok(metricsSummaryCsv.includes('True Positives (TP)'));
  assert.ok(metricsSummaryCsv.includes('Completed Sample Size (N)'));
  assert.ok(fileResultsCsv.includes('correct-eval.js'));
  assert.ok(findingsDetailsCsv.includes('OWASP-A03-001'));
});

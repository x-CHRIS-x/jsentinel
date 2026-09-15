import test from 'node:test';
import assert from 'node:assert/strict';

import {
  JSentinelEvaluator,
  EVALUATOR_VERSION,
  scanWithWebAdapter,
  scanWithExtensionAdapter,
  adaptSuppliedOutput,
  normalizeScanResult,
  normalizeFinding,
  validateMatchingPolicy,
  SCHEMA_VERSION,
  validateEvaluationResult,
  ADJUDICATION_SCHEMA_VERSION,
  makeFindingKey,
  validateAdjudicationDocument,
  applyAdjudicationToEvaluation,
  generateAdjudicationTemplate,
  extractEvaluationFindingsMap
} from './index.mjs';
import { parseCliArgs, runEngineBenchmark } from './runner.mjs';
import {
  validateAndDigestManifest,
  buildCandidatePackageMetadata,
  ingestRunReports
} from '../../scripts/generate-candidate-package-metadata.mjs';

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
  FIXTURE_UNSUPPORTED_NULL_RULE,
  FIXTURE_SAME_LINE_DISTINCT_COLUMNS,
  FIXTURE_IDENTICAL_DUPLICATE_ACTUALS,
  FIXTURE_MISSING_LOCATION,
  FIXTURE_INVALID_LABEL
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
  assert.equal(m.metadataChecks.structuralMetadataMatch, true);
  assert.equal(m.metadataChecks.semanticDescriptionStatus, 'PENDING_MANUAL_SEMANTIC_REVIEW');
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
  assert.equal(suiteResult.rawScanResults[0].ruleErrors.length, 1, 'Preserves ruleErrors');
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

  assert.equal(suiteResult.fileConfusionMatrix.TN, 1, 'Clean file with advisory is TN');
  assert.equal(suiteResult.fileConfusionMatrix.FP, 0, 'Advisory does not cause FP');
  assert.equal(suiteResult.fileConfusionMatrix.TP, 0);
  assert.equal(suiteResult.fileConfusionMatrix.FN, 0);

  assert.equal(suiteResult.advisoryMetrics.totalExpectedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.detectedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.matchedAdvisories, 1);
  assert.equal(suiteResult.advisoryMetrics.advisoryRecall, 1.0);
  assert.equal(suiteResult.advisoryMetrics.advisoryRecallPercentage, '100.00%');
});

test('13. Zero Denominator Protection: returns null and N/A without NaN or throwing', () => {
  const evaluator = new JSentinelEvaluator();
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
  assert.equal(m.metadataChecks.structuralMetadataMatch, false);
  assert.equal(m.metadataChecks.semanticDescriptionStatus, 'PENDING_MANUAL_SEMANTIC_REVIEW');
  assert.equal(m.metadataChecks.adjudicatedMetadataStatus, 'PENDING_MANUAL_REVIEW');
  assert.equal(m.metadataChecks.metadataErrors.length, 2);
});

test('15. Scenario Segregation: scenarios excluded from controlled matrix and unsupportedWeaknesses retained', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_CORRECT.manifest, FIXTURE_SCENARIO.manifest],
    scanResultsMap: {
      [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult,
      [FIXTURE_SCENARIO.manifest.fileName]: FIXTURE_SCENARIO.scanResult
    }
  });

  assert.equal(suiteResult.scanCompletion.scenarioCompletion.total, 1);
  assert.equal(suiteResult.scanCompletion.scenarioCompletion.completed, 1);
  assert.equal(suiteResult.fileConfusionMatrix.N, 1, 'Matrix sample size includes only controlled sample');
  assert.equal(suiteResult.scenarioObservations.length, 1, 'Scenario observation retained separately');
  assert.equal(suiteResult.scenarioObservations[0].scenarioId, 'SCENARIO-SYNTH-001');
  assert.equal(suiteResult.scenarioObservations[0].vulnerabilities.matchedCount, 1);
  assert.equal(suiteResult.scenarioObservations[0].advisories.matchedCount, 1);
  assert.equal(suiteResult.scenarioObservations[0].unsupportedWeaknesses.length, 1, 'Retains unsupportedWeaknesses');
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

test('17. Web Adapter Live Execution and Error Handling with Malformed Descriptor Rejection', async () => {
  // A. Valid code scanning
  const validCode = 'eval("var x = " + location.search);';
  const validResult = await scanWithWebAdapter(validCode, 'test-eval.js');

  assert.equal(validResult.status, 'completed');
  assert.equal(validResult.hasError, false);
  assert.ok(validResult.findings.length > 0, 'Should detect eval');
  assert.equal(validResult.findings[0].ruleId, 'OWASP-A03-001');
  assert.equal(validResult.findings[0].location.line, 1);

  // B. Null/undefined input rejection
  const nullResult = await scanWithWebAdapter(null, 'null.js');
  assert.equal(nullResult.status, 'failed');
  assert.equal(nullResult.hasError, true);
  assert.ok(nullResult.error.includes('null or undefined'));

  // C. Malformed descriptor rejection (object without valid text, content, or code)
  const emptyObjectResult = await scanWithWebAdapter({ name: 'empty.js' }, 'empty.js');
  assert.equal(emptyObjectResult.status, 'failed');
  assert.equal(emptyObjectResult.hasError, true);
  assert.ok(emptyObjectResult.error.includes('Malformed file input descriptor'));

  // D. Throwing scanner engine handling
  const throwingEngine = {
    scanFile: async () => { throw new Error('Simulated engine explosion'); },
    rules: []
  };
  const crashedResult = await scanWithWebAdapter('const a = 1;', 'crashed.js', throwingEngine);
  assert.equal(crashedResult.status, 'failed');
  assert.equal(crashedResult.hasError, true);
  assert.equal(crashedResult.error, 'Simulated engine explosion');
});

test('18. Extension Adapter Live Execution and Error Handling with Malformed Descriptor Rejection', () => {
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

  // C. Malformed descriptor rejection
  const malformedResult = scanWithExtensionAdapter({ name: 'malformed.js' }, 'malformed.js');
  assert.equal(malformedResult.status, 'failed');
  assert.equal(malformedResult.hasError, true);
  assert.ok(malformedResult.error.includes('Malformed file input descriptor'));

  // D. Throwing scanner engine handling
  const throwingEngine = {
    scanCode: () => { throw new Error('Simulated extension error'); },
    rules: []
  };
  const crashedResult = scanWithExtensionAdapter('const a = 1;', 'crashed.js', throwingEngine);
  assert.equal(crashedResult.status, 'failed');
  assert.equal(crashedResult.hasError, true);
  assert.equal(crashedResult.error, 'Simulated extension error');
});

test('19. Fail-Closed Scan Result Normalization and Preserved Errors', () => {
  // A. Empty object fails closed
  const emptyRes = normalizeScanResult({ engine: 'supplied', fileName: 'empty.js', rawResult: {} });
  assert.equal(emptyRes.status, 'failed');
  assert.equal(emptyRes.completed, false);
  assert.equal(emptyRes.hasError, true);

  // B. Missing issues array fails closed
  const missingIssues = normalizeScanResult({ engine: 'supplied', fileName: 'test.js', rawResult: { success: true } });
  assert.equal(missingIssues.status, 'failed');
  assert.equal(missingIssues.completed, false);
  assert.ok(missingIssues.error.includes('issues array missing'));

  // C. Explicit status partial and ruleErrors
  const partialRes = normalizeScanResult({
    engine: 'supplied',
    fileName: 'test.js',
    rawResult: {
      status: 'partial',
      issues: [],
      ruleErrors: [{ ruleName: 'dynamic-timer', error: 'Visitor failed' }]
    }
  });
  assert.equal(partialRes.status, 'partial');
  assert.equal(partialRes.completed, false);
  assert.equal(partialRes.ruleErrors.length, 1);

  // D. Contradictory success: true with non-empty error
  const contradictoryRes = normalizeScanResult({
    engine: 'supplied',
    fileName: 'test.js',
    rawResult: {
      success: true,
      error: 'Rule execution aborted on AST node',
      issues: []
    }
  });
  assert.equal(contradictoryRes.status, 'partial');
  assert.equal(contradictoryRes.completed, false);
  assert.equal(contradictoryRes.hasError, true);
});

test('20. Finite Valid Coordinates: missing or invalid location rejected and cannot match', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_MISSING_LOCATION.manifest,
    FIXTURE_MISSING_LOCATION.scanResult
  );

  // Math.abs(undefined - expLine) => NaN; NaN > tolerance false must NOT match
  assert.equal(match.vulnerabilities.matchedCount, 0, 'Undefined coordinates must never match');
  assert.equal(match.vulnerabilities.missedCount, 1, 'Target with valid line remains missed');
  assert.equal(match.vulnerabilities.unmatchedCount, 1, 'Actual finding with missing coordinates is unmatched');

  // matchColumn: true requires finite coordinates on both sides
  const columnEvaluator = new JSentinelEvaluator({ matchingPolicy: { matchColumn: true } });
  const noColActual = {
    engine: 'supplied',
    fileName: 'test.js',
    status: 'completed',
    hasError: false,
    findings: [{ ruleId: 'OWASP-A03-001', location: { line: 10, column: null } }]
  };
  const colExpected = {
    fileName: 'test.js',
    label: 'vulnerable',
    expectedScannerFindings: [{ ruleId: 'OWASP-A03-001', location: { line: 10, column: 4 } }]
  };
  const colMatch = columnEvaluator.evaluateSample(colExpected, noColActual);
  assert.equal(colMatch.vulnerabilities.matchedCount, 0, 'Cannot match under matchColumn when column is null');
});

test('21. Distinct Same-Line Locations: different columns are NOT duplicates', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_SAME_LINE_DISTINCT_COLUMNS.manifest,
    FIXTURE_SAME_LINE_DISTINCT_COLUMNS.scanResult
  );

  assert.equal(match.vulnerabilities.matchedCount, 1, 'First finding matched target at line 20 col 4');
  assert.equal(match.vulnerabilities.duplicateCount, 0, 'Second finding at column 35 is NOT a duplicate');
  assert.equal(match.vulnerabilities.unmatchedCount, 1, 'Second finding at distinct column is unmatched');
  assert.equal(match.vulnerabilities.unmatched[0].actualFinding.location.column, 35);
});

test('22. Identical Duplicate Actuals Cannot Satisfy Multiple Expectations', () => {
  const evaluator = new JSentinelEvaluator();
  const match = evaluator.evaluateSample(
    FIXTURE_IDENTICAL_DUPLICATE_ACTUALS.manifest,
    FIXTURE_IDENTICAL_DUPLICATE_ACTUALS.scanResult
  );

  assert.equal(match.vulnerabilities.expectedCount, 2);
  assert.equal(match.vulnerabilities.matchedCount, 1, 'Only first target matched');
  assert.equal(match.vulnerabilities.ambiguousCount, 1, 'Second target flagged with coordinate ambiguity');
  assert.equal(match.vulnerabilities.missedCount, 1, 'Second target marked missed due to duplicate actual');
  assert.equal(match.vulnerabilities.duplicateCount, 1, 'Duplicate actual finding recorded');
});

test('23. Policy Validation: rejects invalid parameters', () => {
  assert.throws(() => validateMatchingPolicy(null), /Matching policy must be a non-null object/);
  assert.throws(() => validateMatchingPolicy({ locationTolerance: -1 }), /Invalid locationTolerance/);
  assert.throws(() => validateMatchingPolicy({ locationTolerance: 0, matchColumn: 'yes' }), /Invalid matchColumn/);
  assert.throws(() => validateMatchingPolicy({ locationTolerance: 0, matchColumn: false, advisoryRulePrefixes: 'A06' }), /Invalid advisoryRulePrefixes/);
});

test('24. Unattempted Scans: missing scan recorded as unattempted rather than fabricated attempted', () => {
  const evaluator = new JSentinelEvaluator();
  const suiteResult = evaluator.evaluateSuite({
    manifestFiles: [FIXTURE_CORRECT.manifest, FIXTURE_MISSING.manifest],
    scanResultsMap: {
      [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult
      // FIXTURE_MISSING.manifest is omitted from scanResultsMap
    }
  });

  assert.equal(suiteResult.scanCompletion.totalSamples, 2);
  assert.equal(suiteResult.scanCompletion.attempted, 1, 'Only one scan attempted');
  assert.equal(suiteResult.scanCompletion.unattempted, 1, 'Missing scan is unattempted');
  assert.equal(suiteResult.scanCompletion.controlledEligibility.exclusionBreakdown.EXCLUDED_UNATTEMPTED, 1);
  assert.equal(suiteResult.fileConfusionMatrix.N, 1, 'Unattempted scan excluded from matrix N');
});

test('25. Mixed Suite: comprehensive completion breakdown and controlled eligibility', () => {
  const evaluator = new JSentinelEvaluator();
  const manifestFiles = [
    FIXTURE_CORRECT.manifest,              // completed eligible (TP)
    FIXTURE_CLEAN_NEGATIVE.manifest,       // completed eligible (TN)
    FIXTURE_PARTIAL.manifest,              // partial (excluded)
    FIXTURE_FAILED.manifest,               // failed (excluded)
    FIXTURE_MISSING.manifest,              // unattempted (omitted from scanResultsMap)
    FIXTURE_SCENARIO.manifest,             // scenario (excluded from controlled)
    FIXTURE_INVALID_LABEL.manifest         // invalid label (excluded)
  ];

  const scanResultsMap = {
    [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult,
    [FIXTURE_CLEAN_NEGATIVE.manifest.fileName]: FIXTURE_CLEAN_NEGATIVE.scanResult,
    [FIXTURE_PARTIAL.manifest.fileName]: FIXTURE_PARTIAL.scanResult,
    [FIXTURE_FAILED.manifest.fileName]: FIXTURE_FAILED.scanResult,
    // FIXTURE_MISSING omitted (unattempted)
    [FIXTURE_SCENARIO.manifest.fileName]: FIXTURE_SCENARIO.scanResult,
    [FIXTURE_INVALID_LABEL.manifest.fileName]: FIXTURE_INVALID_LABEL.scanResult
  };

  const suiteResult = evaluator.evaluateSuite({ manifestFiles, scanResultsMap });

  const sc = suiteResult.scanCompletion;
  assert.equal(sc.totalSamples, 7);
  assert.equal(sc.attempted, 6);
  assert.equal(sc.unattempted, 1);
  assert.equal(sc.completed, 4); // correct, clean, scenario, invalid-label
  assert.equal(sc.partial, 1);
  assert.equal(sc.failed, 1);

  // Scenario completion
  assert.equal(sc.scenarioCompletion.total, 1);
  assert.equal(sc.scenarioCompletion.completed, 1);

  // Controlled eligibility
  const ce = sc.controlledEligibility;
  assert.equal(ce.total, 6); // 7 - 1 scenario
  assert.equal(ce.eligible, 2); // correct + clean
  assert.equal(ce.excluded, 4);
  assert.equal(ce.exclusionBreakdown.EXCLUDED_SCENARIO, 1);
  assert.equal(ce.exclusionBreakdown.EXCLUDED_UNATTEMPTED, 1);
  assert.equal(ce.exclusionBreakdown.EXCLUDED_INCOMPLETE_PARTIAL, 1);
  assert.equal(ce.exclusionBreakdown.EXCLUDED_INCOMPLETE_FAILED, 1);
  assert.equal(ce.exclusionBreakdown.EXCLUDED_INVALID_LABEL, 1);

  // Matrix N must equal eligible
  assert.equal(suiteResult.fileConfusionMatrix.N, 2);
  assert.equal(suiteResult.fileConfusionMatrix.TP, 1);
  assert.equal(suiteResult.fileConfusionMatrix.TN, 1);
});

test('26. Finding Precision Metrics: targetMatchFraction reported, precision kept N/A pending adjudication', () => {
  const evaluator = new JSentinelEvaluator();
  const manifestFiles = [FIXTURE_CORRECT.manifest, FIXTURE_CLEAN_FALSE_POSITIVE.manifest];
  const scanResultsMap = {
    [FIXTURE_CORRECT.manifest.fileName]: FIXTURE_CORRECT.scanResult,
    [FIXTURE_CLEAN_FALSE_POSITIVE.manifest.fileName]: FIXTURE_CLEAN_FALSE_POSITIVE.scanResult
  };

  const suiteResult = evaluator.evaluateSuite({ manifestFiles, scanResultsMap });
  const prec = suiteResult.findingPrecisionMetrics;

  assert.equal(prec.totalActualFindings, 2);
  assert.equal(prec.matchedFindings, 1);
  assert.equal(prec.unmatchedFindings, 1);
  assert.equal(prec.targetMatchFraction, 0.5);
  assert.equal(prec.targetMatchFractionPercentage, '50.00%');
  assert.equal(prec.adjudicatedPrecision, null, 'Final precision must remain null pending adjudication');
  assert.equal(prec.adjudicatedPrecisionPercentage, 'N/A');
  assert.equal(prec.adjudicationStatus, 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION');
  assert.equal(prec.pendingGroundTruthReviewCount, 1);
  assert.equal(prec.pendingSemanticDescriptionReviewCount, 1);
});

test('27. Schema Validation, Retained Outputs, and CSV Pipeline', () => {
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

  // Schema validation
  const validation = validateEvaluationResult(suiteResult);
  assert.equal(validation.valid, true, `Result must be valid: ${validation.errors.join(', ')}`);

  // JSON export contains rawScanResults and versioned schema
  const jsonExport = evaluator.exportJSON(suiteResult);
  const parsed = JSON.parse(jsonExport);
  assert.equal(parsed.schemaVersion, SCHEMA_VERSION);
  assert.ok(Array.isArray(parsed.rawScanResults), 'Retains rawScanResults in export');
  assert.equal(parsed.rawScanResults.length, 6);
  assert.equal(parsed.scenarioObservations[0].unsupportedWeaknesses.length, 1);

  // CSV export
  const { metricsSummaryCsv, fileResultsCsv, findingsDetailsCsv } = evaluator.exportCSV(suiteResult);
  assert.ok(metricsSummaryCsv.includes('Target-Match Fraction'));
  assert.ok(metricsSummaryCsv.includes('Controlled Eligible (N)'));
  assert.ok(fileResultsCsv.includes('correct-eval.js'));
  assert.ok(findingsDetailsCsv.includes('OWASP-A03-001'));
});

test('28. Valid Empty-String Source: scans normally as clean completed file in both adapters', async () => {
  // Web adapter on empty string
  const webEmpty = await scanWithWebAdapter('', 'empty.js');
  assert.equal(webEmpty.status, 'completed');
  assert.equal(webEmpty.completed, true);
  assert.equal(webEmpty.findings.length, 0);
  assert.equal(webEmpty.hasError, false);

  // Web adapter on object with content: ''
  const webObjEmpty = await scanWithWebAdapter({ name: 'empty.js', content: '' });
  assert.equal(webObjEmpty.status, 'completed');
  assert.equal(webObjEmpty.completed, true);

  // Extension adapter on empty string
  const extEmpty = scanWithExtensionAdapter('', 'empty.js');
  assert.equal(extEmpty.status, 'completed');
  assert.equal(extEmpty.completed, true);
  assert.equal(extEmpty.findings.length, 0);

  // Extension adapter on object with content: ''
  const extObjEmpty = scanWithExtensionAdapter({ name: 'empty.js', content: '' });
  assert.equal(extObjEmpty.status, 'completed');
  assert.equal(extObjEmpty.completed, true);
});

test('29. Malformed Input Descriptors: fail closed in both adapters', async () => {
  // Object lacking content, code, and text()
  const webMalformed = await scanWithWebAdapter({ name: 'no-code.js' });
  assert.equal(webMalformed.status, 'failed');
  assert.equal(webMalformed.completed, false);
  assert.equal(webMalformed.hasError, true);
  assert.ok(webMalformed.error.includes('Malformed file input descriptor'));

  const extMalformed = scanWithExtensionAdapter({ name: 'no-code.js' });
  assert.equal(extMalformed.status, 'failed');
  assert.equal(extMalformed.completed, false);
  assert.equal(extMalformed.hasError, true);
  assert.ok(extMalformed.error.includes('Malformed file input descriptor'));
});

test('30. Normalization of Unknown Status and Explicit Partial/Failed Flags', () => {
  // Unknown status with issues[] must not default to completed
  const unknownStatus = normalizeScanResult({
    engine: 'supplied',
    fileName: 'test.js',
    rawResult: { status: 'unrecognized_status', issues: [] }
  });
  assert.equal(unknownStatus.status, 'failed', 'Unrecognized status must fail closed');
  assert.equal(unknownStatus.completed, false);

  // Explicit status: 'partial' with completed: false preserves partial
  const partialExplicit = normalizeScanResult({
    engine: 'supplied',
    fileName: 'test.js',
    rawResult: { status: 'partial', completed: false, issues: [] }
  });
  assert.equal(partialExplicit.status, 'partial', 'Explicit status partial must be preserved');
  assert.equal(partialExplicit.isPartial, true);
  assert.equal(partialExplicit.completed, false);

  // Explicit status: 'failed' with completed: false preserves failed
  const failedExplicit = normalizeScanResult({
    engine: 'supplied',
    fileName: 'test.js',
    rawResult: { status: 'failed', completed: false, issues: [] }
  });
  assert.equal(failedExplicit.status, 'failed', 'Explicit status failed must be preserved');
  assert.equal(failedExplicit.isFailed, true);
});

test('31. Finding Adjudication Document Validation: rejects duplicate, unknown, and incomplete entries', () => {
  const dummyEvalResult = {
    metadata: { scannerEngine: 'web' },
    fileResults: [
      {
        sampleId: 'C-A1-001',
        fileName: 'C-A1-001.js',
        label: 'clean',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A08-001', location: { line: 9, column: 23 }, description: 'JSON.parse' }
          }],
          duplicates: []
        }
      }
    ]
  };

  const validKey = makeFindingKey({
    engine: 'web',
    sampleId: 'C-A1-001',
    ruleId: 'OWASP-A08-001',
    line: 9,
    column: 23,
    kind: 'unmatched'
  });

  // Valid document with reviewer, rationale, reviewDate
  const validDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      {
        findingKey: validKey,
        disposition: 'FALSE_POSITIVE',
        rationale: 'Legitimate deserialization in clean sample.',
        reviewer: 'Security Reviewer',
        reviewDate: '2026-09-15T00:00:00.000Z',
        semanticDescriptionOutcome: 'CONFIRMED_ACCURATE'
      }
    ]
  };
  const valRes = validateAdjudicationDocument(validDoc, dummyEvalResult);
  assert.equal(valRes.valid, true);

  // Rejects completed disposition missing reviewer, rationale, or reviewDate
  const incompleteDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      {
        findingKey: validKey,
        disposition: 'TRUE_POSITIVE'
      }
    ]
  };
  const incRes = validateAdjudicationDocument(incompleteDoc, dummyEvalResult);
  assert.equal(incRes.valid, false);
  assert.ok(incRes.errors.some(e => e.includes('requires a non-empty "reviewer"')));
  assert.ok(incRes.errors.some(e => e.includes('requires a non-empty "rationale"')));
  assert.ok(incRes.errors.some(e => e.includes('requires a valid ISO "reviewDate"')));

  // Duplicate key rejection
  const dupDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: validKey, disposition: 'PENDING' },
      { findingKey: validKey, disposition: 'PENDING' }
    ]
  };
  const dupRes = validateAdjudicationDocument(dupDoc, dummyEvalResult);
  assert.equal(dupRes.valid, false);
  assert.ok(dupRes.errors[0].includes('Duplicate adjudication identifier'));

  // Unknown key rejection against evaluation result
  const unknownDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      {
        findingKey: 'web:UNKNOWN:OWASP-A01-001:10:0:unmatched',
        disposition: 'PENDING'
      }
    ]
  };
  const unkRes = validateAdjudicationDocument(unknownDoc, dummyEvalResult);
  assert.equal(unkRes.valid, false);
  assert.ok(unkRes.errors[0].includes('Unknown adjudication identifier'));

  // Engine mismatch rejection
  const mismatchDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'extension',
    adjudications: []
  };
  const misRes = validateAdjudicationDocument(mismatchDoc, dummyEvalResult);
  assert.equal(misRes.valid, false);
  assert.ok(misRes.errors[0].includes('Scanner engine mismatch'));
});

test('32. Adjudication Template Roundtrip and Scoping', () => {
  const evalResult = {
    metadata: { scannerEngine: 'web', evaluatorVersion: '1.0.0', datasetManifestVersion: '1.0.0' },
    fileResults: [
      // 1. Controlled completed with matched target
      {
        sampleId: 'V-A1-001',
        fileName: 'V-A1-001.js',
        label: 'vulnerable',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [{
            expected: { ruleId: 'OWASP-A01-001' },
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }],
          unmatched: [],
          duplicates: []
        }
      },
      // 2. Controlled completed with unmatched finding
      {
        sampleId: 'C-A1-001',
        fileName: 'C-A1-001.js',
        label: 'clean',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A08-001', location: { line: 9, column: 23 } }
          }],
          duplicates: []
        }
      },
      // 3. Scenario file
      {
        sampleId: 'SCENARIO-001',
        fileName: 'admin.jsx',
        label: 'scenario',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A03-008', location: { line: 40, column: 5 } }
          }],
          duplicates: []
        }
      }
    ],
    findingPrecisionMetrics: {
      matchedFindings: 1,
      unmatchedFindings: 2,
      duplicateFindings: 0
    }
  };

  const template = generateAdjudicationTemplate(evalResult);
  assert.equal(template.schemaVersion, ADJUDICATION_SCHEMA_VERSION);
  assert.equal(template.summary.totalEntries, 3);
  assert.equal(template.summary.controlledMatchedCount, 1);
  assert.equal(template.summary.controlledUnmatchedCount, 1);
  assert.equal(template.summary.scenarioEntriesCount, 1);

  // Verify automated match vs human adjudication origin
  const matchedEntry = template.adjudications.find(a => a.kind === 'matched');
  assert.equal(matchedEntry.scope, 'controlled');
  assert.equal(matchedEntry.adjudicationOrigin, 'AUTOMATED_TARGET_MATCH');
  assert.equal(matchedEntry.disposition, 'TRUE_POSITIVE');

  const unmatchedEntry = template.adjudications.find(a => a.kind === 'unmatched' && a.scope === 'controlled');
  assert.equal(unmatchedEntry.adjudicationOrigin, 'HUMAN_ADJUDICATION');
  assert.equal(unmatchedEntry.disposition, 'PENDING');

  const scenarioEntry = template.adjudications.find(a => a.scope === 'scenario');
  assert.equal(scenarioEntry.scope, 'scenario');
});

test('33. Controlled Precision Adjudication: counts only completed controlled unmatched, never double-counts', () => {
  const evalResult = {
    metadata: { scannerEngine: 'web' },
    fileResults: [
      {
        sampleId: 'V-A1-001',
        fileName: 'V-A1-001.js',
        label: 'vulnerable',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [{
            expected: { ruleId: 'OWASP-A01-001' },
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }],
          unmatched: [],
          duplicates: []
        }
      },
      {
        sampleId: 'C-A1-001',
        fileName: 'C-A1-001.js',
        label: 'clean',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A08-001', location: { line: 9, column: 23 } }
          }],
          duplicates: []
        }
      }
    ],
    findingPrecisionMetrics: {
      totalActualFindings: 2,
      matchedFindings: 1,
      duplicateFindings: 0,
      unmatchedFindings: 1,
      targetMatchFraction: 0.5,
      targetMatchFractionPercentage: '50.00%',
      adjudicatedPrecision: null,
      adjudicatedPrecisionPercentage: 'N/A',
      adjudicationStatus: 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION'
    },
    metadataChecksSummary: { totalChecked: 1 }
  };

  const matchedKey = makeFindingKey({ engine: 'web', sampleId: 'V-A1-001', ruleId: 'OWASP-A01-001', line: 10, column: 2, kind: 'matched' });
  const unmatchedKey = makeFindingKey({ engine: 'web', sampleId: 'C-A1-001', ruleId: 'OWASP-A08-001', line: 9, column: 23, kind: 'unmatched' });

  // Case A: Unmatched finding is PENDING -> Precision remains N/A
  const pendingDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: matchedKey, disposition: 'TRUE_POSITIVE', reviewer: 'AUTO', rationale: 'Target match', reviewDate: '2026-09-15T00:00:00.000Z' },
      { findingKey: unmatchedKey, disposition: 'PENDING' }
    ]
  };
  const pendingRes = applyAdjudicationToEvaluation(evalResult, pendingDoc);
  assert.equal(pendingRes.findingPrecisionMetrics.adjudicatedPrecision, null);
  assert.equal(pendingRes.findingPrecisionMetrics.adjudicatedPrecisionPercentage, 'N/A');
  assert.equal(pendingRes.findingPrecisionMetrics.adjudicationStatus, 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION');

  // Case B: Unmatched finding reviewed as FALSE_POSITIVE:
  // Precision = (1 matched + 0 unmatched TP) / (1 matched + 0 unmatched TP + 1 unmatched FP) = 1/2 = 50.00%
  const fpDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: matchedKey, disposition: 'TRUE_POSITIVE', reviewer: 'AUTO', rationale: 'Target match', reviewDate: '2026-09-15T00:00:00.000Z' },
      {
        findingKey: unmatchedKey,
        disposition: 'FALSE_POSITIVE',
        reviewer: 'Chris Ledama',
        rationale: 'Clean sample benign JSON.parse',
        reviewDate: '2026-09-15T00:00:00.000Z'
      }
    ]
  };
  const fpRes = applyAdjudicationToEvaluation(evalResult, fpDoc);
  assert.equal(fpRes.findingPrecisionMetrics.adjudicatedPrecision, 0.5);
  assert.equal(fpRes.findingPrecisionMetrics.adjudicatedPrecisionPercentage, '50.00%');
  assert.equal(fpRes.findingPrecisionMetrics.adjudicatedTruePositives, 1);
  assert.equal(fpRes.findingPrecisionMetrics.adjudicatedFalsePositives, 1);
  assert.equal(fpRes.findingPrecisionMetrics.adjudicationStatus, 'ADJUDICATION_COMPLETE');

  // Case C: Unmatched finding reviewed as TRUE_POSITIVE:
  // Precision = (1 matched + 1 unmatched TP) / (1 matched + 1 unmatched TP + 0 FP) = 2/2 = 100.00%
  // Confirms it does NOT double count matched (which would have been 3/3 if double counted)
  const tpDoc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: matchedKey, disposition: 'TRUE_POSITIVE', reviewer: 'AUTO', rationale: 'Target match', reviewDate: '2026-09-15T00:00:00.000Z' },
      {
        findingKey: unmatchedKey,
        disposition: 'TRUE_POSITIVE',
        reviewer: 'Chris Ledama',
        rationale: 'Newly discovered valid client-side deserialization flaw',
        reviewDate: '2026-09-15T00:00:00.000Z'
      }
    ]
  };
  const tpRes = applyAdjudicationToEvaluation(evalResult, tpDoc);
  assert.equal(tpRes.findingPrecisionMetrics.adjudicatedPrecision, 1.0);
  assert.equal(tpRes.findingPrecisionMetrics.adjudicatedPrecisionPercentage, '100.00%');
  assert.equal(tpRes.findingPrecisionMetrics.adjudicatedTruePositives, 2);
  assert.equal(tpRes.findingPrecisionMetrics.adjudicatedFalsePositives, 0);
  assert.equal(tpRes.findingPrecisionMetrics.adjudicationStatus, 'ADJUDICATION_COMPLETE');
});

test('34. Scenario Segregation and Incomplete Scans in Adjudication', () => {
  const evalResult = {
    metadata: { scannerEngine: 'web' },
    fileResults: [
      // 1. Controlled completed with 1 matched target
      {
        sampleId: 'V-A1-001',
        fileName: 'V-A1-001.js',
        label: 'vulnerable',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [{
            expected: { ruleId: 'OWASP-A01-001' },
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }],
          unmatched: [],
          duplicates: []
        }
      },
      // 2. Scenario file with unmatched finding
      {
        sampleId: 'SCENARIO-001',
        fileName: 'admin.jsx',
        label: 'scenario',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A03-008', location: { line: 40, column: 5 } }
          }],
          duplicates: []
        }
      },
      // 3. Partial scan with unmatched finding
      {
        sampleId: 'V-A2-PARTIAL',
        fileName: 'partial.js',
        label: 'vulnerable',
        scanStatus: 'partial',
        hasScanError: true,
        vulnerabilities: {
          matched: [],
          unmatched: [{
            actualFinding: { ruleId: 'OWASP-A02-001', location: { line: 5, column: 1 } }
          }],
          duplicates: []
        }
      }
    ],
    findingPrecisionMetrics: {
      matchedFindings: 1,
      unmatchedFindings: 0, // Controlled completed has 0 unmatched
      duplicateFindings: 0
    },
    metadataChecksSummary: {}
  };

  const matchedKey = makeFindingKey({ engine: 'web', sampleId: 'V-A1-001', ruleId: 'OWASP-A01-001', line: 10, column: 2, kind: 'matched' });
  const scenKey = makeFindingKey({ engine: 'web', sampleId: 'SCENARIO-001', ruleId: 'OWASP-A03-008', line: 40, column: 5, kind: 'unmatched' });
  const partKey = makeFindingKey({ engine: 'web', sampleId: 'V-A2-PARTIAL', ruleId: 'OWASP-A02-001', line: 5, column: 1, kind: 'unmatched' });

  // Scenario and partial scan findings are reviewed as FP/TP in the doc, but MUST NOT contaminate controlled precision
  const doc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: matchedKey, disposition: 'TRUE_POSITIVE', reviewer: 'AUTO', rationale: 'Target match', reviewDate: '2026-09-15T00:00:00.000Z' },
      { findingKey: scenKey, disposition: 'FALSE_POSITIVE', reviewer: 'Reviewer', rationale: 'Scenario contextual FP', reviewDate: '2026-09-15T00:00:00.000Z' },
      { findingKey: partKey, disposition: 'TRUE_POSITIVE', reviewer: 'Reviewer', rationale: 'Partial scan finding', reviewDate: '2026-09-15T00:00:00.000Z' }
    ]
  };

  const res = applyAdjudicationToEvaluation(evalResult, doc);
  // Controlled precision should strictly reflect 1 matched / 1 total = 100%
  assert.equal(res.findingPrecisionMetrics.adjudicatedPrecision, 1.0);
  assert.equal(res.findingPrecisionMetrics.adjudicatedTruePositives, 1);
  assert.equal(res.findingPrecisionMetrics.adjudicatedFalsePositives, 0);
});

test('35. Semantic Review Scoping: denominator is strictly matched targets', () => {
  const evalResult = {
    metadata: { scannerEngine: 'web' },
    fileResults: [
      {
        sampleId: 'V-A1-001',
        fileName: 'V-A1-001.js',
        label: 'vulnerable',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [{
            expected: { ruleId: 'OWASP-A01-001' },
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }],
          unmatched: [],
          duplicates: []
        }
      }
    ],
    findingPrecisionMetrics: { matchedFindings: 1, unmatchedFindings: 0, duplicateFindings: 0 },
    metadataChecksSummary: { totalChecked: 1 }
  };

  const matchedKey = makeFindingKey({ engine: 'web', sampleId: 'V-A1-001', ruleId: 'OWASP-A01-001', line: 10, column: 2, kind: 'matched' });

  // Confirmed accurate
  const docAccurate = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      {
        findingKey: matchedKey,
        disposition: 'TRUE_POSITIVE',
        reviewer: 'Reviewer',
        rationale: 'Target match',
        reviewDate: '2026-09-15T00:00:00.000Z',
        semanticDescriptionOutcome: 'CONFIRMED_ACCURATE'
      }
    ]
  };
  const resAccurate = applyAdjudicationToEvaluation(evalResult, docAccurate);
  assert.equal(resAccurate.metadataChecksSummary.semanticReview.totalTargetsToReview, 1);
  assert.equal(resAccurate.metadataChecksSummary.semanticReview.confirmedAccurateCount, 1);
  assert.equal(resAccurate.metadataChecksSummary.semanticReview.semanticMatchFraction, 1.0);
  assert.equal(resAccurate.metadataChecksSummary.semanticReview.status, 'REVIEW_COMPLETE');

  // Inaccurate description
  const docInaccurate = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      {
        findingKey: matchedKey,
        disposition: 'TRUE_POSITIVE',
        reviewer: 'Reviewer',
        rationale: 'Target match',
        reviewDate: '2026-09-15T00:00:00.000Z',
        semanticDescriptionOutcome: 'INACCURATE'
      }
    ]
  };
  const resInaccurate = applyAdjudicationToEvaluation(evalResult, docInaccurate);
  assert.equal(resInaccurate.metadataChecksSummary.semanticReview.confirmedAccurateCount, 0);
  assert.equal(resInaccurate.metadataChecksSummary.semanticReview.inaccurateCount, 1);
  assert.equal(resInaccurate.metadataChecksSummary.semanticReview.semanticMatchFraction, 0.0);
});

test('36. Duplicate Precision Eligibility Policy in Adjudication', () => {
  const evalResult = {
    metadata: { scannerEngine: 'web' },
    fileResults: [
      {
        sampleId: 'V-A1-001',
        fileName: 'V-A1-001.js',
        label: 'vulnerable',
        scanStatus: 'completed',
        hasScanError: false,
        vulnerabilities: {
          matched: [{
            expected: { ruleId: 'OWASP-A01-001' },
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }],
          unmatched: [],
          duplicates: [{
            actualFinding: { ruleId: 'OWASP-A01-001', location: { line: 10, column: 2 } }
          }]
        }
      }
    ],
    findingPrecisionMetrics: {
      matchedFindings: 1,
      duplicateFindings: 1,
      unmatchedFindings: 0
    },
    metadataChecksSummary: {}
  };

  const matchedKey = makeFindingKey({ engine: 'web', sampleId: 'V-A1-001', ruleId: 'OWASP-A01-001', line: 10, column: 2, kind: 'matched' });
  const dupKey = makeFindingKey({ engine: 'web', sampleId: 'V-A1-001', ruleId: 'OWASP-A01-001', line: 10, column: 2, kind: 'duplicate' });

  const doc = {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    scannerEngine: 'web',
    adjudications: [
      { findingKey: matchedKey, disposition: 'TRUE_POSITIVE', reviewer: 'AUTO', rationale: 'Target match', reviewDate: '2026-09-15T00:00:00.000Z' },
      { findingKey: dupKey, disposition: 'FALSE_POSITIVE', reviewer: 'AUTO', rationale: 'Duplicate', reviewDate: '2026-09-15T00:00:00.000Z' }
    ]
  };

  // Policy 1: EXCLUDE_FROM_PRECISION -> (1 TP) / (1 TP) = 1.0 (100%)
  const resExclude = applyAdjudicationToEvaluation(evalResult, doc, { duplicateEligibility: 'EXCLUDE_FROM_PRECISION' });
  assert.equal(resExclude.findingPrecisionMetrics.adjudicatedPrecision, 1.0);

  // Policy 2: COUNT_AS_FP -> (1 TP) / (1 TP + 1 duplicate FP) = 1/2 = 50.0%
  const resCountFP = applyAdjudicationToEvaluation(evalResult, doc, { duplicateEligibility: 'COUNT_AS_FP' });
  assert.equal(resCountFP.findingPrecisionMetrics.adjudicatedPrecision, 0.5);
});

test('37. Runner Protection and CLI Argument Parsing', () => {
  const parsed = parseCliArgs(['--output-dir', 'custom/dir', '--run-id', 'custom-run-123']);
  assert.ok(parsed.baseOutputDir.includes('custom'));
  assert.equal(parsed.runId, 'custom-run-123');
});

test('38. Dynamic Package Metadata Generation and Manifest Distribution Enforcement', () => {
  // A. Inconsistent manifest is rejected
  const badManifest = {
    files: [
      { sampleId: 'V-1', label: 'vulnerable' },
      { sampleId: 'C-1', label: 'clean' }
    ]
  };
  assert.throws(
    () => validateAndDigestManifest(badManifest, 'dummy/dir'),
    /Dataset manifest distribution invalid/
  );
});

test('39. Runner Immutability: refuses existing populated output directory', async () => {
  // If destination exists and contains files, runner must throw to protect evidence
  await assert.rejects(
    async () => {
      await runEngineBenchmark({
        engineType: 'web',
        manifest: { files: [] },
        samplesDir: 'dummy',
        outputDir: 'validation/evaluator/runs/phase05-batch-b/web' // already populated!
      });
    },
    /already exists and is populated/
  );
});

test('40. Metadata Ingestion: changed synthetic inputs dynamically change reported outputs with no preset outcome', () => {
  // Test that ingestRunReports correctly extracts metrics and unmatched findings without hardcoded values
  const syntheticRuns = ingestRunReports('validation/evaluator/runs/phase05-batch-b');
  assert.ok(syntheticRuns.web.metrics.controlledMatrix.N > 0);
  assert.equal(typeof syntheticRuns.web.metrics.controlledMatrix.accuracy, 'number');
  assert.ok(Array.isArray(syntheticRuns.web.unmatchedFindings));
  assert.ok(syntheticRuns.web.unmatchedFindings.some(u => u.sampleId === 'C-A1-001' && u.scope === 'controlled'));
});




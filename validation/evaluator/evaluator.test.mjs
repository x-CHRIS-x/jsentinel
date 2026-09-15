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
  validateEvaluationResult
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

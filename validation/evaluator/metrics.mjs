/**
 * JSentinel Metrics Calculator
 * 
 * Computes separate measurements in accordance with Phase 05:
 * 1. File-level confusion matrix (TP, TN, FP, FN, Accuracy, Precision, Recall, Specificity, FPR, FNR).
 * 2. Expected-rule recall (one-to-one matched target vulnerabilities).
 * 3. Finding precision (with unmatched findings marked PENDING manual ground-truth adjudication).
 * 4. Metadata check accuracies (category, severity, location, semantic description).
 * 5. Advisory A06 tracking (retained separately, excluded from vulnerability metrics).
 * 6. Scan completion counts (attempted, completed, partial, failed, excluded).
 * 
 * Strict zero-denominator rule: Any division with a zero denominator yields null / "N/A".
 */

/**
 * Safely computes ratio and formats percentage string with zero-denominator protection.
 * 
 * @param {number} numerator 
 * @param {number} denominator 
 * @returns {{ value: number|null, percentage: string }}
 */
export const safeRatio = (numerator, denominator) => {
  if (!denominator || typeof denominator !== 'number' || denominator <= 0) {
    return { value: null, percentage: 'N/A' };
  }
  const val = numerator / denominator;
  const pct = (val * 100).toFixed(2) + '%';
  return { value: val, percentage: pct };
};

/**
 * Calculates comprehensive metrics across all matched sample results.
 * 
 * @param {Array<Object>} sampleMatches - Array of results from matchSampleFindings.
 * @param {Array<Object>} rawScanResults - Array of normalized scan results.
 * @returns {Object} Full structured metrics report matching result schema.
 */
export const calculateEvaluationMetrics = (sampleMatches = [], rawScanResults = []) => {
  // 1. Scan Completion Counts
  let attempted = sampleMatches.length;
  let completed = 0;
  let partial = 0;
  let failed = 0;
  let excluded = 0;

  for (const item of sampleMatches) {
    if (item.label === 'scenario') {
      excluded++;
      continue;
    }
    if (item.scanStatus === 'failed') {
      failed++;
    } else if (item.scanStatus === 'partial' || item.hasScanError) {
      partial++;
    } else if (item.scanStatus === 'completed') {
      completed++;
    } else {
      failed++;
    }
  }

  // 2. Controlled File-Level Confusion Matrix
  // Evaluated ONLY on completed eligible controlled scans.
  let TP = 0;
  let TN = 0;
  let FP = 0;
  let FN = 0;

  const evaluatedControlledFiles = [];

  for (const item of sampleMatches) {
    // Exclude scenarios from controlled matrix
    if (item.label === 'scenario') {
      continue;
    }

    // Incomplete or failed scans are NOT clean negatives; excluded from matrix N
    if (item.scanStatus !== 'completed' || item.hasScanError) {
      continue;
    }

    const isVulnerableExpected = item.label === 'vulnerable';
    const isCleanExpected = item.label === 'clean';

    // File is positive if it has at least one eligible in-scope vulnerability alert
    // (A06 advisories are excluded by matching engine)
    const hasVulnAlert = item.vulnerabilities.actualCount > 0;

    let classification = '';
    if (isVulnerableExpected) {
      if (hasVulnAlert) {
        TP++;
        classification = 'TP';
      } else {
        FN++;
        classification = 'FN';
      }
    } else if (isCleanExpected) {
      if (hasVulnAlert) {
        FP++;
        classification = 'FP';
      } else {
        TN++;
        classification = 'TN';
      }
    }

    evaluatedControlledFiles.push({
      sampleId: item.sampleId,
      fileName: item.fileName,
      expectedLabel: item.label,
      isPositive: hasVulnAlert,
      classification,
      vulnerabilitiesCount: item.vulnerabilities.actualCount,
      advisoriesCount: item.advisories.actualCount
    });
  }

  const N = TP + TN + FP + FN;

  const accRatio = safeRatio(TP + TN, N);
  const precRatio = safeRatio(TP, TP + FP);
  const recRatio = safeRatio(TP, TP + FN);
  const specRatio = safeRatio(TN, TN + FP);
  const fprRatio = safeRatio(FP, FP + TN);
  const fnrRatio = safeRatio(FN, FN + TP);

  const fileConfusionMatrix = {
    TP,
    TN,
    FP,
    FN,
    N,
    accuracy: accRatio.value,
    precision: precRatio.value,
    recall: recRatio.value,
    specificity: specRatio.value,
    falsePositiveRate: fprRatio.value,
    falseNegativeRate: fnrRatio.value,
    percentages: {
      accuracy: accRatio.percentage,
      precision: precRatio.percentage,
      recall: recRatio.percentage,
      specificity: specRatio.percentage,
      falsePositiveRate: fprRatio.percentage,
      falseNegativeRate: fnrRatio.percentage
    }
  };

  // 3. Expected-Rule Recall Metrics (Controlled files completed scans)
  let totalExpected = 0;
  let matchedExpected = 0;
  let missedExpected = 0;
  let unsupportedExpected = 0;

  for (const item of sampleMatches) {
    if (item.label === 'scenario') continue;
    if (item.scanStatus !== 'completed' || item.hasScanError) continue;

    totalExpected += item.vulnerabilities.expectedCount;
    matchedExpected += item.vulnerabilities.matchedCount;
    missedExpected += item.vulnerabilities.missedCount;
    unsupportedExpected += item.vulnerabilities.unsupportedCount;
  }

  const expectedRuleRecallRatio = safeRatio(matchedExpected, totalExpected);

  const expectedRuleMetrics = {
    totalExpected,
    matchedExpected,
    missedExpected,
    unsupportedExpected,
    expectedRuleRecall: expectedRuleRecallRatio.value,
    expectedRuleRecallPercentage: expectedRuleRecallRatio.percentage
  };

  // 4. Finding-Level Precision Metrics
  let totalActualFindings = 0;
  let matchedFindings = 0;
  let duplicateFindings = 0;
  let unmatchedFindings = 0;

  for (const item of sampleMatches) {
    if (item.label === 'scenario') continue;
    if (item.scanStatus !== 'completed' || item.hasScanError) continue;

    totalActualFindings += item.vulnerabilities.actualCount;
    matchedFindings += item.vulnerabilities.matchedCount;
    duplicateFindings += item.vulnerabilities.duplicateCount;
    unmatchedFindings += item.vulnerabilities.unmatchedCount;
  }

  const provPrecRatio = safeRatio(matchedFindings, totalActualFindings);

  const findingPrecisionMetrics = {
    totalActualFindings,
    matchedFindings,
    duplicateFindings,
    unmatchedFindings,
    adjudicationStatus: 'PENDING manual ground-truth adjudication',
    provisionalPrecision: provPrecRatio.value,
    provisionalPrecisionPercentage: provPrecRatio.percentage
  };

  // 5. Advisory A06 Metrics (Retained separately)
  let totalExpectedAdvisories = 0;
  let detectedAdvisories = 0;
  let matchedAdvisories = 0;

  for (const item of sampleMatches) {
    if (item.label === 'scenario') continue;
    if (item.scanStatus !== 'completed' || item.hasScanError) continue;

    totalExpectedAdvisories += item.advisories.expectedCount;
    detectedAdvisories += item.advisories.actualCount;
    matchedAdvisories += item.advisories.matchedCount;
  }

  const advisoryRecallRatio = safeRatio(matchedAdvisories, totalExpectedAdvisories);

  const advisoryMetrics = {
    totalExpectedAdvisories,
    detectedAdvisories,
    matchedAdvisories,
    advisoryRecall: advisoryRecallRatio.value,
    advisoryRecallPercentage: advisoryRecallRatio.percentage,
    policyNote: 'OWASP-A06-001 component-review advisory signals are reported separately and excluded from vulnerability totals and confusion matrix.'
  };

  // 6. Metadata Checks Summary (Category, Severity, Location, Semantic Description)
  let totalChecked = 0;
  let categoryMatches = 0;
  let categoryMismatches = 0;
  let severityMatches = 0;
  let severityMismatches = 0;
  let locationMatches = 0;
  let locationMismatches = 0;

  for (const item of sampleMatches) {
    if (item.label === 'scenario') continue;
    if (item.scanStatus !== 'completed' || item.hasScanError) continue;

    for (const match of item.vulnerabilities.matched) {
      totalChecked++;
      const checks = match.metadataChecks;
      if (checks.categoryMatch) categoryMatches++; else categoryMismatches++;
      if (checks.severityMatch) severityMatches++; else severityMismatches++;
      if (checks.locationMatch) locationMatches++; else locationMismatches++;
    }
  }

  const catAcc = safeRatio(categoryMatches, totalChecked);
  const sevAcc = safeRatio(severityMatches, totalChecked);
  const locAcc = safeRatio(locationMatches, totalChecked);

  const metadataChecksSummary = {
    totalChecked,
    categoryMatches,
    categoryMismatches,
    severityMatches,
    severityMismatches,
    locationMatches,
    locationMismatches,
    categoryAccuracyPercentage: catAcc.percentage,
    severityAccuracyPercentage: sevAcc.percentage,
    locationAccuracyPercentage: locAcc.percentage,
    semanticDescriptionStatus: 'PENDING_MANUAL_SEMANTIC_REVIEW'
  };

  return {
    scanCompletion: {
      attempted,
      completed,
      partial,
      failed,
      excluded
    },
    fileConfusionMatrix,
    expectedRuleMetrics,
    findingPrecisionMetrics,
    advisoryMetrics,
    metadataChecksSummary,
    evaluatedControlledFiles
  };
};

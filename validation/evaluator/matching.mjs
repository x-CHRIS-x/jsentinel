/**
 * JSentinel One-to-One Matching and Metadata Validation Engine
 * 
 * Implements Phase 05 matching specifications:
 * - One-to-one expected rule + reviewed location matching.
 * - One actual finding cannot match two expectations.
 * - Duplicate findings cannot inflate target detection matches.
 * - Unrelated alerts cannot satisfy target expectations.
 * - Unsupported null-rule expectations follow explicit unresolved policy (never borrow rules).
 * - Unmatched actual findings remain marked PENDING manual ground-truth adjudication.
 * - Metadata validation (category, severity, location, semantic description)
 *   is evaluated and reported separately from detection matching.
 * - Configurable matching choices pending human freeze.
 */

export const DEFAULT_MATCHING_POLICY = {
  locationTolerance: 0, // 0 = exact line match; N = +/- N lines
  matchColumn: false,   // false = line-only; true = requires line and column
  advisoryRulePrefixes: ['OWASP-A06-'],
  unsupportedRulePolicy: 'unresolved', // 'unresolved' | 'strict'
  findingAdjudicationPolicy: 'pending' // 'pending' | 'strict_fp'
};

/**
 * Checks if a rule ID is classified as an advisory under the policy.
 * 
 * @param {string} ruleId 
 * @param {string[]} prefixes 
 * @returns {boolean}
 */
export const isAdvisoryRule = (ruleId, prefixes = DEFAULT_MATCHING_POLICY.advisoryRulePrefixes) => {
  if (!ruleId || typeof ruleId !== 'string') return false;
  return prefixes.some(prefix => ruleId.startsWith(prefix));
};

/**
 * Normalizes an OWASP category string to extract its prefix code (e.g. 'A03').
 * 
 * @param {string} cat 
 * @returns {string}
 */
export const extractCategoryCode = (cat) => {
  if (!cat || typeof cat !== 'string') return '';
  const match = cat.match(/A\d{2}/);
  return match ? match[0] : cat.trim().toUpperCase();
};

/**
 * Performs one-to-one matching between expected entries and actual findings.
 * 
 * @param {Object} params
 * @param {Object} params.sampleManifest - Manifest entry for the file.
 * @param {Object} params.scanResult - Normalized scan result from adapter.
 * @param {Object} [params.options] - Matching configuration options.
 * @returns {Object} Structured matching report.
 */
export const matchSampleFindings = ({ sampleManifest, scanResult, options = {} }) => {
  const policy = { ...DEFAULT_MATCHING_POLICY, ...options };
  const allActualFindings = Array.isArray(scanResult?.findings) ? scanResult.findings : [];

  // Separate vulnerability findings from advisory findings
  const actualVulnFindings = [];
  const actualAdvisoryFindings = [];

  for (const finding of allActualFindings) {
    if (isAdvisoryRule(finding.ruleId, policy.advisoryRulePrefixes) || finding.findingType === 'advisory') {
      actualAdvisoryFindings.push(finding);
    } else {
      actualVulnFindings.push(finding);
    }
  }

  const expectedVulns = Array.isArray(sampleManifest?.expectedScannerFindings)
    ? sampleManifest.expectedScannerFindings
    : [];
  const expectedAdvisories = Array.isArray(sampleManifest?.expectedAdvisories)
    ? sampleManifest.expectedAdvisories
    : [];

  // --- Step 1: Match In-Scope Vulnerabilities ---
  const matchedVulnerabilities = [];
  const missedVulnerabilities = [];
  const unsupportedVulnerabilities = [];
  const usedVulnFindingIndices = new Set();

  for (const expected of expectedVulns) {
    // Check for unsupported null-rule policy
    if (!expected.ruleId || expected.ruleId === 'null') {
      unsupportedVulnerabilities.push({
        status: 'UNSUPPORTED_RULE',
        policy: policy.unsupportedRulePolicy,
        expected,
        actualFinding: null,
        message: 'Expected weakness has null or unsupported ruleId; explicit unresolved policy applied.'
      });
      continue;
    }

    let matchIdx = -1;
    for (let i = 0; i < actualVulnFindings.length; i++) {
      if (usedVulnFindingIndices.has(i)) continue;

      const candidate = actualVulnFindings[i];
      if (candidate.ruleId !== expected.ruleId) continue;

      const expLine = expected.location?.line;
      const actLine = candidate.location?.line;

      const lineDiff = Math.abs(actLine - expLine);
      if (lineDiff > policy.locationTolerance) continue;

      if (policy.matchColumn && expected.location?.column !== undefined && candidate.location?.column !== null) {
        if (candidate.location.column !== expected.location.column) continue;
      }

      matchIdx = i;
      break;
    }

    if (matchIdx !== -1) {
      usedVulnFindingIndices.add(matchIdx);
      const actual = actualVulnFindings[matchIdx];

      // Metadata verification performed separately from detection match
      const expCatCode = extractCategoryCode(expected.owasp2021Category);
      const actCatCode = extractCategoryCode(actual.category);
      const categoryMatch = Boolean(expCatCode && actCatCode && expCatCode === actCatCode);

      const expSev = (expected.severity || '').toUpperCase();
      const actSev = (actual.severity || '').toUpperCase();
      const severityMatch = expSev === actSev;

      const locationMatch = actual.location.line === expected.location?.line;

      const metadataErrors = [];
      if (!categoryMatch) {
        metadataErrors.push(`Category mismatch: expected "${expected.owasp2021Category}", got "${actual.category}"`);
      }
      if (!severityMatch) {
        metadataErrors.push(`Severity mismatch: expected "${expected.severity}", got "${actual.severity}"`);
      }
      if (!locationMatch) {
        metadataErrors.push(`Location line difference: expected line ${expected.location?.line}, got line ${actual.location.line}`);
      }

      matchedVulnerabilities.push({
        status: 'MATCHED',
        expected,
        actualFinding: actual,
        detectionMatch: true,
        metadataChecks: {
          categoryMatch,
          severityMatch,
          locationMatch,
          semanticDescriptionStatus: 'PENDING_MANUAL_SEMANTIC_REVIEW',
          metadataValid: metadataErrors.length === 0,
          metadataErrors
        }
      });
    } else {
      missedVulnerabilities.push({
        status: 'MISSED',
        expected,
        actualFinding: null,
        detectionMatch: false,
        metadataChecks: null
      });
    }
  }

  // Identify duplicate findings and unmatched findings
  const duplicateVulnerabilities = [];
  const unmatchedVulnerabilities = [];

  for (let i = 0; i < actualVulnFindings.length; i++) {
    if (usedVulnFindingIndices.has(i)) continue;

    const extra = actualVulnFindings[i];
    // Check if this extra finding duplicates an already matched expectation
    const isDuplicateOfMatched = matchedVulnerabilities.some(m =>
      m.expected.ruleId === extra.ruleId &&
      Math.abs(extra.location.line - m.expected.location?.line) <= policy.locationTolerance
    );

    if (isDuplicateOfMatched) {
      duplicateVulnerabilities.push({
        status: 'DUPLICATE',
        actualFinding: extra,
        adjudicationStatus: 'DUPLICATE_OF_TARGET',
        message: 'Duplicate finding of an already matched target; cannot inflate target matches.'
      });
    } else {
      unmatchedVulnerabilities.push({
        status: 'UNMATCHED',
        actualFinding: extra,
        adjudicationStatus: 'PENDING_MANUAL_ADJUDICATION',
        message: 'Unmatched actual finding; requires manual ground-truth adjudication.'
      });
    }
  }

  // --- Step 2: Match Advisories Separately ---
  const matchedAdvisories = [];
  const missedAdvisories = [];
  const usedAdvisoryIndices = new Set();

  for (const expectedAdv of expectedAdvisories) {
    let advIdx = -1;
    for (let i = 0; i < actualAdvisoryFindings.length; i++) {
      if (usedAdvisoryIndices.has(i)) continue;
      const candidateAdv = actualAdvisoryFindings[i];
      if (candidateAdv.ruleId === expectedAdv.ruleId) {
        advIdx = i;
        break;
      }
    }

    if (advIdx !== -1) {
      usedAdvisoryIndices.add(advIdx);
      matchedAdvisories.push({
        status: 'MATCHED_ADVISORY',
        expected: expectedAdv,
        actualFinding: actualAdvisoryFindings[advIdx]
      });
    } else {
      missedAdvisories.push({
        status: 'MISSED_ADVISORY',
        expected: expectedAdv,
        actualFinding: null
      });
    }
  }

  const extraAdvisories = [];
  for (let i = 0; i < actualAdvisoryFindings.length; i++) {
    if (!usedAdvisoryIndices.has(i)) {
      extraAdvisories.push({
        status: 'EXTRA_ADVISORY',
        actualFinding: actualAdvisoryFindings[i]
      });
    }
  }

  return {
    sampleId: sampleManifest?.sampleId || scanResult?.fileName || 'unknown',
    fileName: sampleManifest?.fileName || scanResult?.fileName || 'unknown',
    label: sampleManifest?.label || 'unknown',
    scanStatus: scanResult?.status || 'unknown',
    hasScanError: Boolean(scanResult?.hasError),
    vulnerabilities: {
      matched: matchedVulnerabilities,
      missed: missedVulnerabilities,
      unsupported: unsupportedVulnerabilities,
      duplicates: duplicateVulnerabilities,
      unmatched: unmatchedVulnerabilities,
      expectedCount: expectedVulns.length,
      actualCount: actualVulnFindings.length,
      matchedCount: matchedVulnerabilities.length,
      missedCount: missedVulnerabilities.length,
      unsupportedCount: unsupportedVulnerabilities.length,
      duplicateCount: duplicateVulnerabilities.length,
      unmatchedCount: unmatchedVulnerabilities.length
    },
    advisories: {
      matched: matchedAdvisories,
      missed: missedAdvisories,
      extra: extraAdvisories,
      expectedCount: expectedAdvisories.length,
      actualCount: actualAdvisoryFindings.length,
      matchedCount: matchedAdvisories.length,
      missedCount: missedAdvisories.length,
      extraCount: extraAdvisories.length
    },
    policyApplied: policy
  };
};

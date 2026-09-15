/**
 * JSentinel One-to-One Matching and Metadata Validation Engine
 * 
 * Implements Phase 05 matching specifications:
 * - One-to-one expected rule + reviewed location matching.
 * - Requires finite, valid positive line numbers; rejects missing/invalid locations.
 * - Under matchColumn=true, requires finite column numbers on both sides.
 * - Preserves distinct same-line locations (different columns are not duplicates).
 * - Prevents identical duplicate actuals from satisfying multiple expectations under line-only policy.
 * - Reports coordinate ambiguity when multiple expectations compete for duplicate coordinates.
 * - Unsupported null-rule expectations follow explicit unresolved policy (never borrow rules).
 * - Unmatched actual findings remain marked PENDING manual ground-truth adjudication.
 * - Metadata validation is evaluated and reported separately from detection matching without
 *   implying that manual semantic description review has passed.
 */

export const DEFAULT_MATCHING_POLICY = {
  locationTolerance: 0, // 0 = exact line match; N = +/- N lines
  matchColumn: false,   // false = line-only; true = requires line and column
  advisoryRulePrefixes: ['OWASP-A06-']
};

/**
 * Validates matching policy configuration parameters.
 * Throws an Error if any parameter violates contract.
 * 
 * @param {Object} policy 
 */
export const validateMatchingPolicy = (policy) => {
  if (!policy || typeof policy !== 'object') {
    throw new Error('Matching policy must be a non-null object.');
  }

  if (typeof policy.locationTolerance !== 'number' || !Number.isInteger(policy.locationTolerance) || policy.locationTolerance < 0) {
    throw new Error(`Invalid locationTolerance: must be a non-negative integer, received ${policy.locationTolerance}.`);
  }

  if (typeof policy.matchColumn !== 'boolean') {
    throw new Error(`Invalid matchColumn: must be a boolean, received ${policy.matchColumn}.`);
  }

  if (!Array.isArray(policy.advisoryRulePrefixes) || policy.advisoryRulePrefixes.some(p => typeof p !== 'string' || !p)) {
    throw new Error('Invalid advisoryRulePrefixes: must be an array of non-empty strings.');
  }
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
  validateMatchingPolicy(policy);

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
  const ambiguousVulnerabilities = [];
  const usedVulnFindingIndices = new Set();
  const matchedActualCoordinates = []; // Track actual coordinates used to prevent duplicate inflation

  for (const expected of expectedVulns) {
    // Check for unsupported null-rule policy
    if (!expected.ruleId || expected.ruleId === 'null') {
      unsupportedVulnerabilities.push({
        status: 'UNSUPPORTED_RULE',
        policy: 'unresolved',
        expected,
        actualFinding: null,
        message: 'Expected weakness has null or unsupported ruleId; explicit unresolved policy applied.'
      });
      continue;
    }

    const expLine = expected.location?.line;
    // Require finite, positive line coordinate on expected vulnerability
    if (typeof expLine !== 'number' || !Number.isInteger(expLine) || expLine <= 0) {
      missedVulnerabilities.push({
        status: 'MISSED_INVALID_EXPECTED_LOCATION',
        expected,
        actualFinding: null,
        detectionMatch: false,
        message: `Expected vulnerability has missing or non-positive line coordinate: ${expLine}`
      });
      continue;
    }

    let matchIdx = -1;
    let coordinateAmbiguityFound = false;

    for (let i = 0; i < actualVulnFindings.length; i++) {
      if (usedVulnFindingIndices.has(i)) continue;

      const candidate = actualVulnFindings[i];
      if (candidate.ruleId !== expected.ruleId) continue;

      const actLine = candidate.location?.line;
      // Require finite, positive line coordinate on actual finding
      if (typeof actLine !== 'number' || !Number.isInteger(actLine) || actLine <= 0) {
        continue;
      }

      const lineDiff = Math.abs(actLine - expLine);
      if (lineDiff > policy.locationTolerance) continue;

      // Under matchColumn: true, both must have finite column coordinates
      if (policy.matchColumn) {
        const expCol = expected.location?.column;
        const actCol = candidate.location?.column;
        if (typeof expCol !== 'number' || !Number.isFinite(expCol) ||
            typeof actCol !== 'number' || !Number.isFinite(actCol)) {
          continue;
        }
        if (actCol !== expCol) continue;
      }

      // Check if this candidate shares identical coordinates with an already-matched finding for this rule
      const isIdenticalToAlreadyMatched = matchedActualCoordinates.some(coord =>
        coord.ruleId === candidate.ruleId &&
        coord.line === candidate.location.line &&
        coord.column === candidate.location.column
      );

      if (isIdenticalToAlreadyMatched) {
        // An identical duplicate actual cannot satisfy another expectation under line-only policy
        coordinateAmbiguityFound = true;
        continue;
      }

      matchIdx = i;
      break;
    }

    if (matchIdx !== -1) {
      usedVulnFindingIndices.add(matchIdx);
      const actual = actualVulnFindings[matchIdx];
      matchedActualCoordinates.push({
        ruleId: actual.ruleId,
        line: actual.location.line,
        column: actual.location.column
      });

      // Metadata verification performed separately from detection match
      const expCatCode = extractCategoryCode(expected.owasp2021Category);
      const actCatCode = extractCategoryCode(actual.category);
      const categoryMatch = Boolean(expCatCode && actCatCode && expCatCode === actCatCode);

      const expSev = expected.severity ? String(expected.severity).toUpperCase() : null;
      const actSev = actual.severity ? String(actual.severity).toUpperCase() : null;
      const severityMatch = Boolean(expSev && actSev && expSev === actSev);

      const locationMatch = actual.location.line === expected.location?.line &&
        (expected.location?.column === undefined || actual.location.column === expected.location.column);

      const metadataErrors = [];
      if (!categoryMatch) {
        metadataErrors.push(`Category mismatch: expected "${expected.owasp2021Category}", got "${actual.category}"`);
      }
      if (!severityMatch) {
        metadataErrors.push(`Severity mismatch: expected "${expected.severity}", got "${actual.severity}"`);
      }
      if (!locationMatch) {
        metadataErrors.push(`Location difference: expected ${expected.location?.line}:${expected.location?.column ?? 'any'}, got ${actual.location.line}:${actual.location.column ?? 'null'}`);
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
          structuralMetadataMatch: metadataErrors.length === 0,
          semanticDescriptionStatus: 'PENDING_MANUAL_SEMANTIC_REVIEW',
          adjudicatedMetadataStatus: 'PENDING_MANUAL_REVIEW',
          metadataErrors
        }
      });
    } else if (coordinateAmbiguityFound) {
      ambiguousVulnerabilities.push({
        status: 'AMBIGUOUS_DUPLICATE_COORDINATE',
        expected,
        actualFinding: null,
        detectionMatch: false,
        message: 'Second expectation at matching line has only identical duplicate actual coordinates; duplicate cannot satisfy distinct expectation.'
      });
      missedVulnerabilities.push({
        status: 'MISSED',
        expected,
        actualFinding: null,
        detectionMatch: false,
        metadataChecks: null,
        reason: 'AMBIGUOUS_DUPLICATE_COORDINATE'
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

    // An extra finding is a duplicate IF AND ONLY IF it shares identical rule and coordinates with a matched finding
    const isExactCoordinateDuplicate = matchedVulnerabilities.some(m =>
      m.actualFinding.ruleId === extra.ruleId &&
      m.actualFinding.location.line === extra.location.line &&
      m.actualFinding.location.column === extra.location.column
    );

    if (isExactCoordinateDuplicate) {
      duplicateVulnerabilities.push({
        status: 'DUPLICATE',
        actualFinding: extra,
        adjudicationStatus: 'DUPLICATE_OF_TARGET',
        message: 'Identical coordinate duplicate of an already matched target; cannot inflate target matches.'
      });
    } else {
      // Different column or different line is a distinct finding, not a duplicate
      unmatchedVulnerabilities.push({
        status: 'UNMATCHED',
        actualFinding: extra,
        adjudicationStatus: 'PENDING_MANUAL_ADJUDICATION',
        message: 'Unmatched actual finding at distinct coordinate; requires manual ground-truth adjudication.'
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
      ambiguous: ambiguousVulnerabilities,
      duplicates: duplicateVulnerabilities,
      unmatched: unmatchedVulnerabilities,
      expectedCount: expectedVulns.length,
      actualCount: actualVulnFindings.length,
      matchedCount: matchedVulnerabilities.length,
      missedCount: missedVulnerabilities.length,
      unsupportedCount: unsupportedVulnerabilities.length,
      ambiguousCount: ambiguousVulnerabilities.length,
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

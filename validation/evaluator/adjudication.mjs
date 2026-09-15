/**
 * JSentinel Finding Adjudication Engine and Schema (Version 1.0.0)
 * 
 * Manages human ground-truth adjudication of unmatched alerts and semantic description review:
 * - Separately versioned adjudication documents.
 * - Enforces unique finding identities (sampleId/fileName + ruleId + location).
 * - Rejects unknown or duplicate adjudication identifiers.
 * - Computes adjudicated precision when review is complete, while keeping pending as N/A.
 * - Supports duplicate precision eligibility policies and records scope ambiguities explicitly.
 */

import { safeRatio } from './metrics.mjs';

export const ADJUDICATION_SCHEMA_VERSION = '1.0.0';

/**
 * Builds a canonical finding key for unambiguous identification.
 * 
 * @param {string} fileName 
 * @param {string} ruleId 
 * @param {number|null} line 
 * @param {number|null} column 
 * @returns {string}
 */
export const makeFindingKey = (fileName, ruleId, line, column = null) => {
  const linePart = line ?? 'unknown';
  const colPart = column ?? 'any';
  return `${fileName}:${ruleId}:${linePart}:${colPart}`;
};

/**
 * Validates an adjudication document structure and identifiers.
 * 
 * @param {Object} doc - Adjudication document.
 * @param {Set<string>|Array<string>} [knownFindingKeys] - Optional set of valid finding keys.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export const validateAdjudicationDocument = (doc, knownFindingKeys = null) => {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { valid: false, errors: ['Adjudication document must be a non-null object.'] };
  }

  if (doc.schemaVersion !== ADJUDICATION_SCHEMA_VERSION) {
    errors.push(`Invalid schemaVersion: expected "${ADJUDICATION_SCHEMA_VERSION}", got "${doc.schemaVersion}".`);
  }

  if (!Array.isArray(doc.adjudications)) {
    errors.push('Adjudication document must contain an "adjudications" array.');
    return { valid: false, errors };
  }

  const seenKeys = new Set();
  const knownKeysSet = knownFindingKeys ? new Set(knownFindingKeys) : null;

  for (let i = 0; i < doc.adjudications.length; i++) {
    const entry = doc.adjudications[i];
    if (!entry || typeof entry !== 'object') {
      errors.push(`Entry [${i}] must be a non-null object.`);
      continue;
    }

    const key = entry.findingKey || makeFindingKey(entry.fileName, entry.ruleId, entry.location?.line, entry.location?.column);

    if (seenKeys.has(key)) {
      errors.push(`Duplicate adjudication identifier found: "${key}". Duplicate entries are rejected.`);
    }
    seenKeys.add(key);

    if (knownKeysSet && !knownKeysSet.has(key)) {
      errors.push(`Unknown adjudication identifier: "${key}" does not exist in the evaluated findings.`);
    }

    const validDispositions = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'PENDING'];
    if (!validDispositions.includes(entry.disposition)) {
      errors.push(`Entry [${i}] (${key}): invalid disposition "${entry.disposition}". Allowed: ${validDispositions.join(', ')}.`);
    }

    const validSemanticOutcomes = ['CONFIRMED_ACCURATE', 'INACCURATE', 'PENDING'];
    if (entry.semanticDescriptionOutcome && !validSemanticOutcomes.includes(entry.semanticDescriptionOutcome)) {
      errors.push(`Entry [${i}] (${key}): invalid semanticDescriptionOutcome "${entry.semanticDescriptionOutcome}". Allowed: ${validSemanticOutcomes.join(', ')}.`);
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

/**
 * Consumes reviewed adjudication decisions and updates precision metrics without mutating
 * raw scanner results or manifest ground truth.
 * 
 * @param {Object} findingMetrics - Initial findingPrecisionMetrics from calculateEvaluationMetrics.
 * @param {Object} metadataSummary - Initial metadataChecksSummary.
 * @param {Object} adjudicationDoc - Validated adjudication document.
 * @param {Object} [options]
 * @param {string} [options.duplicateEligibility='EXCLUDE_FROM_PRECISION'] - 'EXCLUDE_FROM_PRECISION' | 'COUNT_AS_FP'
 * @returns {Object} Updated metrics with adjudicated precision and semantic description summaries.
 */
export const applyAdjudicationToMetrics = (
  findingMetrics,
  metadataSummary,
  adjudicationDoc,
  options = {}
) => {
  const duplicatePolicy = options.duplicateEligibility || 'EXCLUDE_FROM_PRECISION';

  if (!adjudicationDoc || !Array.isArray(adjudicationDoc.adjudications)) {
    return {
      findingPrecisionMetrics: { ...findingMetrics },
      metadataChecksSummary: { ...metadataSummary }
    };
  }

  let tpCount = 0;
  let fpCount = 0;
  let pendingCount = 0;

  let descAccurateCount = 0;
  let descInaccurateCount = 0;
  let descPendingCount = 0;

  for (const entry of adjudicationDoc.adjudications) {
    if (entry.disposition === 'TRUE_POSITIVE') {
      tpCount++;
    } else if (entry.disposition === 'FALSE_POSITIVE') {
      fpCount++;
    } else {
      pendingCount++;
    }

    if (entry.semanticDescriptionOutcome === 'CONFIRMED_ACCURATE') {
      descAccurateCount++;
    } else if (entry.semanticDescriptionOutcome === 'INACCURATE') {
      descInaccurateCount++;
    } else {
      descPendingCount++;
    }
  }

  const totalUnmatched = findingMetrics.unmatchedFindings;
  const adjudicatedTotal = tpCount + fpCount;
  const hasPendingUnmatched = (totalUnmatched > adjudicatedTotal) || pendingCount > 0;

  let adjudicatedPrecision = null;
  let adjudicatedPrecisionPercentage = 'N/A';
  let adjudicationStatus = 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION';

  if (!hasPendingUnmatched && (findingMetrics.matchedFindings + tpCount + fpCount) > 0) {
    // All unmatched findings have been adjudicated
    let denominator = findingMetrics.matchedFindings + tpCount + fpCount;
    if (duplicatePolicy === 'COUNT_AS_FP') {
      denominator += findingMetrics.duplicateFindings;
    }
    const numerator = findingMetrics.matchedFindings + tpCount;
    const ratio = safeRatio(numerator, denominator);
    adjudicatedPrecision = ratio.value;
    adjudicatedPrecisionPercentage = ratio.percentage;
    adjudicationStatus = 'ADJUDICATION_COMPLETE';
  } else if (adjudicatedTotal > 0) {
    adjudicationStatus = 'PARTIALLY_ADJUDICATED';
  }

  const updatedFindingMetrics = {
    ...findingMetrics,
    adjudicatedTruePositives: tpCount,
    adjudicatedFalsePositives: fpCount,
    adjudicatedPending: pendingCount,
    adjudicatedPrecision,
    adjudicatedPrecisionPercentage,
    adjudicationStatus,
    duplicatePrecisionPolicy: duplicatePolicy,
    pendingGroundTruthReviewCount: Math.max(0, totalUnmatched - adjudicatedTotal)
  };

  const totalDescReviewed = descAccurateCount + descInaccurateCount;
  const totalDescChecked = metadataSummary.totalChecked;
  const hasPendingDesc = (totalDescChecked > totalDescReviewed) || descPendingCount > 0;

  let adjudicatedMetadataAccuracy = null;
  let adjudicatedMetadataAccuracyPercentage = 'N/A';

  if (!hasPendingDesc && totalDescChecked > 0) {
    const ratio = safeRatio(descAccurateCount, totalDescChecked);
    adjudicatedMetadataAccuracy = ratio.value;
    adjudicatedMetadataAccuracyPercentage = ratio.percentage;
  }

  const updatedMetadataSummary = {
    ...metadataSummary,
    semanticDescriptionConfirmedAccurate: descAccurateCount,
    semanticDescriptionInaccurate: descInaccurateCount,
    semanticDescriptionPending: descPendingCount,
    semanticDescriptionStatus: hasPendingDesc ? 'PARTIALLY_REVIEWED' : 'REVIEW_COMPLETE',
    adjudicatedMetadataAccuracyPercentage
  };

  return {
    findingPrecisionMetrics: updatedFindingMetrics,
    metadataChecksSummary: updatedMetadataSummary
  };
};

/**
 * Generates an empty adjudication template populated with all unmatched findings
 * and matched findings requiring semantic review.
 * 
 * @param {Object} evaluationResult 
 * @param {string} [reviewerName=null]
 * @returns {Object} Ready-to-edit adjudication template object.
 */
export const generateAdjudicationTemplate = (evaluationResult, reviewerName = null) => {
  const adjudications = [];

  for (const fileRes of evaluationResult.fileResults || []) {
    // Unmatched findings requiring ground truth review
    for (const u of fileRes.vulnerabilities.unmatched || []) {
      const f = u.actualFinding;
      adjudications.push({
        findingKey: makeFindingKey(fileRes.fileName, f.ruleId, f.location?.line, f.location?.column),
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: { line: f.location?.line, column: f.location?.column },
        sourceLine: f.sourceLine || '',
        description: f.description || '',
        disposition: 'PENDING',
        rationale: '',
        reviewer: reviewerName,
        semanticDescriptionOutcome: 'PENDING',
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    }

    // Matched findings requiring semantic description outcome review
    for (const m of fileRes.vulnerabilities.matched || []) {
      const f = m.actualFinding;
      adjudications.push({
        findingKey: makeFindingKey(fileRes.fileName, f.ruleId, f.location?.line, f.location?.column),
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: { line: f.location?.line, column: f.location?.column },
        sourceLine: f.sourceLine || '',
        description: f.description || '',
        disposition: 'TRUE_POSITIVE', // Matched target is already ground truth TP
        rationale: 'Matches ground-truth expected vulnerability.',
        reviewer: reviewerName,
        semanticDescriptionOutcome: 'PENDING',
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    }
  }

  return {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    documentType: 'JSentinelFindingAdjudication',
    createdAt: new Date().toISOString(),
    evaluatorVersion: evaluationResult.metadata?.evaluatorVersion,
    datasetManifestVersion: evaluationResult.metadata?.datasetManifestVersion,
    summary: {
      totalEntries: adjudications.length,
      unmatchedEntries: (evaluationResult.findingPrecisionMetrics?.unmatchedFindings || 0),
      matchedEntries: (evaluationResult.findingPrecisionMetrics?.matchedFindings || 0)
    },
    adjudications
  };
};

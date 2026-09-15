/**
 * JSentinel Finding Adjudication Engine and Schema (Version 1.0.0)
 * 
 * Manages human ground-truth adjudication of unmatched alerts and semantic description review:
 * - Versioned schema 1.0.0.
 * - Explicit finding scope ('controlled' | 'scenario') and kind ('unmatched' | 'matched' | 'duplicate').
 * - Stable canonical finding keys incorporating engine, sampleId, ruleId, location, and kind.
 * - Rejects unknown, duplicate, cross-run, or mismatched finding identifiers.
 * - Computes controlled finding precision without double-counting matched targets or contaminating
 *   controlled metrics with scenario observations.
 * - Requires reviewer, rationale, and reviewDate for completed human dispositions.
 * - Keeps precision as null / N/A as long as any completed controlled unmatched finding is pending review.
 */

import { safeRatio } from './metrics.mjs';

export const ADJUDICATION_SCHEMA_VERSION = '1.0.0';

/**
 * Builds a canonical finding key for unambiguous identification.
 * 
 * @param {Object} params
 * @param {string} [params.engine='any']
 * @param {string} params.sampleId
 * @param {string} params.ruleId
 * @param {number|null} [params.line=null]
 * @param {number|null} [params.column=null]
 * @param {string} [params.kind='unmatched'] - 'unmatched' | 'matched' | 'duplicate'
 * @returns {string}
 */
export const makeFindingKey = ({
  engine = 'any',
  sampleId,
  ruleId,
  line = null,
  column = null,
  kind = 'unmatched'
}) => {
  const linePart = line ?? 'unknown';
  const colPart = column ?? 'any';
  return `${engine}:${sampleId}:${ruleId}:${linePart}:${colPart}:${kind}`;
};

/**
 * Extracts a map of all valid finding entries from an evaluation result.
 * 
 * @param {Object} evaluationResult 
 * @returns {Map<string, Object>} Map of findingKey to finding context.
 */
export const extractEvaluationFindingsMap = (evaluationResult) => {
  const findingsMap = new Map();
  const engine = evaluationResult.metadata?.scannerEngine || 'any';

  for (const fileRes of evaluationResult.fileResults || []) {
    const scope = fileRes.label === 'scenario' ? 'scenario' : 'controlled';
    const isCompletedScan = fileRes.scanStatus === 'completed' && !fileRes.hasScanError;

    // 1. Matched findings
    for (const m of fileRes.vulnerabilities?.matched || []) {
      const f = m.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'matched'
      });
      findingsMap.set(key, {
        findingKey: key,
        scope,
        kind: 'matched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location,
        isCompletedScan,
        expectedRule: m.expected?.ruleId,
        actualFinding: f
      });
    }

    // 2. Unmatched findings
    for (const u of fileRes.vulnerabilities?.unmatched || []) {
      const f = u.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'unmatched'
      });
      findingsMap.set(key, {
        findingKey: key,
        scope,
        kind: 'unmatched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location,
        isCompletedScan,
        actualFinding: f
      });
    }

    // 3. Duplicate findings
    for (const d of fileRes.vulnerabilities?.duplicates || []) {
      const f = d.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'duplicate'
      });
      findingsMap.set(key, {
        findingKey: key,
        scope,
        kind: 'duplicate',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location,
        isCompletedScan,
        actualFinding: f
      });
    }
  }

  return findingsMap;
};

/**
 * Validates an adjudication document against schema and optionally against an actual evaluation result.
 * 
 * @param {Object} doc - Adjudication document.
 * @param {Object} [evaluationResult=null] - Optional actual evaluationResult to validate against.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export const validateAdjudicationDocument = (doc, evaluationResult = null) => {
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

  let knownFindingsMap = null;
  if (evaluationResult) {
    const expectedEngine = evaluationResult.metadata?.scannerEngine;
    if (doc.scannerEngine && expectedEngine && doc.scannerEngine !== expectedEngine) {
      errors.push(`Scanner engine mismatch: document specifies "${doc.scannerEngine}" but evaluation result is for "${expectedEngine}".`);
    }
    knownFindingsMap = extractEvaluationFindingsMap(evaluationResult);
  }

  const seenKeys = new Set();

  for (let i = 0; i < doc.adjudications.length; i++) {
    const entry = doc.adjudications[i];
    if (!entry || typeof entry !== 'object') {
      errors.push(`Entry [${i}] must be a non-null object.`);
      continue;
    }

    const key = entry.findingKey;
    if (!key || typeof key !== 'string') {
      errors.push(`Entry [${i}] must have a non-empty string "findingKey".`);
      continue;
    }

    if (seenKeys.has(key)) {
      errors.push(`Duplicate adjudication identifier found: "${key}". Duplicate entries are rejected.`);
    }
    seenKeys.add(key);

    if (knownFindingsMap && !knownFindingsMap.has(key)) {
      errors.push(`Unknown adjudication identifier: "${key}" does not exist in the evaluated findings.`);
    }

    const validDispositions = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'PENDING'];
    if (!validDispositions.includes(entry.disposition)) {
      errors.push(`Entry [${i}] (${key}): invalid disposition "${entry.disposition}". Allowed: ${validDispositions.join(', ')}.`);
    }

    // Require reviewer, rationale, and reviewDate for completed human adjudication
    if (entry.disposition === 'TRUE_POSITIVE' || entry.disposition === 'FALSE_POSITIVE') {
      if (!entry.reviewer || typeof entry.reviewer !== 'string' || entry.reviewer.trim() === '') {
        errors.push(`Entry [${i}] (${key}): completed disposition "${entry.disposition}" requires a non-empty "reviewer" field.`);
      }
      if (!entry.rationale || typeof entry.rationale !== 'string' || entry.rationale.trim() === '') {
        errors.push(`Entry [${i}] (${key}): completed disposition "${entry.disposition}" requires a non-empty "rationale" field.`);
      }
      if (!entry.reviewDate || typeof entry.reviewDate !== 'string' || Number.isNaN(Date.parse(entry.reviewDate))) {
        errors.push(`Entry [${i}] (${key}): completed disposition "${entry.disposition}" requires a valid ISO "reviewDate".`);
      }
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
 * Generates an empty adjudication template populated with all findings from an evaluation result.
 * Clearly separates controlled from scenario findings, and distinguishes automated target matches
 * from unmatched findings requiring human ground-truth disposition.
 * 
 * @param {Object} evaluationResult 
 * @param {Object} [options]
 * @param {string} [options.reviewerName=null]
 * @returns {Object} Ready-to-edit adjudication template object.
 */
export const generateAdjudicationTemplate = (evaluationResult, options = {}) => {
  const reviewerName = options.reviewerName || null;
  const engine = evaluationResult.metadata?.scannerEngine || 'web';
  const adjudications = [];

  for (const fileRes of evaluationResult.fileResults || []) {
    const scope = fileRes.label === 'scenario' ? 'scenario' : 'controlled';
    const isCompleted = fileRes.scanStatus === 'completed' && !fileRes.hasScanError;

    // 1. Unmatched findings (primary subjects of ground truth review)
    for (const u of fileRes.vulnerabilities?.unmatched || []) {
      const f = u.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'unmatched'
      });
      adjudications.push({
        findingKey: key,
        scope,
        kind: 'unmatched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: { line: f.location?.line, column: f.location?.column },
        sourceLine: f.sourceLine || '',
        description: f.description || '',
        scanStatus: fileRes.scanStatus,
        isCompletedScan: isCompleted,
        adjudicationOrigin: 'HUMAN_ADJUDICATION',
        disposition: 'PENDING',
        rationale: '',
        reviewer: reviewerName,
        reviewDate: null,
        semanticDescriptionOutcome: 'PENDING',
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    }

    // 2. Matched findings (already automated target matches; available for semantic review)
    for (const m of fileRes.vulnerabilities?.matched || []) {
      const f = m.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'matched'
      });
      adjudications.push({
        findingKey: key,
        scope,
        kind: 'matched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: { line: f.location?.line, column: f.location?.column },
        sourceLine: f.sourceLine || '',
        description: f.description || '',
        scanStatus: fileRes.scanStatus,
        isCompletedScan: isCompleted,
        adjudicationOrigin: 'AUTOMATED_TARGET_MATCH',
        disposition: 'TRUE_POSITIVE',
        rationale: 'Automated 1-to-1 match against ground-truth expected vulnerability target.',
        reviewer: 'AUTOMATED_EVALUATOR',
        reviewDate: new Date().toISOString(),
        semanticDescriptionOutcome: 'PENDING',
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    }

    // 3. Duplicate findings
    for (const d of fileRes.vulnerabilities?.duplicates || []) {
      const f = d.actualFinding;
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line: f.location?.line,
        column: f.location?.column,
        kind: 'duplicate'
      });
      adjudications.push({
        findingKey: key,
        scope,
        kind: 'duplicate',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: { line: f.location?.line, column: f.location?.column },
        sourceLine: f.sourceLine || '',
        description: f.description || '',
        scanStatus: fileRes.scanStatus,
        isCompletedScan: isCompleted,
        adjudicationOrigin: 'AUTOMATED_DUPLICATE_ISOLATION',
        disposition: 'FALSE_POSITIVE',
        rationale: 'Duplicate finding at same coordinates as matched target.',
        reviewer: 'AUTOMATED_EVALUATOR',
        reviewDate: new Date().toISOString(),
        semanticDescriptionOutcome: 'PENDING',
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    }
  }

  const controlledUnmatched = adjudications.filter(a => a.scope === 'controlled' && a.kind === 'unmatched');
  const controlledMatched = adjudications.filter(a => a.scope === 'controlled' && a.kind === 'matched');
  const scenarioEntries = adjudications.filter(a => a.scope === 'scenario');

  return {
    schemaVersion: ADJUDICATION_SCHEMA_VERSION,
    documentType: 'JSentinelFindingAdjudication',
    createdAt: new Date().toISOString(),
    scannerEngine: engine,
    evaluatorVersion: evaluationResult.metadata?.evaluatorVersion,
    datasetManifestVersion: evaluationResult.metadata?.datasetManifestVersion,
    summary: {
      totalEntries: adjudications.length,
      controlledEntries: adjudications.length - scenarioEntries.length,
      controlledUnmatchedCount: controlledUnmatched.length,
      controlledMatchedCount: controlledMatched.length,
      scenarioEntriesCount: scenarioEntries.length
    },
    adjudications
  };
};

/**
 * Consumes reviewed adjudication decisions and updates precision metrics without mutating
 * raw scanner results or manifest ground truth.
 * 
 * Strict research guarantees:
 * - Validates input document against actual evaluationResult findings.
 * - Rejects unknown, duplicate, cross-run, or mismatched finding IDs.
 * - Controlled precision counts ONLY completed eligible controlled unmatched dispositions in addition
 *   to the baseline automated matched count.
 * - Matched findings are NEVER counted twice.
 * - Scenario findings NEVER enter controlled precision calculations.
 * - Adjudicated precision remains null / N/A as long as any completed controlled unmatched finding is pending.
 * - Precision can never exceed 1.0 (100%).
 * 
 * @param {Object} evaluationResult - Complete evaluationResult from evaluateSuite.
 * @param {Object} adjudicationDoc - Adjudication document to apply.
 * @param {Object} [options]
 * @param {string} [options.duplicateEligibility='EXCLUDE_FROM_PRECISION'] - 'EXCLUDE_FROM_PRECISION' | 'COUNT_AS_FP'
 * @returns {Object} Updated metrics with adjudicated precision and semantic description summaries.
 */
export const applyAdjudicationToEvaluation = (
  evaluationResult,
  adjudicationDoc,
  options = {}
) => {
  const duplicatePolicy = options.duplicateEligibility || 'EXCLUDE_FROM_PRECISION';

  // 1. Validate adjudication document against actual evaluationResult
  const validation = validateAdjudicationDocument(adjudicationDoc, evaluationResult);
  if (!validation.valid) {
    throw new Error(`Adjudication document validation failed:\n${validation.errors.join('\n')}`);
  }

  const baselineFindingMetrics = evaluationResult.findingPrecisionMetrics || {};
  const baselineMetadataChecks = evaluationResult.metadataChecksSummary || {};
  const findingsMap = extractEvaluationFindingsMap(evaluationResult);

  // Group adjudications by key
  const docEntriesMap = new Map();
  for (const entry of adjudicationDoc.adjudications) {
    docEntriesMap.set(entry.findingKey, entry);
  }

  // Inspect ONLY completed controlled unmatched findings for precision
  let reviewedUnmatchedTP = 0;
  let reviewedUnmatchedFP = 0;
  let reviewedUnmatchedPending = 0;

  // Track semantic review for matched targets in completed controlled scans
  let semanticConfirmedCount = 0;
  let semanticInaccurateCount = 0;
  let semanticPendingCount = 0;
  let totalMatchedTargetsToReview = 0;

  for (const [key, findingContext] of findingsMap.entries()) {
    if (findingContext.scope !== 'controlled' || !findingContext.isCompletedScan) {
      // Scenarios and incomplete scans are excluded from controlled precision
      continue;
    }

    if (findingContext.kind === 'unmatched') {
      const docEntry = docEntriesMap.get(key);
      if (!docEntry || docEntry.disposition === 'PENDING') {
        reviewedUnmatchedPending++;
      } else if (docEntry.disposition === 'TRUE_POSITIVE') {
        reviewedUnmatchedTP++;
      } else if (docEntry.disposition === 'FALSE_POSITIVE') {
        reviewedUnmatchedFP++;
      }
    } else if (findingContext.kind === 'matched') {
      totalMatchedTargetsToReview++;
      const docEntry = docEntriesMap.get(key);
      if (docEntry && docEntry.semanticDescriptionOutcome === 'CONFIRMED_ACCURATE') {
        semanticConfirmedCount++;
      } else if (docEntry && docEntry.semanticDescriptionOutcome === 'INACCURATE') {
        semanticInaccurateCount++;
      } else {
        semanticPendingCount++;
      }
    }
  }

  // Controlled precision calculation
  const automatedMatched = baselineFindingMetrics.matchedFindings || 0;
  const automatedDuplicates = baselineFindingMetrics.duplicateFindings || 0;

  let adjudicatedPrecision = null;
  let adjudicatedPrecisionPercentage = 'N/A';
  let adjudicationStatus = 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION';

  const totalControlledUnmatched = baselineFindingMetrics.unmatchedFindings || 0;
  const hasPendingUnmatched = reviewedUnmatchedPending > 0;

  if (!hasPendingUnmatched && totalControlledUnmatched >= (reviewedUnmatchedTP + reviewedUnmatchedFP)) {
    // All completed controlled unmatched findings have been reviewed!
    const numerator = automatedMatched + reviewedUnmatchedTP;
    let denominator = automatedMatched + reviewedUnmatchedTP + reviewedUnmatchedFP;

    if (duplicatePolicy === 'COUNT_AS_FP') {
      denominator += automatedDuplicates;
    }

    const ratio = safeRatio(numerator, denominator);
    adjudicatedPrecision = ratio.value;
    adjudicatedPrecisionPercentage = ratio.percentage;
    adjudicationStatus = 'ADJUDICATION_COMPLETE';
  } else if (reviewedUnmatchedTP > 0 || reviewedUnmatchedFP > 0) {
    adjudicationStatus = 'PARTIALLY_ADJUDICATED';
  }

  const updatedFindingPrecisionMetrics = {
    ...baselineFindingMetrics,
    adjudicatedTruePositives: automatedMatched + reviewedUnmatchedTP,
    adjudicatedFalsePositives: reviewedUnmatchedFP,
    adjudicatedPendingUnmatched: reviewedUnmatchedPending,
    adjudicatedPrecision,
    adjudicatedPrecisionPercentage,
    adjudicationStatus,
    duplicatePrecisionPolicy: duplicatePolicy
  };

  // Semantic description summary
  let semanticMatchFraction = null;
  let semanticMatchPercentage = 'N/A';

  if (totalMatchedTargetsToReview > 0 && semanticPendingCount === 0) {
    const ratio = safeRatio(semanticConfirmedCount, totalMatchedTargetsToReview);
    semanticMatchFraction = ratio.value;
    semanticMatchPercentage = ratio.percentage;
  }

  const updatedMetadataChecksSummary = {
    ...baselineMetadataChecks,
    semanticReview: {
      totalTargetsToReview: totalMatchedTargetsToReview,
      confirmedAccurateCount: semanticConfirmedCount,
      inaccurateCount: semanticInaccurateCount,
      pendingCount: semanticPendingCount,
      semanticMatchFraction,
      semanticMatchPercentage,
      status: semanticPendingCount === 0 && totalMatchedTargetsToReview > 0 ? 'REVIEW_COMPLETE' : 'PARTIALLY_REVIEWED'
    }
  };

  return {
    ...evaluationResult,
    findingPrecisionMetrics: updatedFindingPrecisionMetrics,
    metadataChecksSummary: updatedMetadataChecksSummary,
    adjudicationApplied: {
      appliedAt: new Date().toISOString(),
      schemaVersion: ADJUDICATION_SCHEMA_VERSION,
      duplicatePolicy,
      reviewedUnmatchedTP,
      reviewedUnmatchedFP,
      reviewedUnmatchedPending
    }
  };
};

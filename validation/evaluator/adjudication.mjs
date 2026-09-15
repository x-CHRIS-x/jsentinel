/**
 * JSentinel Finding Adjudication Engine and Schema (Version 1.0.0)
 * 
 * Manages human ground-truth adjudication of unmatched alerts and semantic description review:
 * - Versioned schema 1.0.0.
 * - Explicit finding scope ('controlled' | 'scenario') and kind ('unmatched' | 'matched' | 'duplicate').
 * - Stable canonical finding keys incorporating engine, sampleId, ruleId, location, kind, and occurrence index.
 * - Enforces occurrence multiplicity: identical alerts in the same sample preserve distinct occurrence IDs.
 * - Binds required run ID, result digest, and scanner engine; rejects cross-run documents and tampered canonical fields.
 * - Rejects unknown, duplicate, cross-run, or mismatched finding identifiers.
 * - Computes controlled finding precision without double-counting matched targets or contaminating
 *   controlled metrics with scenario observations.
 * - Requires genuine human reviewer, rationale, and reviewDate for completed human dispositions.
 * - Requires genuine human reviewer (rejecting AUTOMATED_EVALUATOR) for completed semantic review.
 * - Validates duplicate policy enum ('EXCLUDE_FROM_PRECISION' | 'COUNT_AS_FP').
 * - Keeps precision as null / N/A as long as any completed controlled unmatched finding is pending review.
 */

import crypto from 'node:crypto';
import { safeRatio } from './metrics.mjs';

export const ADJUDICATION_SCHEMA_VERSION = '1.0.0';

/**
 * Computes a deterministic SHA-256 digest of an evaluation result's findings and structure.
 * 
 * @param {Object} evaluationResult 
 * @returns {string} 64-character hex digest.
 */
export const computeEvaluationDigest = (evaluationResult) => {
  if (!evaluationResult || typeof evaluationResult !== 'object') {
    throw new Error('evaluationResult must be a non-null object.');
  }
  const meta = evaluationResult.metadata || {};
  const runId = meta.runId || 'unbound';
  const engine = meta.scannerEngine || 'unknown';
  const manifestVer = meta.datasetManifestVersion || 'unknown';
  const evalVer = meta.evaluatorVersion || 'unknown';
  const matchingPolicy = meta.matchingPolicy
    ? `${meta.matchingPolicy.locationTolerance}:${meta.matchingPolicy.matchColumn}:${(meta.matchingPolicy.advisoryRulePrefixes || []).join(',')}`
    : 'default';

  const fileSummaries = (evaluationResult.fileResults || []).map(f => {
    const serializeFinding = (af) => {
      if (!af) return 'none';
      const rule = af.ruleId || 'unknown';
      const line = af.location?.line ?? 'none';
      const col = af.location?.column ?? 'none';
      const sev = af.severity ?? 'none';
      const desc = af.description ?? '';
      const cat = af.category ?? 'none';
      return `${rule}:${line}:${col}:${sev}:${desc}:${cat}`;
    };

    const matchedKeys = (f.vulnerabilities?.matched || []).map(m => serializeFinding(m.actualFinding)).join('|');
    const unmatchedKeys = (f.vulnerabilities?.unmatched || []).map(u => serializeFinding(u.actualFinding)).join('|');
    const duplicateKeys = (f.vulnerabilities?.duplicates || []).map(d => serializeFinding(d.actualFinding)).join('|');
    return `${f.sampleId}:${f.fileName}:${f.scanStatus}:${f.hasScanError}:${matchedKeys}:${unmatchedKeys}:${duplicateKeys}`;
  }).join(';');

  const canonicalPayload = `${runId}:${engine}:${manifestVer}:${evalVer}:${matchingPolicy}:${fileSummaries}`;
  return crypto.createHash('sha256').update(canonicalPayload).digest('hex');
};

/**
 * Builds a canonical finding key for unambiguous identification.
 * Preserves occurrence index to ensure identical repeated alerts at the same coordinates
 * do not collapse and distort the evaluation denominator.
 * 
 * @param {Object} params
 * @param {string} [params.engine='any']
 * @param {string} params.sampleId
 * @param {string} params.ruleId
 * @param {number|null} [params.line=null]
 * @param {number|null} [params.column=null]
 * @param {string} [params.kind='unmatched'] - 'unmatched' | 'matched' | 'duplicate'
 * @param {number} [params.occurrenceIndex=0]
 * @returns {string}
 */
export const makeFindingKey = ({
  engine = 'any',
  sampleId,
  ruleId,
  line = null,
  column = null,
  kind = 'unmatched',
  occurrenceIndex = 0
}) => {
  const linePart = line ?? 'unknown';
  const colPart = column ?? 'any';
  return `${engine}:${sampleId}:${ruleId}:${linePart}:${colPart}:${kind}:${occurrenceIndex}`;
};

/**
 * Extracts a map of all valid finding entries from an evaluation result.
 * Preserves actual occurrence multiplicity by tracking occurrence indices per coordinate tuple.
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

    // Track occurrence counts per coordinate tuple within this sample
    const occurrenceCounters = new Map();
    const getOccurrenceIndex = (ruleId, line, column, kind) => {
      const coordKey = `${ruleId}:${line ?? 'unknown'}:${column ?? 'any'}:${kind}`;
      const current = occurrenceCounters.get(coordKey) || 0;
      occurrenceCounters.set(coordKey, current + 1);
      return current;
    };

    // 1. Matched findings
    for (const m of fileRes.vulnerabilities?.matched || []) {
      const f = m.actualFinding;
      const line = f.location?.line ?? null;
      const col = f.location?.column ?? null;
      const occIndex = getOccurrenceIndex(f.ruleId, line, col, 'matched');
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line,
        column: col,
        kind: 'matched',
        occurrenceIndex: occIndex
      });
      findingsMap.set(key, {
        findingKey: key,
        occurrenceIndex: occIndex,
        scope,
        kind: 'matched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location ? { line: f.location.line, column: f.location.column } : null,
        isCompletedScan,
        expectedRule: m.expected?.ruleId,
        actualFinding: f
      });
    }

    // 2. Unmatched findings
    for (const u of fileRes.vulnerabilities?.unmatched || []) {
      const f = u.actualFinding;
      const line = f.location?.line ?? null;
      const col = f.location?.column ?? null;
      const occIndex = getOccurrenceIndex(f.ruleId, line, col, 'unmatched');
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line,
        column: col,
        kind: 'unmatched',
        occurrenceIndex: occIndex
      });
      findingsMap.set(key, {
        findingKey: key,
        occurrenceIndex: occIndex,
        scope,
        kind: 'unmatched',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location ? { line: f.location.line, column: f.location.column } : null,
        isCompletedScan,
        actualFinding: f
      });
    }

    // 3. Duplicate findings
    for (const d of fileRes.vulnerabilities?.duplicates || []) {
      const f = d.actualFinding;
      const line = f.location?.line ?? null;
      const col = f.location?.column ?? null;
      const occIndex = getOccurrenceIndex(f.ruleId, line, col, 'duplicate');
      const key = makeFindingKey({
        engine,
        sampleId: fileRes.sampleId,
        ruleId: f.ruleId,
        line,
        column: col,
        kind: 'duplicate',
        occurrenceIndex: occIndex
      });
      findingsMap.set(key, {
        findingKey: key,
        occurrenceIndex: occIndex,
        scope,
        kind: 'duplicate',
        sampleId: fileRes.sampleId,
        fileName: fileRes.fileName,
        ruleId: f.ruleId,
        location: f.location ? { line: f.location.line, column: f.location.column } : null,
        isCompletedScan,
        actualFinding: f
      });
    }
  }

  return findingsMap;
};

/**
 * Validates an adjudication document against schema and optionally against an actual evaluation result.
 * Enforces:
 * - Presence of required root provenance fields: scannerEngine, evaluationRunId, evaluationResultDigest.
 * - Exact cross-run digest and engine agreement when validated against an evaluationResult.
 * - Integrity of canonical finding fields: rejects tampering with scope, kind, sampleId, fileName, ruleId, or location.
 * - Real human reviewer, rationale, and reviewDate for completed human dispositions (rejecting AUTOMATED_EVALUATOR).
 * - Real human reviewer for completed semantic descriptions.
 * - Validation of duplicateEligibility enum ('EXCLUDE_FROM_PRECISION' | 'COUNT_AS_FP').
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

  if (!doc.scannerEngine || typeof doc.scannerEngine !== 'string') {
    errors.push('Adjudication document must specify a non-empty string "scannerEngine".');
  }

  if (!doc.evaluationRunId || typeof doc.evaluationRunId !== 'string') {
    errors.push('Adjudication document must specify a non-empty string "evaluationRunId".');
  }

  if (!doc.evaluationResultDigest || typeof doc.evaluationResultDigest !== 'string') {
    errors.push('Adjudication document must specify a non-empty string "evaluationResultDigest".');
  }

  if (!Array.isArray(doc.adjudications)) {
    errors.push('Adjudication document must contain an "adjudications" array.');
    return { valid: false, errors };
  }

  let knownFindingsMap = null;
  if (evaluationResult) {
    if (!evaluationResult.metadata?.runId || typeof evaluationResult.metadata.runId !== 'string') {
      errors.push(
        'Evaluation result missing required non-empty "metadata.runId". ' +
        'Legacy unbound evaluation results are rejected; runId is required.'
      );
    } else if (doc.evaluationRunId && doc.evaluationRunId !== evaluationResult.metadata.runId) {
      errors.push(
        `Evaluation run ID mismatch: document specifies run ID "${doc.evaluationRunId}" ` +
        `but evaluation result has run ID "${evaluationResult.metadata.runId}". Cross-run adjudication documents are rejected.`
      );
    }

    const expectedEngine = evaluationResult.metadata?.scannerEngine;
    if (expectedEngine && doc.scannerEngine !== expectedEngine) {
      errors.push(`Scanner engine mismatch: document specifies "${doc.scannerEngine}" but evaluation result is for "${expectedEngine}".`);
    }

    const expectedDigest = computeEvaluationDigest(evaluationResult);
    if (doc.evaluationResultDigest && doc.evaluationResultDigest !== expectedDigest) {
      errors.push(
        `Evaluation result digest mismatch: document specifies digest "${doc.evaluationResultDigest}" ` +
        `but evaluation result digest is "${expectedDigest}". Cross-run adjudication documents are rejected.`
      );
    }

    knownFindingsMap = extractEvaluationFindingsMap(evaluationResult);
  }

  const seenKeys = new Set();
  const validDispositions = ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'PENDING'];
  const validSemanticOutcomes = ['CONFIRMED_ACCURATE', 'INACCURATE', 'PENDING'];
  const validScopes = ['controlled', 'scenario'];
  const validKinds = ['unmatched', 'matched', 'duplicate'];
  const validDuplicatePolicies = ['EXCLUDE_FROM_PRECISION', 'COUNT_AS_FP'];

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

    let knownFinding = null;
    if (knownFindingsMap) {
      if (!knownFindingsMap.has(key)) {
        errors.push(`Unknown adjudication identifier: "${key}" does not exist in the evaluated findings.`);
      } else {
        knownFinding = knownFindingsMap.get(key);
      }
    }

    // Tampered canonical fields check against ground-truth finding
    if (knownFinding) {
      if (entry.scope && entry.scope !== knownFinding.scope) {
        errors.push(`Entry [${i}] (${key}): tampered scope (expected "${knownFinding.scope}", got "${entry.scope}").`);
      }
      if (entry.kind && entry.kind !== knownFinding.kind) {
        errors.push(`Entry [${i}] (${key}): tampered kind (expected "${knownFinding.kind}", got "${entry.kind}").`);
      }
      if (entry.sampleId && entry.sampleId !== knownFinding.sampleId) {
        errors.push(`Entry [${i}] (${key}): tampered sampleId (expected "${knownFinding.sampleId}", got "${entry.sampleId}").`);
      }
      if (entry.fileName && entry.fileName !== knownFinding.fileName) {
        errors.push(`Entry [${i}] (${key}): tampered fileName (expected "${knownFinding.fileName}", got "${entry.fileName}").`);
      }
      if (entry.ruleId && entry.ruleId !== knownFinding.ruleId) {
        errors.push(`Entry [${i}] (${key}): tampered ruleId (expected "${knownFinding.ruleId}", got "${entry.ruleId}").`);
      }
      if (knownFinding.location && entry.location) {
        if (entry.location.line !== knownFinding.location.line || entry.location.column !== knownFinding.location.column) {
          errors.push(
            `Entry [${i}] (${key}): tampered location coordinates ` +
            `(expected line ${knownFinding.location.line} col ${knownFinding.location.column}, ` +
            `got line ${entry.location.line} col ${entry.location.column}).`
          );
        }
      }
    }

    if (entry.scope && !validScopes.includes(entry.scope)) {
      errors.push(`Entry [${i}] (${key}): invalid scope "${entry.scope}". Allowed: ${validScopes.join(', ')}.`);
    }

    if (entry.kind && !validKinds.includes(entry.kind)) {
      errors.push(`Entry [${i}] (${key}): invalid kind "${entry.kind}". Allowed: ${validKinds.join(', ')}.`);
    }

    if (!validDispositions.includes(entry.disposition)) {
      errors.push(`Entry [${i}] (${key}): invalid disposition "${entry.disposition}". Allowed: ${validDispositions.join(', ')}.`);
    }

    if (entry.duplicateEligibility && !validDuplicatePolicies.includes(entry.duplicateEligibility)) {
      errors.push(`Entry [${i}] (${key}): invalid duplicateEligibility "${entry.duplicateEligibility}". Allowed: ${validDuplicatePolicies.join(', ')}.`);
    }

    // Require genuine human reviewer, rationale, and reviewDate for completed human adjudication
    if (entry.kind === 'unmatched' && (entry.disposition === 'TRUE_POSITIVE' || entry.disposition === 'FALSE_POSITIVE')) {
      if (!entry.reviewer || typeof entry.reviewer !== 'string' || entry.reviewer.trim() === '' || entry.reviewer === 'AUTOMATED_EVALUATOR') {
        errors.push(`Entry [${i}] (${key}): completed human disposition requires a valid human reviewer name (cannot be empty or "AUTOMATED_EVALUATOR").`);
      }
      if (!entry.rationale || typeof entry.rationale !== 'string' || entry.rationale.trim() === '') {
        errors.push(`Entry [${i}] (${key}): completed disposition "${entry.disposition}" requires a non-empty "rationale" field.`);
      }
      if (!entry.reviewDate || typeof entry.reviewDate !== 'string' || Number.isNaN(Date.parse(entry.reviewDate))) {
        errors.push(`Entry [${i}] (${key}): completed disposition "${entry.disposition}" requires a valid ISO "reviewDate".`);
      }
    }

    // Semantic review completed outcome check
    if (entry.semanticDescriptionOutcome && !validSemanticOutcomes.includes(entry.semanticDescriptionOutcome)) {
      errors.push(`Entry [${i}] (${key}): invalid semanticDescriptionOutcome "${entry.semanticDescriptionOutcome}". Allowed: ${validSemanticOutcomes.join(', ')}.`);
    }

    if (entry.semanticDescriptionOutcome === 'CONFIRMED_ACCURATE' || entry.semanticDescriptionOutcome === 'INACCURATE') {
      const semReviewer = entry.semanticReviewer || entry.reviewer;
      const semRationale = entry.semanticRationale || entry.rationale;
      const semDate = entry.semanticReviewDate || entry.reviewDate;

      if (!semReviewer || typeof semReviewer !== 'string' || semReviewer.trim() === '' || semReviewer === 'AUTOMATED_EVALUATOR') {
        errors.push(`Entry [${i}] (${key}): completed semantic review outcome "${entry.semanticDescriptionOutcome}" requires a valid human reviewer (cannot be empty or "AUTOMATED_EVALUATOR").`);
      }
      if (!semRationale || typeof semRationale !== 'string' || semRationale.trim() === '') {
        errors.push(`Entry [${i}] (${key}): completed semantic review requires a non-empty rationale.`);
      }
      if (!semDate || typeof semDate !== 'string' || Number.isNaN(Date.parse(semDate))) {
        errors.push(`Entry [${i}] (${key}): completed semantic review requires a valid ISO reviewDate.`);
      }
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
  if (!evaluationResult || typeof evaluationResult !== 'object') {
    throw new Error('evaluationResult must be a non-null object.');
  }
  const runId = evaluationResult.metadata?.runId;
  if (!runId || typeof runId !== 'string') {
    throw new Error(
      'Cannot generate adjudication template: evaluationResult lacks required non-empty "metadata.runId". ' +
      'Legacy unbound evaluation results must be rerun or explicitly assigned a runId.'
    );
  }
  const reviewerName = options.reviewerName || null;
  const engine = evaluationResult.metadata?.scannerEngine || 'web';
  const resultDigest = computeEvaluationDigest(evaluationResult);

  const findingsMap = extractEvaluationFindingsMap(evaluationResult);
  const adjudications = [];

  for (const finding of findingsMap.values()) {
    if (finding.kind === 'unmatched') {
      adjudications.push({
        findingKey: finding.findingKey,
        occurrenceIndex: finding.occurrenceIndex,
        scope: finding.scope,
        kind: 'unmatched',
        sampleId: finding.sampleId,
        fileName: finding.fileName,
        ruleId: finding.ruleId,
        location: finding.location ? { line: finding.location.line, column: finding.location.column } : null,
        sourceLine: finding.actualFinding?.sourceLine || '',
        description: finding.actualFinding?.description || '',
        scanStatus: finding.isCompletedScan ? 'completed' : 'incomplete',
        isCompletedScan: finding.isCompletedScan,
        adjudicationOrigin: 'HUMAN_ADJUDICATION',
        disposition: 'PENDING',
        rationale: '',
        reviewer: reviewerName,
        reviewDate: null,
        semanticDescriptionOutcome: 'PENDING',
        semanticReviewer: null,
        semanticRationale: '',
        semanticReviewDate: null,
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    } else if (finding.kind === 'matched') {
      adjudications.push({
        findingKey: finding.findingKey,
        occurrenceIndex: finding.occurrenceIndex,
        scope: finding.scope,
        kind: 'matched',
        sampleId: finding.sampleId,
        fileName: finding.fileName,
        ruleId: finding.ruleId,
        location: finding.location ? { line: finding.location.line, column: finding.location.column } : null,
        sourceLine: finding.actualFinding?.sourceLine || '',
        description: finding.actualFinding?.description || '',
        scanStatus: finding.isCompletedScan ? 'completed' : 'incomplete',
        isCompletedScan: finding.isCompletedScan,
        adjudicationOrigin: 'AUTOMATED_TARGET_MATCH',
        disposition: 'TRUE_POSITIVE',
        rationale: 'Automated 1-to-1 match against ground-truth expected vulnerability target.',
        reviewer: 'AUTOMATED_EVALUATOR',
        reviewDate: new Date().toISOString(),
        semanticDescriptionOutcome: 'PENDING',
        semanticReviewer: null,
        semanticRationale: '',
        semanticReviewDate: null,
        duplicateEligibility: 'EXCLUDE_FROM_PRECISION',
        scopeAmbiguityNote: null
      });
    } else if (finding.kind === 'duplicate') {
      adjudications.push({
        findingKey: finding.findingKey,
        occurrenceIndex: finding.occurrenceIndex,
        scope: finding.scope,
        kind: 'duplicate',
        sampleId: finding.sampleId,
        fileName: finding.fileName,
        ruleId: finding.ruleId,
        location: finding.location ? { line: finding.location.line, column: finding.location.column } : null,
        sourceLine: finding.actualFinding?.sourceLine || '',
        description: finding.actualFinding?.description || '',
        scanStatus: finding.isCompletedScan ? 'completed' : 'incomplete',
        isCompletedScan: finding.isCompletedScan,
        adjudicationOrigin: 'AUTOMATED_DUPLICATE_ISOLATION',
        disposition: 'FALSE_POSITIVE',
        rationale: 'Duplicate finding at same coordinates as matched target.',
        reviewer: 'AUTOMATED_EVALUATOR',
        reviewDate: new Date().toISOString(),
        semanticDescriptionOutcome: 'PENDING',
        semanticReviewer: null,
        semanticRationale: '',
        semanticReviewDate: null,
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
    evaluationRunId: runId,
    evaluationResultDigest: resultDigest,
    evaluatorVersion: evaluationResult.metadata?.evaluatorVersion || '1.0.0',
    datasetManifestVersion: evaluationResult.metadata?.datasetManifestVersion || '1.0.0',
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
 * - Validates input document against actual evaluationResult findings and cryptographic digest.
 * - Rejects unknown, duplicate, cross-run, or mismatched finding IDs.
 * - Rejects tampered canonical finding fields.
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
  if (!evaluationResult || typeof evaluationResult !== 'object') {
    throw new Error('evaluationResult must be a non-null object.');
  }
  if (!evaluationResult.metadata?.runId || typeof evaluationResult.metadata.runId !== 'string') {
    throw new Error(
      'Cannot apply adjudication: evaluationResult lacks required non-empty "metadata.runId". ' +
      'Legacy unbound evaluation results are rejected; runId is required.'
    );
  }

  const duplicatePolicy = options.duplicateEligibility || 'EXCLUDE_FROM_PRECISION';
  const validDuplicatePolicies = ['EXCLUDE_FROM_PRECISION', 'COUNT_AS_FP'];

  if (!validDuplicatePolicies.includes(duplicatePolicy)) {
    throw new Error(`Invalid duplicateEligibility policy "${duplicatePolicy}". Allowed: ${validDuplicatePolicies.join(', ')}.`);
  }

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
    // All completed controlled unmatched findings have been reviewed
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

/**
 * JSentinel Research Evaluator Result Schema (Version 1.0.0)
 * 
 * Defines the structured, checkable output format for Phase 05 benchmark evaluation.
 * Separates file-level confusion matrix, one-to-one expected rule detection,
 * finding-level precision with pending manual adjudication, metadata checks,
 * advisory-only tracking, scan completion counts, and scenario observations.
 */

export const SCHEMA_VERSION = '1.0.0';

export const RESULT_SCHEMA_DEFINITION = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  title: 'JSentinelEvaluationResult',
  version: SCHEMA_VERSION,
  type: 'object',
  required: [
    'schemaVersion',
    'metadata',
    'scanCompletion',
    'fileConfusionMatrix',
    'expectedRuleMetrics',
    'findingPrecisionMetrics',
    'advisoryMetrics',
    'metadataChecksSummary',
    'scenarioObservations',
    'fileResults'
  ],
  properties: {
    schemaVersion: { type: 'string', const: SCHEMA_VERSION },
    metadata: {
      type: 'object',
      required: ['evaluatorVersion', 'timestamp', 'matchingPolicy'],
      properties: {
        evaluatorVersion: { type: 'string' },
        timestamp: { type: 'string' },
        scannerEngine: { type: 'string' },
        datasetManifestVersion: { type: 'string' },
        matchingPolicy: {
          type: 'object',
          required: [
            'locationTolerance',
            'matchColumn',
            'advisoryRulePrefixes',
            'unsupportedRulePolicy',
            'findingAdjudicationPolicy'
          ],
          properties: {
            locationTolerance: { type: 'integer', minimum: 0 },
            matchColumn: { type: 'boolean' },
            advisoryRulePrefixes: { type: 'array', items: { type: 'string' } },
            unsupportedRulePolicy: { type: 'string' },
            findingAdjudicationPolicy: { type: 'string' }
          }
        }
      }
    },
    scanCompletion: {
      type: 'object',
      required: ['attempted', 'completed', 'partial', 'failed', 'excluded'],
      properties: {
        attempted: { type: 'integer', minimum: 0 },
        completed: { type: 'integer', minimum: 0 },
        partial: { type: 'integer', minimum: 0 },
        failed: { type: 'integer', minimum: 0 },
        excluded: { type: 'integer', minimum: 0 }
      }
    },
    fileConfusionMatrix: {
      type: 'object',
      required: [
        'TP', 'TN', 'FP', 'FN', 'N',
        'accuracy', 'precision', 'recall',
        'specificity', 'falsePositiveRate', 'falseNegativeRate',
        'percentages'
      ],
      properties: {
        TP: { type: 'integer', minimum: 0 },
        TN: { type: 'integer', minimum: 0 },
        FP: { type: 'integer', minimum: 0 },
        FN: { type: 'integer', minimum: 0 },
        N: { type: 'integer', minimum: 0 },
        accuracy: { type: ['number', 'null'] },
        precision: { type: ['number', 'null'] },
        recall: { type: ['number', 'null'] },
        specificity: { type: ['number', 'null'] },
        falsePositiveRate: { type: ['number', 'null'] },
        falseNegativeRate: { type: ['number', 'null'] },
        percentages: {
          type: 'object',
          required: [
            'accuracy', 'precision', 'recall',
            'specificity', 'falsePositiveRate', 'falseNegativeRate'
          ],
          properties: {
            accuracy: { type: 'string' },
            precision: { type: 'string' },
            recall: { type: 'string' },
            specificity: { type: 'string' },
            falsePositiveRate: { type: 'string' },
            falseNegativeRate: { type: 'string' }
          }
        }
      }
    },
    expectedRuleMetrics: {
      type: 'object',
      required: [
        'totalExpected',
        'matchedExpected',
        'missedExpected',
        'unsupportedExpected',
        'expectedRuleRecall',
        'expectedRuleRecallPercentage'
      ],
      properties: {
        totalExpected: { type: 'integer', minimum: 0 },
        matchedExpected: { type: 'integer', minimum: 0 },
        missedExpected: { type: 'integer', minimum: 0 },
        unsupportedExpected: { type: 'integer', minimum: 0 },
        expectedRuleRecall: { type: ['number', 'null'] },
        expectedRuleRecallPercentage: { type: 'string' }
      }
    },
    findingPrecisionMetrics: {
      type: 'object',
      required: [
        'totalActualFindings',
        'matchedFindings',
        'duplicateFindings',
        'unmatchedFindings',
        'adjudicationStatus',
        'provisionalPrecision',
        'provisionalPrecisionPercentage'
      ],
      properties: {
        totalActualFindings: { type: 'integer', minimum: 0 },
        matchedFindings: { type: 'integer', minimum: 0 },
        duplicateFindings: { type: 'integer', minimum: 0 },
        unmatchedFindings: { type: 'integer', minimum: 0 },
        adjudicationStatus: { type: 'string' },
        provisionalPrecision: { type: ['number', 'null'] },
        provisionalPrecisionPercentage: { type: 'string' }
      }
    },
    advisoryMetrics: {
      type: 'object',
      required: [
        'totalExpectedAdvisories',
        'detectedAdvisories',
        'matchedAdvisories',
        'policyNote'
      ],
      properties: {
        totalExpectedAdvisories: { type: 'integer', minimum: 0 },
        detectedAdvisories: { type: 'integer', minimum: 0 },
        matchedAdvisories: { type: 'integer', minimum: 0 },
        policyNote: { type: 'string' }
      }
    },
    metadataChecksSummary: {
      type: 'object',
      required: [
        'totalChecked',
        'categoryMatches',
        'categoryMismatches',
        'severityMatches',
        'severityMismatches',
        'locationMatches',
        'locationMismatches',
        'categoryAccuracyPercentage',
        'severityAccuracyPercentage',
        'locationAccuracyPercentage',
        'semanticDescriptionStatus'
      ]
    },
    scenarioObservations: {
      type: 'array',
      items: { type: 'object' }
    },
    fileResults: {
      type: 'array',
      items: { type: 'object' }
    }
  }
};

/**
 * Validates an evaluation result object against the Phase 05 result schema.
 * 
 * @param {Object} result - Evaluator output object.
 * @returns {{ valid: boolean, errors: string[] }}
 */
export const validateEvaluationResult = (result) => {
  const errors = [];
  if (!result || typeof result !== 'object') {
    return { valid: false, errors: ['Result must be a non-null object.'] };
  }

  if (result.schemaVersion !== SCHEMA_VERSION) {
    errors.push(`Invalid schemaVersion: expected "${SCHEMA_VERSION}", received "${result.schemaVersion}".`);
  }

  const requiredSections = [
    'metadata',
    'scanCompletion',
    'fileConfusionMatrix',
    'expectedRuleMetrics',
    'findingPrecisionMetrics',
    'advisoryMetrics',
    'metadataChecksSummary',
    'scenarioObservations',
    'fileResults'
  ];

  for (const section of requiredSections) {
    if (!result[section] || typeof result[section] !== 'object') {
      errors.push(`Missing or invalid required section: "${section}".`);
    }
  }

  if (result.fileConfusionMatrix) {
    const cm = result.fileConfusionMatrix;
    for (const key of ['TP', 'TN', 'FP', 'FN', 'N']) {
      if (typeof cm[key] !== 'number' || cm[key] < 0) {
        errors.push(`fileConfusionMatrix.${key} must be a non-negative number.`);
      }
    }
    if (cm.N !== (cm.TP + cm.TN + cm.FP + cm.FN)) {
      errors.push(`fileConfusionMatrix.N (${cm.N}) must equal TP + TN + FP + FN (${cm.TP + cm.TN + cm.FP + cm.FN}).`);
    }
  }

  if (result.scanCompletion) {
    const sc = result.scanCompletion;
    for (const key of ['attempted', 'completed', 'partial', 'failed', 'excluded']) {
      if (typeof sc[key] !== 'number' || sc[key] < 0) {
        errors.push(`scanCompletion.${key} must be a non-negative number.`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
};

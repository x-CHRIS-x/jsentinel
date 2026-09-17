/**
 * Disclosed Synthetic Test Fixtures for JSentinel Evaluator
 * 
 * Provides isolated, deterministic test cases covering all edge cases specified in Phase 05:
 * 1. correct: target vulnerability matched by rule and location.
 * 2. missing: target vulnerability omitted by scanner (FN).
 * 3. unrelated: scanner alert with different rule or distant location cannot satisfy target.
 * 4. duplicate: multiple findings for same target; duplicates cannot inflate matches.
 * 5. multiple-only-one-match: multiple findings where only one matches target expectation.
 * 6. one-actual-cannot-match-two-expectations: one finding cannot satisfy two targets.
 * 7. parse-failure: syntax error resulting in failed scan; empty findings not inferred as clean.
 * 8. partial: rule error during scan; partial scan excluded from completed matrix N.
 * 9. failed: runtime error caught by adapter; failed scan excluded from completed matrix N.
 * 10. clean-negative: clean file with 0 findings (TN).
 * 11. clean-unrelated-falsepositive: clean file with unexpected alert (FP).
 * 12. advisory-only: file with only A06 advisory; excluded from vulnerability metrics.
 * 13. zero-denominator: empty or zero-positive datasets producing N/A instead of crash.
 * 14. metadata-error-separate-from-detection: matching detection with severity/category error.
 * 15. scenario-exclusion: scenario workloads segregated from controlled V/C matrix.
 * 16. unsupported-null-rule: expectation with null ruleId; explicit unresolved policy.
 * 17. same-line-distinct-columns: distinct findings on same line with different columns are not duplicates.
 * 18. identical-duplicate-actuals: identical duplicate findings cannot satisfy multiple expectations.
 * 19. missing-location: missing or undefined coordinates are rejected and never match.
 * 20. invalid-label: unrecognized label excluded explicitly from controlled matrix.
 */

// 1. Correct Match Fixture
export const FIXTURE_CORRECT = {
  manifest: {
    sampleId: 'V-SYNTH-001',
    fileName: 'correct-eval.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 10, column: 4 },
        weaknessDescription: 'Dynamic eval execution of user input.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'correct-eval.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 10, column: 4 },
        description: 'Dangerous use of eval()'
      }
    ]
  }
};

// 2. Missing Vulnerability Fixture (FN)
export const FIXTURE_MISSING = {
  manifest: {
    sampleId: 'V-SYNTH-002',
    fileName: 'missing-timer.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-002',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 15, column: 2 },
        weaknessDescription: 'Dynamic string setTimeout injection.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'missing-timer.js',
    status: 'completed',
    hasError: false,
    findings: []
  }
};

// 3. Unrelated Alert Fixture
export const FIXTURE_UNRELATED = {
  manifest: {
    sampleId: 'V-SYNTH-003',
    fileName: 'unrelated-alert.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 12, column: 2 },
        weaknessDescription: 'Eval call on line 12.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'unrelated-alert.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A02-003',
        ruleId: 'OWASP-A02-003',
        category: 'A02:2021-Cryptographic Failures',
        severity: 'MEDIUM',
        location: { line: 55, column: 8 },
        description: 'Use of Math.random() for security sensitive context.'
      }
    ]
  }
};

// 4. Duplicate Findings Fixture
export const FIXTURE_DUPLICATE = {
  manifest: {
    sampleId: 'V-SYNTH-004',
    fileName: 'duplicate-findings.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-006',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 20, column: 5 },
        weaknessDescription: 'Direct innerHTML assignment.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'duplicate-findings.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-006',
        ruleId: 'OWASP-A03-006',
        category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 20, column: 5 },
        description: 'innerHTML assignment hit 1'
      },
      {
        id: 'OWASP-A03-006',
        ruleId: 'OWASP-A03-006',
        category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 20, column: 5 },
        description: 'innerHTML assignment hit 2 (duplicate)'
      }
    ]
  }
};

// 5. Multiple Findings where Only One Matches Target
export const FIXTURE_MULTIPLE_ONLY_ONE_MATCH = {
  manifest: {
    sampleId: 'V-SYNTH-005',
    fileName: 'multiple-one-match.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A07-001',
        owasp2021Category: 'A07:2021-Identification and Authentication Failures',
        severity: 'HIGH',
        location: { line: 25, column: 4 },
        weaknessDescription: 'Sensitive auth token stored in localStorage.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'multiple-one-match.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A05-001',
        ruleId: 'OWASP-A05-001',
        category: 'A05:2021-Security Misconfiguration',
        severity: 'MEDIUM',
        location: { line: 10, column: 2 },
        description: 'console.log secret'
      },
      {
        id: 'OWASP-A07-001',
        ruleId: 'OWASP-A07-001',
        category: 'A07:2021-Identification and Authentication Failures',
        severity: 'HIGH',
        location: { line: 25, column: 4 },
        description: 'localStorage auth token store'
      },
      {
        id: 'OWASP-A08-002',
        ruleId: 'OWASP-A08-002',
        category: 'A08:2021-Software and Data Integrity Failures',
        severity: 'HIGH',
        location: { line: 40, column: 6 },
        description: 'Prototype pollution assignment'
      }
    ]
  }
};

// 6. One Actual Cannot Match Two Expectations Fixture
export const FIXTURE_ONE_CANNOT_MATCH_TWO = {
  manifest: {
    sampleId: 'V-SYNTH-006',
    fileName: 'two-targets-one-finding.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 30, column: 4 },
        weaknessDescription: 'Target 1: eval vulnerability.'
      },
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 30, column: 4 },
        weaknessDescription: 'Target 2: second distinct vulnerability.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'two-targets-one-finding.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 30, column: 4 },
        description: 'Single actual eval finding.'
      }
    ]
  }
};

// 7. Parse Failure Fixture
export const FIXTURE_PARSE_FAILURE = {
  manifest: {
    sampleId: 'V-SYNTH-007',
    fileName: 'broken-syntax.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 5, column: 2 }
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'broken-syntax.js',
    status: 'failed',
    hasError: true,
    error: 'SyntaxError: Unexpected token, expected "}" (5:12)',
    parseError: 'SyntaxError: Unexpected token, expected "}" (5:12)',
    findings: []
  }
};

// 8. Partial Scan Fixture
export const FIXTURE_PARTIAL = {
  manifest: {
    sampleId: 'V-SYNTH-008',
    fileName: 'partial-scan.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 8, column: 2 }
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'partial-scan.js',
    status: 'partial',
    hasError: true,
    error: null,
    ruleErrors: [{ ruleName: 'dynamic-timer', error: 'Visitor traversal aborted' }],
    findings: []
  }
};

// 9. Runtime Failed Scan Fixture
export const FIXTURE_FAILED = {
  manifest: {
    sampleId: 'V-SYNTH-009',
    fileName: 'crashed-scanner.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A01-001',
        owasp2021Category: 'A01:2021-Broken Access Control',
        severity: 'HIGH',
        location: { line: 14, column: 2 }
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'crashed-scanner.js',
    status: 'failed',
    hasError: true,
    error: 'Uncaught TypeError: Cannot read properties of undefined',
    findings: []
  }
};

// 10. Clean Negative Fixture (TN)
export const FIXTURE_CLEAN_NEGATIVE = {
  manifest: {
    sampleId: 'C-SYNTH-010',
    fileName: 'clean-negative.js',
    label: 'clean',
    expectedScannerFindings: []
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'clean-negative.js',
    status: 'completed',
    hasError: false,
    findings: []
  }
};

// 11. Clean Unrelated False Positive Fixture (FP)
export const FIXTURE_CLEAN_FALSE_POSITIVE = {
  manifest: {
    sampleId: 'C-SYNTH-011',
    fileName: 'clean-fp.js',
    label: 'clean',
    expectedScannerFindings: []
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'clean-fp.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A02-004',
        ruleId: 'OWASP-A02-004',
        category: 'A02:2021-Cryptographic Failures',
        severity: 'HIGH',
        location: { line: 18, column: 4 },
        description: 'Plaintext http URL in telemetry string.'
      }
    ]
  }
};

// 12. Advisory-Only Fixture (A06)
export const FIXTURE_ADVISORY_ONLY = {
  manifest: {
    sampleId: 'C-SYNTH-012',
    fileName: 'clean-with-advisory.js',
    label: 'clean',
    expectedScannerFindings: [],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        owasp2021Category: 'A06:2021-Vulnerable and Outdated Components',
        severity: 'INFORMATIONAL',
        location: { line: 1, column: 0 },
        weaknessDescription: 'Third-party library import component check.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'clean-with-advisory.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A06-001',
        ruleId: 'OWASP-A06-001',
        category: 'A06:2021-Vulnerable and Outdated Components',
        findingType: 'advisory',
        severity: 'INFORMATIONAL',
        location: { line: 1, column: 0 },
        description: 'Review dependency lodash for vulnerabilities.'
      }
    ]
  }
};

// 13. Metadata Error Separate from Detection Fixture
export const FIXTURE_METADATA_ERROR = {
  manifest: {
    sampleId: 'V-SYNTH-013',
    fileName: 'metadata-mismatch.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 14, column: 2 },
        weaknessDescription: 'Expected CRITICAL eval weakness'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'metadata-mismatch.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        category: 'A05:2021-Security Misconfiguration', // Category mismatch
        severity: 'LOW',                                // Severity mismatch
        location: { line: 14, column: 2 },
        description: 'eval detected with wrong metadata'
      }
    ]
  }
};

// 14. Scenario Exclusion Fixture (with unsupportedWeaknesses)
export const FIXTURE_SCENARIO = {
  manifest: {
    sampleId: 'SCENARIO-SYNTH-001',
    fileName: 'scenario-multi.js',
    label: 'scenario',
    workloadType: 'simulated-browser-workload',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-007',
        owasp2021Category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 22, column: 4 }
      }
    ],
    expectedAdvisories: [
      {
        ruleId: 'OWASP-A06-001',
        location: { line: 2, column: 0 }
      }
    ],
    unsupportedWeaknesses: [
      {
        category: 'A01:2021-Broken Access Control',
        description: 'Server-side RBAC enforcement not observable in static AST analysis.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'scenario-multi.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-007',
        ruleId: 'OWASP-A03-007',
        category: 'A03:2021-Injection',
        severity: 'HIGH',
        location: { line: 22, column: 4 },
        description: 'document.write detected'
      },
      {
        id: 'OWASP-A06-001',
        ruleId: 'OWASP-A06-001',
        findingType: 'advisory',
        severity: 'INFORMATIONAL',
        location: { line: 2, column: 0 },
        description: 'import advisory'
      }
    ]
  }
};

// 15. Unsupported Null-Rule Fixture
export const FIXTURE_UNSUPPORTED_NULL_RULE = {
  manifest: {
    sampleId: 'V-SYNTH-015',
    fileName: 'unsupported-null-rule.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: null,
        owasp2021Category: 'A04:2021-Insecure Design',
        severity: 'HIGH',
        location: { line: 10, column: 2 },
        weaknessDescription: 'Unsupported architectural flaw.'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'unsupported-null-rule.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        location: { line: 10, column: 2 },
        description: 'eval detected'
      }
    ]
  }
};

// 16. Same-Line Distinct Columns Fixture
export const FIXTURE_SAME_LINE_DISTINCT_COLUMNS = {
  manifest: {
    sampleId: 'V-SYNTH-016',
    fileName: 'same-line-distinct.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        location: { line: 20, column: 4 },
        severity: 'CRITICAL'
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'same-line-distinct.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        severity: 'CRITICAL',
        location: { line: 20, column: 4 }
      },
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        severity: 'CRITICAL',
        location: { line: 20, column: 35 } // Distinct column: NOT a duplicate!
      }
    ]
  }
};

// 17. Identical Duplicate Actuals Cannot Satisfy Multiple Expectations Fixture
export const FIXTURE_IDENTICAL_DUPLICATE_ACTUALS = {
  manifest: {
    sampleId: 'V-SYNTH-017',
    fileName: 'two-targets-duplicate-actuals.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        location: { line: 20, column: 4 }
      },
      {
        ruleId: 'OWASP-A03-001',
        location: { line: 20, column: 4 }
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'two-targets-duplicate-actuals.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        location: { line: 20, column: 4 }
      },
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        location: { line: 20, column: 4 } // Identical duplicate: cannot satisfy Target 2
      }
    ]
  }
};

// 18. Missing / Invalid Location Fixture
export const FIXTURE_MISSING_LOCATION = {
  manifest: {
    sampleId: 'V-SYNTH-018',
    fileName: 'missing-location.js',
    label: 'vulnerable',
    expectedScannerFindings: [
      {
        ruleId: 'OWASP-A03-001',
        location: { line: 10, column: 2 }
      }
    ]
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'missing-location.js',
    status: 'completed',
    hasError: false,
    findings: [
      {
        id: 'OWASP-A03-001',
        ruleId: 'OWASP-A03-001',
        location: { line: undefined, column: undefined } // Invalid location
      }
    ]
  }
};

// 19. Invalid Label Fixture
export const FIXTURE_INVALID_LABEL = {
  manifest: {
    sampleId: 'UNKNOWN-019',
    fileName: 'invalid-label.js',
    label: 'arbitrary_invalid_label',
    expectedScannerFindings: []
  },
  scanResult: {
    engine: 'supplied',
    fileName: 'invalid-label.js',
    status: 'completed',
    hasError: false,
    findings: []
  }
};

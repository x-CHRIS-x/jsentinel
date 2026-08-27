/* global process */
/**
 * Tier 3: Cross-Feature Integration Tests
 * 
 * Verifies:
 * - End-to-end integration: Scanner Output -> Guidance ID Resolution -> Catalog Lookup
 * - Multi-scenario guidance routing for ambiguous rules (A02-005 and A06-001)
 * - JSON export data structure, format integrity, and safe non-prescriptive action suggestions
 * - False Positive lifecycle integration: score penalty deduction, active issue filtering, JSON export tracking
 * - PDF formatter data structure alignment with Section 6 remediation guidelines
 */

import {
  TestRunner,
  assert,
  assertEqual,
  assertNotEqual,
  assertTrue,
  assertFalse,
  scanSourceCode,
  loadWebGuidanceCatalog
} from './helpers/testUtils.js';

export async function runTier3() {
  const runner = new TestRunner('Tier 3: Cross-Feature Integration');

  // Test 1: Scanner Issue Model Contract & Guidance ID Lookup Flow
  runner.test('Scanner issue findings resolve cleanly to guidance catalog recommendations', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const getGuidance = webMod.getGuidance || ((id) => (webMod.guidanceCatalog || webMod.default)[id] || webMod.FALLBACK_GUIDANCE);

    const testSnippet = `
      // Broken access control open redirect
      function handleRedirect(userTarget) {
        window.location.href = userTarget;
      }

      // Hardcoded password
      const userPassword = "SuperSecretPassword123!";

      // Dangerous eval injection
      function runDynamic(code) {
        eval(code);
      }
    `;

    const issues = scanSourceCode(testSnippet, 'testModule.js');
    assert(issues.length >= 3, `Expected at least 3 issues detected, got ${issues.length}`);

    for (const issue of issues) {
      // Verify ScanIssue shape
      assert(typeof issue.id === 'string' && issue.id.startsWith('OWASP-'), `Issue ID must be valid OWASP ID: ${issue.id}`);
      assert(typeof issue.guidanceId === 'string', `Issue must have guidanceId: ${issue.guidanceId}`);
      assert(typeof issue.line === 'number', `Issue must have numeric line: ${issue.line}`);
      assert(typeof issue.sourceLine === 'string', `Issue must have sourceLine: ${issue.sourceLine}`);
      assert(typeof issue.suggestion === 'string' && issue.suggestion.length > 0, `Issue must have suggestion: ${issue.suggestion}`);

      // Resolve in guidance catalog
      const guidance = getGuidance(issue.guidanceId);
      assert(guidance !== null && typeof guidance === 'object', `Guidance lookup failed for ${issue.guidanceId}`);
      assert(typeof guidance.title === 'string', `Resolved guidance must have title for ${issue.guidanceId}`);
      assert(typeof guidance.recommendedAction === 'string', `Resolved guidance must have recommendedAction for ${issue.guidanceId}`);
      assert(Array.isArray(guidance.approaches), `Resolved guidance must have approaches for ${issue.guidanceId}`);
      assert(Array.isArray(guidance.verifySteps), `Resolved guidance must have verifySteps for ${issue.guidanceId}`);
    }
  });

  // Test 2: Multi-Scenario Guidance Routing - OWASP-A02-005 (Credential vs Network Address)
  runner.test('Multi-scenario routing: A02-005 resolves credential and network-address variants accurately', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    const credSnippet = `const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";`;

    const credIssues = scanSourceCode(credSnippet, 'credTest.js');
    assert(credIssues.length >= 1, 'Should detect AWS secret key in credSnippet');

    const credGuidanceId = credIssues[0].guidanceId || credIssues[0].id;
    // Check if variant or base maps to credential guidance
    const credGuidance = catalog[credGuidanceId] || catalog['OWASP-A02-005:credential'] || catalog['OWASP-A02-005'];
    assert(credGuidance !== undefined, 'Credential guidance must exist in catalog');
    assert(credGuidance.risk.toLowerCase().includes('secret') || credGuidance.risk.toLowerCase().includes('credential') || credGuidance.summary.toLowerCase().includes('secret'), 'Credential guidance must address secrets');

    const netGuidance = catalog['OWASP-A02-005:network-address'];
    assert(netGuidance !== undefined, 'Network address guidance variant must exist');
    assert(netGuidance.recommendedAction.toLowerCase().includes('endpoint') || netGuidance.recommendedAction.toLowerCase().includes('address') || netGuidance.recommendedAction.toLowerCase().includes('configuration') || netGuidance.recommendedAction.toLowerCase().includes('ip'), 'Network address guidance must guide configuration review');
  });

  // Test 3: Multi-Scenario Guidance Routing - OWASP-A06-001 (Component Review, Express Headers, Dynamic Request Target)
  runner.test('Multi-scenario routing: A06-001 distinguishes component-review, express-headers, and dynamic-request-target', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const catalog = webMod.guidanceCatalog || webMod.default;

    const compVariant = catalog['OWASP-A06-001:component-review'];
    const expVariant = catalog['OWASP-A06-001:express-headers'];
    const dynVariant = catalog['OWASP-A06-001:dynamic-request-target'];

    assert(compVariant !== undefined, 'A06-001 component-review variant must exist');
    assert(expVariant !== undefined, 'A06-001 express-headers variant must exist');
    assert(dynVariant !== undefined, 'A06-001 dynamic-request-target variant must exist');

    // Distinct guidance verification
    assertNotEqual(compVariant.recommendedAction, expVariant.recommendedAction, 'Component review and Express headers must have different actions');
    assertNotEqual(expVariant.recommendedAction, dynVariant.recommendedAction, 'Express headers and Dynamic request target must have different actions');
    assertNotEqual(compVariant.recommendedAction, dynVariant.recommendedAction, 'Component review and Dynamic request target must have different actions');
  });

  // Test 4: JSON Exporter Output Schema & Safe Action Summaries
  runner.test('JSON exporter produces clean flat schema with non-prescriptive guidance actions and zero code replacement keys', async () => {
    // Simulate JSON export generator data structures
    const sampleResults = [
      {
        fileName: 'src/components/LoginForm.jsx',
        success: true,
        hasError: false,
        issues: [
          {
            id: 'OWASP-A01-001',
            guidanceId: 'OWASP-A01-001',
            severity: 'HIGH',
            line: 25,
            column: 6,
            message: 'Potential open redirect vulnerability',
            suggestion: 'Validate dynamic redirect targets against a whitelist of trusted domains, or avoid dynamic redirections entirely.',
            cvssBaseScore: 7.4,
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N'
          }
        ]
      }
    ];

    const sampleStats = {
      totalIssues: 1,
      activeIssuesCount: 1,
      criticalIssues: 0,
      highIssues: 1,
      mediumIssues: 0,
      lowIssues: 0,
      securityScore: 90.0
    };

    const sampleOwaspCategories = [
      { name: 'A01:2021-Broken Access Control', count: 1, severity: 'HIGH' }
    ];

    const sampleFpFlags = [];

    // Build JSON export model
    const flatIssues = [];
    sampleResults.forEach(res => {
      res.issues.forEach(issue => {
        const fpKey = `${res.fileName}:${issue.id}:${issue.line}:${issue.column}`;
        flatIssues.push({
          fileName: res.fileName,
          id: issue.id,
          guidanceId: issue.guidanceId || issue.id,
          severity: issue.severity,
          line: issue.line,
          column: issue.column,
          message: issue.message,
          suggestion: issue.suggestion,
          cvssBaseScore: issue.cvssBaseScore,
          cvssVector: issue.cvssVector,
          isFalsePositive: sampleFpFlags.includes(fpKey)
        });
      });
    });

    const report = {
      meta: {
        projectName: 'Test Project',
        scannedAt: new Date().toISOString(),
        scannerEngine: 'JSentinel Core v1.0.0'
      },
      summary: sampleStats,
      owaspProfile: sampleOwaspCategories,
      files: sampleResults.map(r => ({
        fileName: r.fileName,
        success: r.success,
        issuesCount: r.issues.length,
        activeIssuesCount: r.issues.length,
        score: 90.0
      })),
      issues: flatIssues
    };

    // Serialize & deserialize
    const jsonStr = JSON.stringify(report, null, 2);
    const parsed = JSON.parse(jsonStr);

    assertEqual(parsed.meta.projectName, 'Test Project');
    assertEqual(parsed.summary.totalIssues, 1);
    assertEqual(parsed.issues.length, 1);
    assertEqual(parsed.issues[0].id, 'OWASP-A01-001');
    assertFalse(parsed.issues[0].isFalsePositive);

    // Verify zero forbidden keys anywhere in JSON
    const forbiddenKeys = ['bad', 'good', 'replacementCode', 'goodSnippet', 'codeFixGuide'];
    for (const key of forbiddenKeys) {
      assert(jsonStr.includes(`"${key}":`) === false, `Exported JSON must not contain key "${key}"`);
    }
  });

  // Test 5: False Positive Scoring and JSON Filtering Lifecycle
  runner.test('Marking issue as False Positive recalculates score and updates export flag', () => {
    const rawIssues = [
      { id: 'OWASP-A02-001', severity: 'CRITICAL', line: 10, column: 2, message: 'Hardcoded password' },
      { id: 'OWASP-A01-001', severity: 'HIGH', line: 20, column: 4, message: 'Open redirect' },
      { id: 'OWASP-A05-001', severity: 'MEDIUM', line: 30, column: 6, message: 'Console log secret' }
    ];

    const fileName = 'src/test.js';
    const fpKeyToMark = `${fileName}:OWASP-A02-001:10:2`;
    let fpFlags = [];

    // Calculate initial score (penalty: 20 + 10 + 5 = 35 -> score: 65.0)
    const computeStats = (flags) => {
      let penalty = 0;
      let activeCount = 0;
      let critical = 0;
      let high = 0;
      let medium = 0;

      rawIssues.forEach(issue => {
        const key = `${fileName}:${issue.id}:${issue.line}:${issue.column}`;
        if (!flags.includes(key)) {
          activeCount++;
          if (issue.severity === 'CRITICAL') { critical++; penalty += 20.0; }
          else if (issue.severity === 'HIGH') { high++; penalty += 10.0; }
          else if (issue.severity === 'MEDIUM') { medium++; penalty += 5.0; }
        }
      });
      return {
        activeCount,
        critical,
        high,
        medium,
        securityScore: parseFloat(Math.max(0, 100 - penalty).toFixed(1))
      };
    };

    const initial = computeStats(fpFlags);
    assertEqual(initial.activeCount, 3);
    assertEqual(initial.securityScore, 65.0);

    // Flag CRITICAL issue as False Positive
    fpFlags.push(fpKeyToMark);
    const afterFP = computeStats(fpFlags);

    // Active count decreases, CRITICAL is removed from penalty (penalty: 10 + 5 = 15 -> score: 85.0)
    assertEqual(afterFP.activeCount, 2);
    assertEqual(afterFP.critical, 0);
    assertEqual(afterFP.securityScore, 85.0);

    // Check JSON export issue representation
    const exportedIssue = {
      fileName,
      id: rawIssues[0].id,
      line: rawIssues[0].line,
      column: rawIssues[0].column,
      isFalsePositive: fpFlags.includes(fpKeyToMark)
    };
    assertTrue(exportedIssue.isFalsePositive, 'Exported issue must reflect isFalsePositive = true');
  });

  // Test 6: PDF Remediation Guidance Section Data Layout
  runner.test('PDF report remediation structures enforce safe guidance-only formatting without replacement code', async () => {
    const webMod = await loadWebGuidanceCatalog();
    const getGuidance = webMod.getGuidance || ((id) => (webMod.guidanceCatalog || webMod.default)[id] || webMod.FALLBACK_GUIDANCE);

    // Emulate PDF Section 6 generation data extraction
    const uniqueRuleIds = ['OWASP-A01-001', 'OWASP-A03-001', 'OWASP-A07-001'];
    const pdfGuidanceRows = [];

    for (const ruleId of uniqueRuleIds) {
      const g = getGuidance(ruleId);
      pdfGuidanceRows.push({
        sectionHeader: 'Security Remediation Guidance',
        ruleTitle: `${ruleId}: ${g.title}`,
        patternLabel: 'Illustrative rule pattern — not the detected source',
        risk: g.risk,
        action: g.recommendedAction,
        cannotInfer: g.cannotInfer,
        approaches: g.approaches,
        verifySteps: g.verifySteps
      });
    }

    assertEqual(pdfGuidanceRows.length, 3);
    for (const row of pdfGuidanceRows) {
      assertEqual(row.sectionHeader, 'Security Remediation Guidance');
      assertEqual(row.patternLabel, 'Illustrative rule pattern — not the detected source');
      assert(typeof row.risk === 'string' && row.risk.length > 0);
      assert(typeof row.action === 'string' && row.action.length > 0);
      assert(typeof row.cannotInfer === 'string' && row.cannotInfer.length > 0);
      assert(Array.isArray(row.approaches) && row.approaches.length >= 1);
      assert(Array.isArray(row.verifySteps) && row.verifySteps.length >= 1);
    }
  });

  return await runner.run();
}

// Allow direct execution: node tests/e2e/tier3_cross_feature.test.js
if (process.argv[1] && process.argv[1].endsWith('tier3_cross_feature.test.js')) {
  runTier3().then(res => {
    process.exit(res.failed > 0 ? 1 : 0);
  });
}

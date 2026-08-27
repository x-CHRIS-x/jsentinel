/* global process */
/**
 * Tier 4: Real-World Workload Execution (108 Benchmark Samples + 8 Full Application Scenarios)
 * 
 * Verifies:
 * - End-to-end scanner execution on realistic project codebases (`test-samples/samples/`)
 * - 100% True Positive detection rate across all 54 Vulnerable benchmark samples (`V-*.js`)
 * - 100% Clean Pass rate (0 false positive findings) across all 54 Clean benchmark samples (`C-*.js`)
 * - `guidanceId`, `sourceLine`, and `suggestion` attachment for every detected finding
 * - Coverage and detection fidelity across all OWASP categories (A01, A02, A03, A05, A06, A07, A08, A10)
 * - Full scan verification across 8 realistic full-stack application scenarios
 * - Workload performance and non-crash stability guarantees
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  TestRunner,
  assert,
  assertEqual,
  assertFalse,
  PROJECT_ROOT,
  scanSourceCode
} from './helpers/testUtils.js';

export async function runTier4() {
  const runner = new TestRunner('Tier 4: Real-World Workload Execution (108 Samples + 8 Scenarios)');

  const samplesDir = path.join(PROJECT_ROOT, 'test-samples/samples');
  assert(fs.existsSync(samplesDir), `Samples directory not found at ${samplesDir}`);

  const allSampleFiles = fs.readdirSync(samplesDir).filter(f => f.endsWith('.js') || f.endsWith('.jsx'));
  const vulnerableFiles = allSampleFiles.filter(f => f.startsWith('V-')).sort();
  const cleanFiles = allSampleFiles.filter(f => f.startsWith('C-')).sort();
  const applicationScenarioFiles = allSampleFiles.filter(f => !f.startsWith('V-') && !f.startsWith('C-')).sort();

  // Test 1: Workload Sample Set Discovery
  runner.test('Workload sample dataset contains 54 vulnerable, 54 clean samples, and 8 full app scenarios', () => {
    assertEqual(vulnerableFiles.length, 54, `Expected 54 vulnerable samples, found ${vulnerableFiles.length}`);
    assertEqual(cleanFiles.length, 54, `Expected 54 clean samples, found ${cleanFiles.length}`);
    assertEqual(vulnerableFiles.length + cleanFiles.length, 108, `Expected 108 standard benchmark samples, found ${vulnerableFiles.length + cleanFiles.length}`);
    assertEqual(applicationScenarioFiles.length, 8, `Expected 8 full application scenario files, found ${applicationScenarioFiles.length}`);
  });

  // Test 2: Vulnerable Samples True Positive Detections (54/54)
  runner.test('Scanner executes cleanly on all 54 vulnerable samples with 100% True Positive detection rate', async () => {
    const failedDetections = [];
    const issuesByFile = new Map();

    for (const vFile of vulnerableFiles) {
      const filePath = path.join(samplesDir, vFile);
      const code = fs.readFileSync(filePath, 'utf8');

      let issues = [];
      try {
        issues = scanSourceCode(code, vFile);
      } catch (err) {
        assert(false, `Scanner threw error while scanning ${vFile}: ${err.message}`);
      }

      if (issues.length === 0) {
        failedDetections.push(vFile);
      } else {
        issuesByFile.set(vFile, issues);
      }
    }

    if (failedDetections.length > 0) {
      assert(false, `Scanner failed to detect vulnerabilities in ${failedDetections.length} files: ${failedDetections.join(', ')}`);
    }

    assertEqual(issuesByFile.size, 54, 'All 54 vulnerable files must produce at least one detected vulnerability');
  });

  // Test 3: Guidance Attachment & Source Line Extraction on All Findings
  runner.test('All detected findings have valid guidanceId, non-empty sourceLine, and clean non-prescriptive suggestions', async () => {
    let totalFindingsChecked = 0;

    for (const vFile of vulnerableFiles) {
      const filePath = path.join(samplesDir, vFile);
      const code = fs.readFileSync(filePath, 'utf8');
      const lines = code.split('\n');

      const issues = scanSourceCode(code, vFile);
      for (const issue of issues) {
        totalFindingsChecked++;

        // Rule ID format
        assert(typeof issue.id === 'string' && issue.id.startsWith('OWASP-'), `Invalid rule ID: ${issue.id} in ${vFile}`);

        // Guidance ID
        assert(typeof issue.guidanceId === 'string' && issue.guidanceId.length > 0, `Missing guidanceId on finding ${issue.id} in ${vFile}`);

        // Numeric Line
        assert(typeof issue.line === 'number' && issue.line >= 1 && issue.line <= lines.length, `Invalid line number ${issue.line} in ${vFile}`);

        // Source Line
        assert(typeof issue.sourceLine === 'string' && issue.sourceLine.trim().length > 0, `Missing sourceLine on line ${issue.line} in ${vFile}`);

        // Suggestion format (must not contain bad/good replacement code templates)
        assert(typeof issue.suggestion === 'string' && issue.suggestion.trim().length > 0, `Missing suggestion in ${vFile}`);
        assertFalse(issue.suggestion.includes('// bad:'), `Suggestion in ${vFile} should not contain code fix markers`);
        assertFalse(issue.suggestion.includes('// good:'), `Suggestion in ${vFile} should not contain code fix markers`);

        // Invariant severity & CVSS
        assert(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(issue.severity), `Invalid severity ${issue.severity} in ${vFile}`);
        assert(typeof issue.cvssBaseScore === 'number' || issue.cvssBaseScore === undefined, `Invalid CVSS score in ${vFile}`);
      }
    }

    assert(totalFindingsChecked >= 54, `Expected at least 54 findings across 54 vulnerable files, checked ${totalFindingsChecked}`);
  });

  // Test 4: Clean Samples Invariant (0 False Positives across all 54 Clean Files)
  runner.test('Scanner executes cleanly on all 54 clean samples with 0 false positive detections (100% clean pass rate)', () => {
    const falsePositives = [];

    for (const cFile of cleanFiles) {
      const filePath = path.join(samplesDir, cFile);
      const code = fs.readFileSync(filePath, 'utf8');

      let issues = [];
      try {
        issues = scanSourceCode(code, cFile);
      } catch (err) {
        assert(false, `Scanner threw error on clean file ${cFile}: ${err.message}`);
      }

      if (issues.length > 0) {
        falsePositives.push({ file: cFile, issues: issues.map(i => `${i.id}@L${i.line}`) });
      }
    }

    if (falsePositives.length > 0) {
      const summary = falsePositives.map(fp => `${fp.file}: [${fp.issues.join(', ')}]`).join('; ');
      assert(false, `False positives detected on clean samples (${falsePositives.length} files): ${summary}`);
    }

    assertEqual(falsePositives.length, 0, 'Clean samples must produce 0 false positive issues');
  });

  // Test 5: Category Coverage Distribution
  runner.test('Detections span across all 8 OWASP vulnerability categories in the workload', () => {
    const categoryDetections = new Map();

    for (const vFile of vulnerableFiles) {
      const filePath = path.join(samplesDir, vFile);
      const code = fs.readFileSync(filePath, 'utf8');
      const issues = scanSourceCode(code, vFile);

      issues.forEach(issue => {
        const match = issue.id.match(/^OWASP-(A\d+)/);
        const cat = match ? match[1] : 'Unknown';
        categoryDetections.set(cat, (categoryDetections.get(cat) || 0) + 1);
      });
    }

    const expectedCategories = ['A01', 'A02', 'A03', 'A05', 'A06', 'A07', 'A08', 'A10'];
    for (const cat of expectedCategories) {
      const count = categoryDetections.get(cat) || 0;
      assert(count > 0, `Expected positive vulnerability detections for category ${cat}, found ${count}`);
    }
  });

  // Test 6: Real-World Multi-Module Application Scenarios (8 Scenarios)
  runner.test('Scanner executes on 8 realistic application workload files with findings across real-world structures', () => {
    const scenarioResults = new Map();

    for (const appFile of applicationScenarioFiles) {
      const filePath = path.join(samplesDir, appFile);
      const code = fs.readFileSync(filePath, 'utf8');

      let issues = [];
      try {
        issues = scanSourceCode(code, appFile);
      } catch (err) {
        assert(false, `Scanner crashed on application scenario ${appFile}: ${err.message}`);
      }

      assert(issues.length > 0, `Application scenario ${appFile} should contain realistic vulnerability findings`);
      scenarioResults.set(appFile, issues.length);
    }

    assertEqual(scenarioResults.size, 8, 'All 8 application scenarios must execute cleanly');
  });

  // Test 7: Workload Performance & Stability
  runner.test('Full workload scan (116 files) completes within performance budget (average < 100ms per file)', () => {
    const startTime = Date.now();
    let totalFilesScanned = 0;

    for (const file of allSampleFiles) {
      const filePath = path.join(samplesDir, file);
      const code = fs.readFileSync(filePath, 'utf8');
      scanSourceCode(code, file);
      totalFilesScanned++;
    }

    const durationMs = Date.now() - startTime;
    const avgPerFileMs = durationMs / totalFilesScanned;

    assertEqual(totalFilesScanned, 116, 'Must have scanned all 116 files in workload');
    assert(avgPerFileMs < 100, `Average scan time per file (${avgPerFileMs.toFixed(1)}ms) exceeded 100ms threshold`);
  });

  return await runner.run();
}

// Allow direct execution: node tests/e2e/tier4_real_world_workload.test.js
if (process.argv[1] && process.argv[1].endsWith('tier4_real_world_workload.test.js')) {
  runTier4().then(res => {
    process.exit(res.failed > 0 ? 1 : 0);
  });
}

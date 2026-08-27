/* global process */
/**
 * JSentinel E2E Test Suite - Master Runner
 * 
 * Executes all 4 test tiers:
 * - Tier 1: Feature Coverage & Guidance Catalog Schema Integrity
 * - Tier 2: Boundary & Corner Cases (Negative Lookups, Safety Assertions)
 * - Tier 3: Cross-Feature Integration (Scanner -> Catalog -> Exporters)
 * - Tier 4: Real-World Workload Execution (108 Real-World Samples: 54 V- / 54 C-)
 * 
 * Exit Codes:
 * - 0: All tiers passed cleanly (100% pass rate)
 * - 1: One or more test assertions failed
 */

import { runTier1 } from './tier1_feature_coverage.test.js';
import { runTier2 } from './tier2_boundary_corner.test.js';
import { runTier3 } from './tier3_cross_feature.test.js';
import { runTier4 } from './tier4_real_world_workload.test.js';

async function main() {
  console.log('\x1b[1m\x1b[35m');
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║               JSentinel E2E Test Suite — Master Runner                       ║');
  console.log('║               Guidance-Only Security Recommendation System                   ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');
  console.log('\x1b[0m');

  const suiteStartTime = Date.now();
  const tierResults = [];

  // Execute Tiers sequentially
  const tiers = [
    { name: 'Tier 1: Feature Coverage', fn: runTier1 },
    { name: 'Tier 2: Boundary & Corner Cases', fn: runTier2 },
    { name: 'Tier 3: Cross-Feature Integration', fn: runTier3 },
    { name: 'Tier 4: Real-World Workload', fn: runTier4 }
  ];

  for (const tier of tiers) {
    try {
      const result = await tier.fn();
      tierResults.push(result);
    } catch (err) {
      console.error(`\x1b[31mFatal error executing ${tier.name}: ${err.message}\x1b[0m`);
      tierResults.push({
        suiteName: tier.name,
        total: 1,
        passed: 0,
        failed: 1,
        duration: 0,
        errors: [{ name: tier.name, error: err }]
      });
    }
  }

  const totalDuration = ((Date.now() - suiteStartTime) / 1000).toFixed(2);
  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;

  console.log('\x1b[1m\x1b[36m' + '═'.repeat(78) + '\x1b[0m');
  console.log('\x1b[1m\x1b[37m                         E2E TEST EXECUTION SUMMARY                          \x1b[0m');
  console.log('\x1b[1m\x1b[36m' + '═'.repeat(78) + '\x1b[0m');

  tierResults.forEach((res, idx) => {
    totalTests += res.total;
    totalPassed += res.passed;
    totalFailed += res.failed;

    const statusBadge = res.failed === 0 
      ? '\x1b[32m[PASS]\x1b[0m' 
      : '\x1b[31m[FAIL]\x1b[0m';
    
    console.log(`  Tier ${idx + 1}: ${res.suiteName.padEnd(48)} ${statusBadge} (${res.passed}/${res.total}) [${res.duration}s]`);
  });

  console.log('\x1b[1m\x1b[36m' + '─'.repeat(78) + '\x1b[0m');
  console.log(`  \x1b[1mTotal Tests:\x1b[0m     ${totalTests}`);
  console.log(`  \x1b[1mPassed:\x1b[0m          \x1b[32m${totalPassed}\x1b[0m`);
  console.log(`  \x1b[1mFailed:\x1b[0m          ${totalFailed > 0 ? '\x1b[31m' + totalFailed + '\x1b[0m' : '\x1b[32m0\x1b[0m'}`);
  console.log(`  \x1b[1mTotal Duration:\x1b[0m  ${totalDuration}s`);
  console.log('\x1b[1m\x1b[36m' + '═'.repeat(78) + '\x1b[0m');

  if (totalFailed > 0) {
    console.log('\n\x1b[1m\x1b[31m❌ FAILURES ENCOUNTERED:\x1b[0m');
    tierResults.forEach(res => {
      if (res.errors && res.errors.length > 0) {
        res.errors.forEach(e => {
          console.log(`  \x1b[31m• [${res.suiteName}] ${e.name}:\x1b[0m ${e.error.message}`);
        });
      }
    });
    console.log('\n\x1b[1m\x1b[31mE2E Suite Status: FAILED (Exit Code 1)\x1b[0m\n');
    process.exit(1);
  } else {
    console.log('\n\x1b[1m\x1b[32m✔ ALL E2E TEST TIERS PASSED SUCCESSFULLY (100% Pass Rate)\x1b[0m\n');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('\x1b[31mUnhandled exception in test runner:\x1b[0m', err);
  process.exit(1);
});

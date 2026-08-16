/**
 * Quick verification script: runs the scanner engine against all test samples
 * and reports which files were detected/missed.
 */
const fs = require('fs');
const path = require('path');
const { scanCode } = require('./src/scanner/scannerEngine');
const { allRules } = require('./src/scanner/rules');

const samplesDir = path.join(__dirname, '..', 'test-samples', 'samples');
const files = fs.readdirSync(samplesDir).filter(f => f.endsWith('.js') || f.endsWith('.jsx'));

let totalFiles = 0;
let vCorrect = 0; // Vulnerable files correctly flagged
let vMissed = 0;  // Vulnerable files missed (false negatives)
let cCorrect = 0; // Clean files correctly clean
let cFalsePos = 0; // Clean files incorrectly flagged (false positives)

const missed = [];
const falsePositives = [];

for (const file of files) {
  totalFiles++;
  const filePath = path.join(samplesDir, file);
  const code = fs.readFileSync(filePath, 'utf-8');
  const result = scanCode(code, file, allRules);
  
  const isVulnerable = file.startsWith('V-');
  const isClean = file.startsWith('C-');
  const hasIssues = result.issues.length > 0;

  if (isVulnerable) {
    if (hasIssues) {
      vCorrect++;
    } else {
      vMissed++;
      missed.push(file);
    }
  } else if (isClean) {
    if (!hasIssues) {
      cCorrect++;
    } else {
      cFalsePos++;
      const issueIds = result.issues.map(i => `${i.id} (${i.severity})`).join(', ');
      falsePositives.push(`${file}: ${issueIds}`);
    }
  } else {
    // Realistic test files (admin-dashboard, etc.): just report
    const issueCount = result.issues.length;
    console.log(`  [INFO] ${file}: ${issueCount} issues`);
  }
}

console.log('\n========================================');
console.log('  JSentinel Scanner Verification Report');
console.log('========================================\n');
console.log(`Total files scanned: ${totalFiles}`);
console.log('');
console.log(`--- Vulnerable Files (V-*.js) ---`);
console.log(`  Correctly detected: ${vCorrect}`);
console.log(`  Missed (FALSE NEGATIVES): ${vMissed}`);
if (missed.length > 0) {
  console.log(`  Files missed:`);
  missed.forEach(f => console.log(`    ✖ ${f}`));
}
console.log('');
console.log(`--- Clean Files (C-*.js) ---`);
console.log(`  Correctly clean: ${cCorrect}`);
console.log(`  Incorrectly flagged (FALSE POSITIVES): ${cFalsePos}`);
if (falsePositives.length > 0) {
  console.log(`  Files with false positives:`);
  falsePositives.forEach(f => console.log(`    ✖ ${f}`));
}
console.log('\n========================================');
const totalTests = vCorrect + vMissed + cCorrect + cFalsePos;
const totalPassed = vCorrect + cCorrect;
console.log(`  ACCURACY: ${totalPassed}/${totalTests} (${((totalPassed/totalTests)*100).toFixed(1)}%)`);
console.log('========================================\n');

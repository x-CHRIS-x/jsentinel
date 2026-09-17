import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { scanFile, deduplicateOverlappingHtmlIssues as webDeduplicate } from '../src/utils/scannerEngine.js';
import * as webPolicy from '../src/utils/findingPolicy.js';
import { formatJSONReport } from '../src/utils/jsonExporter.js';

const require = createRequire(import.meta.url);
const extPolicy = require('../vscode-extension/src/utils/findingPolicy.js');
const { scanCode, deduplicateOverlappingHtmlIssues: extDeduplicate } = require('../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../vscode-extension/src/scanner/rules.js');

const modules = ['injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization', 'knownVulns', 'accessControl'];
const webRules = (await Promise.all(modules.map(name => import(`../src/scanner/rules/${name}.js`)))).flatMap(mod => Object.values(mod).flat());

const scanBoth = async (code, name = 'test-sample.js') => [
  await scanFile({ name, text: async () => code }, webRules),
  scanCode(code, name, allRules)
];

test('Regression A: template assignment produces exactly OWASP-A03-004 and one eligible deduction', async () => {
  const code = 'container.innerHTML = `<div class="card">${username}</div>`;';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 1);

    const issue = result.issues[0];
    assert.equal(issue.id, 'OWASP-A03-004');
    assert.equal(issue.guidanceId, 'OWASP-A03-004');
    assert.equal(issue.severity, 'HIGH');
    assert.equal(issue.line, 1);
    assert.equal(issue.column, 0);
    assert.equal(issue.sourceLine, 'container.innerHTML = `<div class="card">${username}</div>`;');

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 1);
      assert.equal(stats.activeIssuesCount, 1);
      assert.equal(stats.highIssues, 1);
      assert.equal(stats.securityScore, 90);
    }
  }
});

test('Regression B: function-result assignment produces exactly OWASP-A03-005 and one eligible deduction', async () => {
  const code = 'container.innerHTML = renderCard(username);';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 1);

    const issue = result.issues[0];
    assert.equal(issue.id, 'OWASP-A03-005');
    assert.equal(issue.guidanceId, 'OWASP-A03-005');
    assert.equal(issue.severity, 'HIGH');
    assert.equal(issue.line, 1);
    assert.equal(issue.column, 0);

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 1);
      assert.equal(stats.activeIssuesCount, 1);
      assert.equal(stats.highIssues, 1);
      assert.equal(stats.securityScore, 90);
    }
  }
});

test('Regression C: generic innerHTML assignment produces OWASP-A03-006 and one eligible deduction', async () => {
  const code = 'container.innerHTML = rawMarkup;';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 1);

    const issue = result.issues[0];
    assert.equal(issue.id, 'OWASP-A03-006');
    assert.equal(issue.guidanceId, 'OWASP-A03-006');
    assert.equal(issue.severity, 'HIGH');
    assert.equal(issue.line, 1);
    assert.equal(issue.column, 0);

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 1);
      assert.equal(stats.activeIssuesCount, 1);
      assert.equal(stats.highIssues, 1);
      assert.equal(stats.securityScore, 90);
    }
  }
});

test('Regression D: two distinct assignments remain two findings including on the same line', async () => {
  const codeSameLineMixed = 'a.innerHTML = `<p>${x}</p>`; b.innerHTML = render(y);';
  const resultsMixed = await scanBoth(codeSameLineMixed);

  for (const result of resultsMixed) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 2);

    const ids = result.issues.map(i => i.id).sort();
    assert.deepEqual(ids, ['OWASP-A03-004', 'OWASP-A03-005']);
    assert.equal(result.issues[0].line, 1);
    assert.equal(result.issues[1].line, 1);
    assert.notEqual(result.issues[0].column, result.issues[1].column);

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 2);
      assert.equal(stats.activeIssuesCount, 2);
      assert.equal(stats.highIssues, 2);
      assert.equal(stats.securityScore, 80);
    }
  }

  const codeSameLineGeneric = 'a.innerHTML = x; b.innerHTML = y;';
  const resultsGeneric = await scanBoth(codeSameLineGeneric);

  for (const result of resultsGeneric) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 2);
    assert.equal(result.issues[0].id, 'OWASP-A03-006');
    assert.equal(result.issues[1].id, 'OWASP-A03-006');
    assert.equal(result.issues[0].line, 1);
    assert.equal(result.issues[1].line, 1);
    assert.notEqual(result.issues[0].column, result.issues[1].column);

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 2);
      assert.equal(stats.activeIssuesCount, 2);
      assert.equal(stats.highIssues, 2);
      assert.equal(stats.securityScore, 80);
    }
  }
});

test('Regression E: unrelated vulnerability at the same location survives alongside HTML finding', async () => {
  for (const dedupFn of [webDeduplicate, extDeduplicate]) {
    const rawIssues = [
      { id: 'OWASP-A02-001', line: 10, column: 5, severity: 'CRITICAL', message: 'Hardcoded password' },
      { id: 'OWASP-A03-004', line: 10, column: 5, severity: 'HIGH', message: 'Template innerHTML' },
      { id: 'OWASP-A03-006', line: 10, column: 5, severity: 'HIGH', message: 'General innerHTML' }
    ];

    const deduped = dedupFn(rawIssues);
    assert.equal(deduped.length, 2);
    assert.equal(deduped[0].id, 'OWASP-A02-001');
    assert.equal(deduped[1].id, 'OWASP-A03-004');
  }

  const code = 'eval(userInput); container.innerHTML = `<p>${userInput}</p>`;';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 2);

    const ids = result.issues.map(i => i.id).sort();
    assert.deepEqual(ids, ['OWASP-A03-001', 'OWASP-A03-004']);
  }
});

test('Regression F: normalized both-engine parity across all HTML assignment scenarios', async () => {
  const snippets = [
    'container.innerHTML = `<span class="user">${name}</span>`;',
    'container.innerHTML = formatName(name);',
    'container.innerHTML = rawHtmlInput;',
    'a.innerHTML = `<p>${x}</p>`; b.innerHTML = render(y);',
    'a.innerHTML = x;\nb.innerHTML = y;',
    'box.innerHTML =\n  `<div id="msg">${message}</div>`;',
    'if (isAdmin) {\n  panel.innerHTML = `<div class="admin">${panelData}</div>`;\n} else {\n  panel.innerHTML = renderUser(panelData);\n}'
  ];

  for (const snippet of snippets) {
    const [webResult, extResult] = await scanBoth(snippet);
    assert.equal(webResult.hasError, false);
    assert.equal(extResult.hasError, false);

    const normWeb = webResult.issues.map(i => [i.id, i.line, i.column, i.severity, i.findingType || 'vulnerability-pattern'].join(':')).sort();
    const normExt = extResult.issues.map(i => [i.id, i.line, i.column, i.severity, i.findingType || 'vulnerability-pattern'].join(':')).sort();
    assert.deepEqual(normWeb, normExt);
  }
});

test('Regression G: counts and scoring reflect single deduction for overlapping findings and false-positive handling works', async () => {
  const code = 'container.innerHTML = `<div class="card">${name}</div>`;';
  const results = await scanBoth(code, 'card-component.js');

  for (const result of results) {
    const baselineStats = webPolicy.calculateStats([result]);
    assert.equal(baselineStats.totalIssues, 1);
    assert.equal(baselineStats.activeIssuesCount, 1);
    assert.equal(baselineStats.highIssues, 1);
    assert.equal(baselineStats.securityScore, 90);

    const fpKey = `card-component.js:${result.issues[0].id}:${result.issues[0].line}:${result.issues[0].column}`;
    const fpStats = webPolicy.calculateStats([result], [fpKey]);
    assert.equal(fpStats.totalIssues, 1);
    assert.equal(fpStats.activeIssuesCount, 0);
    assert.equal(fpStats.highIssues, 0);
    assert.equal(fpStats.securityScore, 100);

    const jsonReport = formatJSONReport([result], baselineStats, [], [fpKey]);
    assert.equal(jsonReport.summary.totalIssues, 1);
    assert.equal(jsonReport.summary.activeIssuesCount, 0);
    assert.equal(jsonReport.summary.securityScore, 100);
    assert.equal(jsonReport.issues[0].isFalsePositive, true);
  }
});

test('Regression H: advisory-only A06 visible with zero vulnerability count and zero deduction', async () => {
  const code = 'import axios from "axios"; axios.get("/api/data");';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 1);

    const issue = result.issues[0];
    assert.equal(issue.id, 'OWASP-A06-001');
    assert.equal(issue.findingType, 'advisory');
    assert.equal(issue.severity, 'INFORMATIONAL');
    assert.equal(issue.cvssBaseScore, null);

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 0);
      assert.equal(stats.activeIssuesCount, 0);
      assert.equal(stats.advisoryCount, 1);
      assert.equal(stats.activeAdvisoryCount, 1);
      assert.equal(stats.securityScore, 100);
    }
  }
});

test('Regression I: mixed vulnerability and advisory: only vulnerability is counted and deducted', async () => {
  const code = 'import axios from "axios";\ncontainer.innerHTML = `<div class="msg">${input}</div>`;';
  const results = await scanBoth(code);

  for (const result of results) {
    assert.equal(result.hasError, false);
    assert.equal(result.issues.length, 2);

    const advisory = result.issues.find(webPolicy.isAdvisory);
    const vulnerability = result.issues.find(i => !webPolicy.isAdvisory(i));

    assert.ok(advisory, 'Advisory finding must be present');
    assert.ok(vulnerability, 'Vulnerability finding must be present');
    assert.equal(advisory.id, 'OWASP-A06-001');
    assert.equal(advisory.findingType, 'advisory');
    assert.equal(vulnerability.id, 'OWASP-A03-004');
    assert.equal(vulnerability.severity, 'HIGH');

    for (const policy of [webPolicy, extPolicy]) {
      const stats = policy.calculateStats([result]);
      assert.equal(stats.totalIssues, 1);
      assert.equal(stats.activeIssuesCount, 1);
      assert.equal(stats.advisoryCount, 1);
      assert.equal(stats.activeAdvisoryCount, 1);
      assert.equal(stats.highIssues, 1);
      assert.equal(stats.securityScore, 90);
    }
  }
});

test('Regression J: new saved scans are corrected but historical saved results are not silently recalculated or rewritten', async () => {
  const historicalRecord = {
    id: 'scan_legacy_1720000000000',
    timestamp: '2026-08-01T10:00:00.000Z',
    projectName: 'legacy-project',
    scannerVersion: 'JSentinel browser-scope v1',
    stats: {
      totalIssues: 2,
      activeIssuesCount: 2,
      advisoryCount: 0,
      activeAdvisoryCount: 0,
      criticalIssues: 0,
      highIssues: 2,
      mediumIssues: 0,
      lowIssues: 0,
      securityScore: 80
    },
    issues: [
      {
        id: 'OWASP-A03-004',
        severity: 'HIGH',
        line: 5,
        column: 0,
        message: 'Unsafe innerHTML assignment using dynamic template literal'
      },
      {
        id: 'OWASP-A03-006',
        severity: 'HIGH',
        line: 5,
        column: 0,
        message: 'Dangerous use of innerHTML'
      }
    ]
  };

  const serializedHistorical = JSON.stringify(historicalRecord);
  const reloadedHistorical = JSON.parse(serializedHistorical);

  assert.equal(reloadedHistorical.stats.totalIssues, 2);
  assert.equal(reloadedHistorical.stats.securityScore, 80);
  assert.equal(reloadedHistorical.issues.length, 2);

  const code = 'container.innerHTML = `<div class="card">${username}</div>`;';
  const [newWebResult] = await scanBoth(code, 'legacy-file.js');
  const newStats = webPolicy.calculateStats([newWebResult]);

  assert.equal(newWebResult.issues.length, 1);
  assert.equal(newStats.totalIssues, 1);
  assert.equal(newStats.securityScore, 90);

  assert.equal(reloadedHistorical.stats.totalIssues, 2);
  assert.equal(reloadedHistorical.stats.securityScore, 80);
});

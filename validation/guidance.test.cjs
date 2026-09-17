const assert = require('node:assert/strict');
const { test, before } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { pathToFileURL } = require('node:url');

// Run with: node --test validation/guidance.test.cjs
const root = path.resolve(__dirname, '..');
const extension = require('../vscode-extension/src/data/guidanceCatalog.js');
let web;
let formatJSONReport;
before(async () => {
  web = await import(pathToFileURL(path.join(root, 'src/data/guidanceCatalog.js')));
  ({ formatJSONReport } = await import(pathToFileURL(path.join(root, 'src/utils/jsonExporter.js'))));
});

const baseIds = [
  ...['001', '002'].map(n => `OWASP-A01-${n}`),
  ...['001', '002', '003', '004', '005', '006', '007'].map(n => `OWASP-A02-${n}`),
  ...['001', '002', '003', '004', '005', '006', '007', '008'].map(n => `OWASP-A03-${n}`),
  ...['001', '002', '003', '004'].map(n => `OWASP-A05-${n}`),
  'OWASP-A06-001', 'OWASP-A07-001',
  ...['001', '002', '003'].map(n => `OWASP-A08-${n}`),
  'OWASP-A10-001',
];
const variantIds = [
  'OWASP-A02-005:credential', 'OWASP-A02-005:network-address',
  'OWASP-A06-001:component-review', 'OWASP-A06-001:express-headers',
  'OWASP-A06-001:dynamic-request-target',
];
const exampleIds = [
  'OWASP-A02-003', 'OWASP-A03-002', 'OWASP-A03-003', 'OWASP-A03-004',
  'OWASP-A03-005', 'OWASP-A03-006', 'OWASP-A03-008', 'OWASP-A08-003',
];

test('web and extension publish identical complete guidance and fallback records', () => {
  assert.deepEqual(web.getAllGuidance(), extension.getAllGuidance());
  assert.deepEqual(web.FALLBACK_GUIDANCE, extension.FALLBACK_GUIDANCE);
  assert.equal(web.GUIDANCE_DISCLAIMER, extension.GUIDANCE_DISCLAIMER);
  assert.deepEqual(Object.keys(web.getAllGuidance()).sort(), [...baseIds, ...variantIds].sort());
  for (const id of baseIds) {
    const expected = [id, ...variantIds.filter(variant => variant.startsWith(`${id}:`))].sort();
    for (const catalog of [web, extension]) {
      assert.deepEqual(catalog.getGuidanceByRuleId(` ${id} `).map(record => record.guidanceId).sort(), expected);
    }
  }
});

test('each recommendation carries context and selective examples have no placeholders', () => {
  for (const record of [...Object.values(web.getAllGuidance()), web.FALLBACK_GUIDANCE]) {
    const label = record.guidanceId;
    for (const key of ['contextCheck', 'shortAction', 'risk', 'cannotInfer']) {
      assert.equal(typeof record[key], 'string', `${label}.${key}`);
      assert.ok(record[key].trim().length > 0, `${label}.${key} must contain useful text`);
    }
    assert.equal(record.shortAction, record.recommendedAction, label);
    assert.equal(record.summary, record.recommendedAction, label);
    assert.ok(record.approaches.length >= 1 && record.approaches.length <= 2, label);
    assert.ok(record.verifySteps.length >= 2 && record.verifySteps.length <= 3, label);
    if (exampleIds.includes(label)) {
      assert.equal(typeof record.illustrativePattern, 'string', label);
      assert.ok(record.illustrativePattern.trim(), label);
    } else {
      assert.equal(record.illustrativePattern, null, `${label}: omit examples that depend on architecture`);
    }
  }
});

const lookupCases = [
  [null, 'UNKNOWN'], [undefined, 'UNKNOWN'], [42, 'UNKNOWN'], [{}, 'UNKNOWN'],
  ['', 'UNKNOWN'], ['  ', 'UNKNOWN'], ['missing', 'UNKNOWN'],
  ['__disclaimer', 'UNKNOWN'], ['__proto__', 'UNKNOWN'], ['constructor', 'UNKNOWN'],
  [' __disclaimer:unknown ', 'UNKNOWN'],
  [' OWASP-A03-006 ', 'OWASP-A03-006'],
  [' OWASP-A02-005:credential ', 'OWASP-A02-005:credential'],
  [' OWASP-A02-005:unknown ', 'OWASP-A02-005'],
  [' OWASP-A02-005 :unknown ', 'OWASP-A02-005'],
  [{ guidanceId: ' OWASP-A02-005:credential ', id: 'OWASP-A03-006' }, 'OWASP-A02-005:credential'],
  [{ guidanceId: 'OWASP-A02-005:unknown', id: 'OWASP-A03-006' }, 'OWASP-A02-005'],
  [{ guidanceId: '__disclaimer', id: ' OWASP-A03-006 ' }, 'OWASP-A03-006'],
  [{ guidanceId: {}, id: 'OWASP-A02-005:unknown' }, 'OWASP-A02-005'],
  [{ guidanceId: ['OWASP-A03-001'], id: 'OWASP-A03-006' }, 'OWASP-A03-006'],
  [{ guidanceId: 'missing', id: ' OWASP-A02-005:credential ' }, 'OWASP-A02-005:credential'],
  [{ guidanceId: ' ', id: 'OWASP-A03-006' }, 'OWASP-A03-006'],
  [{ guidanceId: '__disclaimer', id: '__proto__' }, 'UNKNOWN'],
];

test('both lookup APIs reject metadata and resolve trimmed identifiers and base variants', () => {
  for (const catalog of [web, extension]) {
    assert.equal(catalog.guidanceCatalog.__disclaimer, catalog.GUIDANCE_DISCLAIMER);
    assert.equal(Object.keys(catalog.guidanceCatalog).includes('__disclaimer'), false);
    for (const [input, expectedId] of lookupCases) {
      const expected = expectedId === 'UNKNOWN' ? catalog.FALLBACK_GUIDANCE : catalog.guidanceCatalog[expectedId];
      assert.strictEqual(catalog.getGuidance(input), expected, JSON.stringify(input));
    }
  }
});

test('JSON report uses canonical conditional guidance and preserves unknown suggestions and schema', () => {
  const issues = [
    { id: 'OWASP-A03-006', severity: 'HIGH', suggestion: 'Old unconditional advice' },
    { id: 'OWASP-A02-005', guidanceId: 'OWASP-A02-005:credential', severity: 'CRITICAL' },
    { id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:unknown', severity: 'MEDIUM' },
    { id: 'OWASP-A03-006', guidanceId: {}, severity: 'LOW' },
    { id: 'CUSTOM', suggestion: 'Project-specific suggestion', severity: 'LOW' },
    { id: '__disclaimer', severity: 'LOW' },
  ].map((issue, index) => ({ line: index + 1, column: 0, message: 'Finding', ...issue }));
  const results = [{ fileName: 'project/src/example.js', success: true, hasError: false, issues }];
  const beforeResults = structuredClone(results);
  const fpKey = `project/src/example.js:${issues[1].id}:2:0`;
  const report = formatJSONReport(results, { totalIssues: issues.length }, [], [fpKey]);
  assert.deepEqual(results, beforeResults, 'formatting must not mutate scanner output');
  assert.deepEqual(report.issues.map(issue => issue.suggestion), [
    web.getGuidance(issues[0]).recommendedAction,
    web.getGuidance(issues[1]).recommendedAction,
    web.getGuidance(issues[2]).recommendedAction,
    web.getGuidance(issues[3]).recommendedAction,
    'Project-specific suggestion', '',
  ]);
  assert.deepEqual(Object.keys(report.issues[0]).sort(), [
    'fileName', 'id', 'guidanceId', 'severity', 'line', 'column', 'sourceLine',
    'message', 'suggestion', 'cvssBaseScore', 'cvssVector', 'isFalsePositive',
    'findingType', 'eligibleForVulnerabilityMetrics',
  ].sort());
  assert.equal(report.issues[1].isFalsePositive, true);
  assert.equal(report.files[0].activeIssuesCount, issues.length - 1);
  assert.equal(report.files[0].score, 82);
  assert.equal(report.meta.disclaimer, web.GUIDANCE_DISCLAIMER);
});

// Load the real extension modules while providing only their host API boundary.
function loadExtension(relativePath, vscode = {}) {
  const filename = path.join(root, 'vscode-extension/src', relativePath);
  const localRequire = createRequire(filename);
  const module = { exports: {} };
  const wrapper = vm.runInThisContext(`(function(require, module, exports, __dirname) {\n${fs.readFileSync(filename, 'utf8')}\n})`, { filename });
  wrapper(name => name === 'vscode' ? vscode : localRequire(name), module, module.exports, path.dirname(filename));
  return module.exports;
}

// Small DOM boundary for the real sidebar renderer. This checks content, aria
// state and click transitions; native browser keyboard/focus behavior needs UI QA.
class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.className = '';
    this.style = {};
    this.attributes = {};
    this.handlers = {};
    this._text = '';
    this.classList = {
      add: value => { this.className = `${this.className} ${value}`.trim(); },
      remove: value => { this.className = this.className.split(' ').filter(item => item !== value).join(' '); },
    };
  }
  appendChild(child) { this.children.push(child); return child; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(value) {
    this.children = [];
    this._text = String(value).replace(/<[^>]*>/g, '');
    // Arrow spans are addressed by the sidebar event handlers after insertion.
    for (const match of String(value).matchAll(/<span class="([^"]*arrow[^"]*)">([^<]*)<\/span>/g)) {
      const arrow = new Element('span');
      arrow.className = match[1];
      arrow.textContent = match[2];
      this.children.push(arrow);
    }
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  click() { this.handlers.click?.({ preventDefault() {} }); }
  querySelectorAll(selector) {
    const matches = element => selector.startsWith('.')
      ? element.className.split(' ').includes(selector.slice(1))
      : element.tagName.toLowerCase() === selector;
    return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

function createSidebar() {
  const { JSentinelSidebarProvider } = loadExtension('sidebarProvider.js');
  const html = new JSentinelSidebarProvider({})._getHtmlForWebview({});
  assert.doesNotMatch(html, /__(?:GUIDANCE_CATALOG|FALLBACK_GUIDANCE|DISCLAIMER|OWASP)_JSON__/);
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1]);
  const elements = new Map();
  const sandbox = {
    acquireVsCodeApi: () => ({ getState: () => ({}), setState() {}, postMessage() {} }),
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
      },
      querySelectorAll: () => [],
      createElement: tag => new Element(tag),
      createTextNode: text => { const node = new Element('#text'); node.textContent = text; return node; },
    },
    window: { addEventListener() {} },
  };
  vm.createContext(sandbox);
  scripts.forEach(script => vm.runInContext(script, sandbox, { filename: 'sidebar.html' }));
  return sandbox;
}

test('sidebar uses canonical fallback and identical lookup decisions', () => {
  const sidebar = createSidebar();
  for (const [input, expectedId] of lookupCases) {
    const record = sidebar.getGuidanceForIssue(input);
    assert.equal(record.guidanceId, expectedId, JSON.stringify(input));
    assert.deepEqual(JSON.parse(JSON.stringify(record)), web.getGuidance(input));
  }
});

test('sidebar shows context and action together, hides absent examples, and keeps details single-open', () => {
  const sidebar = createSidebar();
  for (const id of ['OWASP-A03-006', 'OWASP-A02-006', 'OWASP-A10-001', 'OWASP-A06-001:dynamic-request-target', 'UNKNOWN']) {
    const record = web.getGuidance(id);
    const container = new Element();
    const issue = { id, fpKey: `file:${id}:1:0`, line: 1, message: 'Finding', sourceLine: id === 'UNKNOWN' ? '' : 'element.innerHTML = input;' };
    sidebar.renderRemediationContent(container, issue);
    const detailArea = container.querySelector('.guidance-details-container');
    const upfront = container.children.filter(child => child !== detailArea).map(child => child.textContent).join('');
    assert.ok(upfront.includes(record.contextCheck), id);
    assert.ok(upfront.includes(record.recommendedAction), id);
    assert.ok(upfront.includes(web.GUIDANCE_DISCLAIMER), `${id}: disclaimer must not depend on examples`);
    if (id === 'UNKNOWN') assert.match(upfront, /unavailable/i);
    const toggles = detailArea.querySelectorAll('.guidance-detail-toggle');
    const examples = toggles.filter(button => /Example/i.test(button.textContent));
    assert.equal(examples.length, record.illustrativePattern ? 1 : 0, id);
    assert.ok(toggles.every(button => button.tagName === 'BUTTON' && button.type === 'button'));
    toggles[0].click();
    assert.ok(detailArea.textContent.includes(record.cannotInfer), `${id}: limitations belong with the risk`);
    assert.equal(toggles[0].getAttribute('aria-expanded'), 'true');
    toggles[1].click();
    assert.equal(toggles[0].getAttribute('aria-expanded'), 'false');
    assert.equal(toggles[1].getAttribute('aria-expanded'), 'true');
    const openPanels = detailArea.querySelectorAll('.guidance-detail-content').filter(panel => panel.style.display !== 'none');
    assert.equal(openPanels.length, 1);
    assert.equal(openPanels[0].id, toggles[1].getAttribute('aria-controls'));
    if (examples.length) {
      examples[0].click();
      assert.ok(detailArea.querySelectorAll('code').some(code => code.textContent === record.illustrativePattern));
    }
  }
});

test('hover keeps context, action, risk and verification concise and suppresses false positives', () => {
  const vscode = {
    MarkdownString: class { constructor(value) { this.value = value; } },
    Position: class { constructor(line, character) { this.line = line; this.character = character; } },
    Range: class { constructor(start, end) { this.start = start; this.end = end; } },
    Hover: class { constructor(contents, range) { this.contents = contents; this.range = range; } },
  };
  const { createHoverProvider } = loadExtension('hoverProvider.js', vscode);
  const document = { fileName: 'example.js', uri: { toString: () => 'file:///example.js' }, lineAt: () => ({ text: '  element.innerHTML = value;' }) };
  for (const id of ['OWASP-A03-006', 'OWASP-A10-001', 'UNKNOWN']) {
    const issue = { id, line: 2, column: 2, severity: 'HIGH', confidence: 'MEDIUM', message: 'Flagged code', sourceLine: id === 'UNKNOWN' ? '' : 'element.innerHTML = value;' };
    const map = new Map([[document.uri.toString(), [issue]]]);
    const provider = createHoverProvider(map);
    const hover = provider.provideHover(document, { line: 1 });
    const content = hover.contents.value;
    const record = web.getGuidance(issue);
    for (const text of [record.contextCheck, record.recommendedAction, record.risk, ...record.verifySteps]) assert.ok(content.includes(text), `${id}: ${text}`);
    assert.match(content, /sidebar/i);
    assert.match(content.replace(/\*/g, ''), /line:? 2/i);
    assert.doesNotMatch(content, /^#{1,6}.*(?:Choose an Approach|Example)|Conceptual pattern/im);
    if (record.illustrativePattern) assert.ok(!content.includes(record.illustrativePattern));
    assert.equal(hover.range.start.character, 2);
    assert.equal(provider.provideHover(document, { line: 0 }), null);
    const hidden = createHoverProvider(map, () => [`example.js:${id}:2:2`]);
    assert.equal(hidden.provideHover(document, { line: 1 }), null);
  }
});

function runExample(id, globals = {}, resultExpression) {
  const context = vm.createContext(globals);
  vm.runInContext(web.getGuidance(id).illustrativePattern, context, { timeout: 1000, filename: `${id}.example.js` });
  return { context, result: resultExpression ? vm.runInContext(resultExpression, context) : undefined };
}

test('random identifier example uses the cryptographic API', () => {
  let calls = 0;
  const uuid = '22a40f6e-6201-40de-8fd0-144b6b094323';
  const { result } = runExample('OWASP-A02-003', {
    crypto: { randomUUID() { calls += 1; return uuid; } },
    Math: { random() { assert.fail('security-sensitive values must not use Math.random'); } },
  }, 'identifier');
  assert.equal(calls, 1);
  assert.equal(result, uuid);
});

test('timer example passes a callback and preserves the scheduled argument', () => {
  let callback;
  const calls = [];
  const { context } = runExample('OWASP-A03-002', {
    userId: 'user-at-scheduling',
    processUserData: value => calls.push(value),
    setTimeout(fn, delay) {
      assert.equal(typeof fn, 'function');
      assert.equal(delay, 1000);
      callback = fn;
    },
  });
  context.userId = 'user-after-scheduling';
  assert.deepEqual(calls, []);
  callback();
  assert.deepEqual(calls, ['user-at-scheduling']);
});

test('fixed dispatch example executes known operations and rejects inherited or unknown names', () => {
  assert.equal(runExample('OWASP-A03-003', { action: 'add' }, 'result').result, 5);
  for (const action of ['constructor', '__proto__', 'toString', 'missing', 'add; alert(1)']) {
    assert.throws(() => runExample('OWASP-A03-003', { action }), /Unsupported operation/, action);
  }
});

function textTarget() {
  return {
    textContent: '',
    set innerHTML(_value) { assert.fail('the plain-text example must not parse user input as HTML'); },
  };
}

test('plain-text DOM examples preserve markup as text', () => {
  const markup = '<img src=x onerror="alert(1)"> & welcome';
  const cardTitle = textTarget();
  runExample('OWASP-A03-004', { cardTitle, userName: markup });
  assert.equal(cardTitle.textContent, markup);
  const contentElement = textTarget();
  runExample('OWASP-A03-006', { contentElement, untrustedInput: markup });
  assert.equal(contentElement.textContent, markup);
  const container = textTarget();
  const userData = { name: 'John' };
  runExample('OWASP-A03-005', {
    container, userData,
    renderUserProfile(data) { assert.equal(data, userData); return markup; },
  });
  assert.equal(container.textContent, markup);
});

test('normal JSX example escapes untrusted markup using React rendering', () => {
  const Babel = require('@babel/standalone');
  const React = require('react');
  const { renderToStaticMarkup } = require('react-dom/server');
  const code = Babel.transform(web.getGuidance('OWASP-A03-008').illustrativePattern, { presets: ['react'] }).code;
  const userContent = '<img src=x onerror="alert(1)"> & welcome';
  const element = vm.runInNewContext(code, { React, userContent }, { timeout: 1000 });
  const html = renderToStaticMarkup(element);
  assert.match(html, /&lt;img/);
  assert.match(html, /&amp; welcome/);
  assert.doesNotMatch(html, /<img\b/);
});

test('explicit field selection accepts expected JSON data and ignores hostile additional keys', () => {
  const untrustedData = JSON.parse('{"name":"John","isAdmin":true,"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}');
  const { result: target, context } = runExample('OWASP-A08-003', { untrustedData }, 'target');
  assert.equal(Object.getPrototypeOf(target), null);
  assert.deepEqual(Object.keys(target), ['name']);
  assert.equal(target.name, 'John');
  assert.equal(vm.runInContext('({}).polluted', context), undefined);
  for (const invalid of [null, [], {}, { name: false }, { name: 3 }, Object.create({ name: 'inherited' })]) {
    assert.throws(() => runExample('OWASP-A08-003', { untrustedData: invalid }), undefined, JSON.stringify(invalid));
  }
});

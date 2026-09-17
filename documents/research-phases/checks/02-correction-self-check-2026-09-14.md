# Phase 02 Correction Self-Check: 2026-09-14

## Identity, Scope, and Ancestry

- Worker and session: AO implementation session `jsentinel-20` (Gemini 3.8 Flash High).
- Working branch: `ao/jsentinel-20/phase02-validation-correction`.
- Exact base commit: `9e7a4ed956b928f9dc91e141795512eed5f48d42`.
  This base contains:
  - `eb8ce33` (Phase 02 initial implementation)
  - `d40f205` (Phase 02 self-check evidence)
  - `6b3e369` (Phase 02 Gemini independent review)
  - `9e7a4ed` (Phase 02 Sonnet independent re-review)
- Implementation commit: `b345d42e5979d49f5af56504f2305e143aacd6ea`.
- Scope: Bounded Phase 02 correction only. Address manager rejection rationale, implement smallest justified alias mutation handling in both scanner engines, add focused regressions, and provide this self-check record.
- Non-goals: No general dataflow engine, no dataset regeneration, no chapter editing, no evaluator changes, no AU testing, no Phase 03 work, no merge, and no pull request.

## Manager Rejection Rationale and Accounting Correction

Phase 02 candidate `eb8ce33` was rejected by the project manager for two specific reasons:

1. **Known Bypass via Alias Mutation:**
   The implementation in `eb8ce33` only inspected direct method calls on the allowlist identifier (`allowed.push(...)`). When code aliased the allowlist array (`const alias = allowed; alias.push(untrusted);`), the mutation was missed. If an allowlist check followed (`if (allowed.includes(target))`), the scanner treated the check as safe and suppressed the open redirect finding. An array must remain unchanged to prove destination safety. Direct and aliased mutations before the sink must prevent unsafe suppression.

2. **Accurate Scanner Execution Accounting:**
   Prior review reports claimed 464 scanner executions for the 116-sample browser-scope test by multiplying test assertions. Converting test assertions into scanner executions violates repository integrity rules against inflated evidence.
   - The browser-scope 116-sample test runs each sample through two engines (web scanner and extension scanner). This executes exactly 232 scans (116 samples * 2 engines = 232 scans).
   - Comparing base and candidate trees requires running both candidates (232 scans each), totaling 464 scans only when both are actually executed.
   - This correction explicitly records raw scanner execution counts and distinguishes them from assertion counts.

## Implemented Correction

### Scanner Rule Changes

Both `src/scanner/rules/accessControl.js` and `vscode-extension/src/scanner/rules.js` were updated in `getValidAllowlistBinding`. The helper functions remain byte-for-byte identical across both engines.

The updated `getValidAllowlistBinding` function now:
1. Validates the base binding as a constant `VariableDeclarator` initialized to a non-empty array literal of string or empty-template elements.
2. Tracks alias bindings created via `VariableDeclarator` (`const alias = current;`, `let alias = current;`) and `AssignmentExpression` (`alias = current;`).
3. Uses a worklist to inspect references for both the original binding and all discovered aliases.
4. Detects array mutations across all tracked references:
   - Method calls from `mutatingMethods` (`push`, `pop`, `shift`, `unshift`, `splice`, `reverse`, `sort`, `fill`, `copyWithin`).
   - Element and property assignments (`arr[0] = untrusted`, `arr.length = 0`).
   - Property update expressions (`arr[0]++`).
   - Unary `delete` operations (`delete arr[0]`), resolving the previously noted `delete` gap.
5. Returns `null` if any mutation is detected on the array or any of its aliases.
6. Preserves valid suppression for supported, unchanged fixed allowlists (including cases with unmutated alias references).

### Before and After Sink Behavior and Conservative Boundaries

The scanner enforces that an allowlist array must remain unchanged to justify suppressing open redirect alerts:
- **Direct or aliased mutation before sink:** Strictly invalidates the allowlist. The finding is retained and reported.
- **Direct or aliased mutation after sink:** Conservatively invalidates the allowlist. In JavaScript, functions are often executed repeatedly or after module loading, so mutations located below a function body can compromise earlier validation. Without a full inter-procedural control-flow graph engine, any mutation within the file scope disqualifies the array as fixed. This boundary is disclosed honestly as an intentional, conservative design choice.

## Preserved Historical Evidence

All historical review reports and probe scripts are preserved byte-for-byte in the repository:
- `documents/research-phases/checks/02-changes.md`
- `documents/research-phases/checks/02-checklist.md`
- `documents/research-phases/checks/02-issues.md`
- `documents/research-phases/checks/02-independent-review-2026-09-14.md`
- `documents/research-phases/checks/02-independent-review-probe-2026-09-14.mjs`
- `documents/research-phases/checks/02-independent-rereview-jsentinel-17-2026-09-14.md`
- `documents/research-phases/checks/02-independent-probes-jsentinel-17-2026-09-14.mjs`

Their historical PASS verdicts are not overwritten. They remain preserved as the record of prior reviews for commit `eb8ce33`. Those verdicts are superseded for candidate `b345d42`.

## Verification Commands and Observed Results

All commands were executed in workspace `C:\Users\johnc\.ao\data\worktrees\jsentinel\jsentinel-20`.

| Command | Exit Code | Observed Output / Details |
| --- | ---: | --- |
| `git status` | 0 | Branch clean, exactly 3 files committed in implementation commit `b345d42`. |
| `git diff 9e7a4ed -- documents/` | 0 | Exit 0 with empty diff; historical reports preserved byte-for-byte. |
| `node --test validation/validation-handling.test.mjs` | 0 | 6 tests passed (0 failed, 1373 ms). Covered all 6 criteria including 21 unsafe cases and 7 safe cases. |
| `node --test validation/browser-scope.test.mjs` | 0 | 11 tests passed (0 failed, 3208 ms). Includes full 116-sample check across both engines (232 scanner executions). |
| `node --test validation/guidance.test.cjs` | 0 | 13 tests passed (0 failed, 470 ms). |
| `npm run lint` | 0 | ESLint passed with 0 errors and 0 warnings. |
| `npm --prefix vscode-extension run lint` | 0 | Extension ESLint passed with 0 errors and 0 warnings. |
| `npm run build` | 0 | Vite v8.0.8 build succeeded; 233 modules transformed. |
| Scoped file inspection | 0 | Only 2 scanner rule files and 1 test file modified in implementation commit. |

### Summary of Focused Regressions in `validation-handling.test.mjs`

- **Criterion 1 (5 cases):** Negated includes in consequent, parenthesized includes, else branch, indexOf === -1, and indexOf < 0. All correctly flagged.
- **Criterion 2 (7 cases):** Unrelated functions (`validate`, `check`, `test`, `customValidator.isValid`) and OR conditions (`allowed.includes(target) || isAdmin`). All correctly flagged.
- **Criterion 3 (21 cases):**
  - Target variable reassignment (inside block and after early return).
  - Variable shadowing across scopes.
  - Direct array mutations: `push`, `unshift`, `delete`, index assignment, and mutations after the sink.
  - Alias mutations: `const alias = allowed; alias.push(...)`, alias push inside function, alias via assignment expression, transitive alias (`a = allowed; b = a; b.push(...)`), alias element assignment, alias delete operator, alias mutation with early return, and alias mutation after sink.
  - Allowlist reassignment and dynamic array elements.
  - Checks in separate branches and checks on wrong variable.
  All 21 cases correctly flagged.
- **Criterion 4 (7 cases):** Unchanged fixed allowlists with `location.href`, `location.replace`, `window.location.replace`, template literals, inverted branch with error exit, and unchanged arrays with unmutated alias reference. All 7 cases correctly suppressed.
- **Criterion 5 (7 cases):** Safe early returns (5 cases) suppressed; unsafe non-returning and conditional early returns (2 cases) flagged.
- **Callers Parity (4 cases):** Both engines agree on all assignment and call expression patterns.

## Limitations and Disclosures

1. **No General Alias Analysis:**
   The implementation tracks direct and transitive local aliases created by simple variable declarations and assignments. It does not perform heap shape analysis, object destructuring tracking, or inter-procedural alias tracking.
2. **Conservative Scope Invalidation:**
   Any mutation of an allowlist array anywhere in the file invalidates suppression. If code mutates an allowlist textually after a redirect in a single-pass script, the scanner still flags the redirect.
3. **Array Mutation Forms:**
   Common array mutation methods (`push`, `pop`, `shift`, `unshift`, `splice`, `reverse`, `sort`, `fill`, `copyWithin`), element assignments (`arr[0] = ...`), property updates, and `delete arr[0]` are detected. Complex mutations via external helper functions (`customMutator(allowed)`) remain outside the local syntactic scanner scope.
4. **Acorn vs Babel Literals:**
   The indexOf comparison handles Babel AST node types (`NumericLiteral` and unary minus). Espree or Acorn engines emitting generic `Literal` nodes remain an AST difference limitation.

## Self-Check Verdict

**SELF-CHECK: PASS.**

The allowlist alias mutation bypass is fixed in both `src/scanner/rules/accessControl.js` and `vscode-extension/src/scanner/rules.js`. Both engines maintain identical validation logic. All focused regressions pass, broader suites pass without regression, and scan count claims are accurately stated.

Independent review and manager acceptance remain pending. Per current policy, one fresh Opus verifier will be assigned by the manager.

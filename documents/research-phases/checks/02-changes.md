# Phase 02: Changes and Implementation Review Target

Branch: `ao/jsentinel-15/phase02-validation`
Date: September 14, 2026

## Commit References

- Comparison base: `0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4` (Phase 01 accepted code `c2a4c05` plus preserved verification evidence).
- Implementation candidate: `eb8ce33fce57b0f77892ed458555165be42d222e` (`eb8ce33`), "fix: constrain open redirect validation to explicit allowlists and safe control flow".
- Candidate self-check status: SATISFIED on worker self-check.
- Independent audit status: PENDING. Independent verification and manager acceptance have not yet been performed. This report does not self-certify independent PASS.

## Implementation Files Changed

| File | Change | Consequence |
| --- | --- | --- |
| `src/scanner/rules/accessControl.js` | Replaced legacy substring-based `isValidated` with AST allowlist checks, control-flow branch tracking, mutation detection, and early-return analysis. | Web scanner accurately distinguishes safe allowlist branches from unsafe rejected branches, mutations, and non-returning guards. |
| `vscode-extension/src/scanner/rules.js` | Replaced legacy `isValidated` with the identical helper logic, maintaining exact parity with the web scanner. | Extension scanner matches web scanner detection and suppression behavior on all redirect inputs. |
| `validation/validation-handling.test.mjs` | Created focused development regression suite with 6 test suites covering 34 distinct validation scenarios across both engines. | Provides verifiable regression coverage for rejected branches, validator names, OR conditions, mutations, shadowing, early returns, and callers. |

## Detailed Technical Changes

1. **Replaced Loose Function Name Matching**:
   - The previous helper matched any function call containing substrings like `include`, `indexof`, `test`, `validate`, or `check`.
   - The updated helper only matches explicit membership checks (`allowed.includes(target)` or `allowed.indexOf(target)` comparisons with `-1` or `0`).
   - Unrelated functions such as `validate(target)`, `check(target)`, or custom object methods are no longer accepted as validators.

2. **Fixed Rejected Branch Handling**:
   - Previously, the helper checked if any `IfStatement` test matched, regardless of whether the redirect was in the consequent or alternate, and stripped negation indiscriminately.
   - As a result, code inside `if (!allowed.includes(target)) { window.location.href = target; }` was incorrectly suppressed.
   - The updated helper tracks whether the condition was positive or negated. A redirect in the consequent requires a positive check. A redirect in the alternate requires a negated check.

3. **Disallowed OR Conditions**:
   - The previous helper evaluated binary and logical expressions with loose `||` traversal.
   - The updated helper rejects `||` expressions because an alternate truthy term cannot guarantee that the allowlist check passed.

4. **Added Allowlist Integrity Verification**:
   - The helper inspects the binding of the allowlist array in scope.
   - The allowlist must be declared as a variable with an array literal initializer containing only string literals or empty template literals.
   - The array must be constant (no reassignments) and must not have mutating method calls (`push`, `pop`, `shift`, `unshift`, `splice`, `reverse`, `sort`, `fill`, `copyWithin`) or element assignments (`allowed[i] = ...`).

5. **Added Early Return Guard Analysis**:
   - When a redirect is not enclosed in a matching `IfStatement` branch, the helper inspects preceding sibling statements in the same block.
   - If a preceding sibling is an `IfStatement` with a negated check (`!allowed.includes(target)`) whose consequent unconditionally exits (`return` or `throw`), the subsequent statements in that block are protected.
   - Non-returning guards (such as logging only) and conditional exits do not qualify.

6. **Enforced Target Integrity**:
   - The helper verifies that the target variable has not been reassigned between the validation point and the redirect sink.
   - Target shadowing is detected by ensuring that the target binding at the check matches the target binding at the sink.

## Supported Validation Forms and Limitations

### Supported Forms

- Direct `if (allowed.includes(target))` with redirect inside the consequent block.
- Inverted `if (!allowed.includes(target))` with redirect inside the alternate (`else`) block.
- Equivalent `allowed.indexOf(target) !== -1` or `>= 0` checks in matching branches.
- Guard statements `if (!allowed.includes(target)) return;` or `if (!allowed.includes(target)) throw ...;` where the redirect follows in the same block.
- Local and module-level allowlist arrays of fixed string literals that remain unchanged.
- Both active caller forms: `window.location.href = target` (including `location.href` and template literals `${target}`) and `location.replace(target)` (including `window.location.replace`).

### Unsupported Limitations

- External, dynamic, or configuration-driven allowlists (such as values fetched over HTTP, loaded from JSON, or read from environment variables).
- Custom validator functions or third-party validation libraries (such as validator.js or custom regex test functions).
- Complex Boolean conditions combining allowlist checks with other arbitrary application logic.
- Non-standard exit flows where an early exit is performed through an external abort function rather than a language-level `return` or `throw`.
- Inter-procedural validation where the allowlist check occurs in a caller or separate utility function.

## Stopping Point

Work stops at the completion of Phase 02 validation handling and candidate documentation. No Phase 03 modifications (such as HTML duplicate finding or project scoring changes) have been started.

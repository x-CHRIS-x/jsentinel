# Phase 02: Issues and Review Disclosures

Branch: `ao/jsentinel-15/phase02-validation`
Date: September 14, 2026
Base: `0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4` (`0de4a53`)
Candidate: `eb8ce33fce57b0f77892ed458555165be42d222e` (`eb8ce33`)

**Status: Worker self-check completed. Independent verification and manager acceptance PENDING.**

---

## Resolved Phase 02 Defects

### P2-V01: False Suppression on Rejected Allowlist Branches

- **Previous Behavior**: The validation helper stripped unary negation unconditionally and did not correlate the redirect sink location with the `consequent` or `alternate` branches. Placing an unsafe redirect inside `if (!allowed.includes(target)) { window.location.href = target; }` resulted in false suppression.
- **Resolution**: The updated helper tracks condition polarity (`POSITIVE` vs `NEGATED`). Only redirects placed in the matching branch (consequent for positive checks, alternate for negated checks) are eligible for suppression.

### P2-V02: Unsound Substring Matching of Validator Functions

- **Previous Behavior**: Any function call whose name contained `include`, `indexof`, `test`, `validate`, or `check` was accepted as a validator. Calls like `validate(target)` or `customValidator.check(target)` suppressed open redirect findings without inspecting what the function actually checked.
- **Resolution**: Substring matching was removed entirely. Validation is strictly limited to verified array membership checks (`includes` or `indexOf` comparisons) against a known allowlist.

### P2-V03: Insufficient Guarding via Logical OR Expressions

- **Previous Behavior**: In logical expressions (`node.type === 'LogicalExpression'`), the helper returned `checkTestNode(left) || checkTestNode(right)`. If an allowlist check was combined with any other expression using `||` (such as `allowed.includes(target) || isAdmin`), the redirect was suppressed even when the allowlist check evaluated to false.
- **Resolution**: The helper rejects `||` expressions because alternative conditions cannot prove that the destination value was validated.

### P2-V04: Bypasses via Target Reassignment, Shadowing, and Array Mutation

- **Previous Behavior**: The helper only walked up parent AST nodes without inspecting variable bindings or mutations. Attackers or developers could reassign `target = untrusted` after the check, shadow `target` with an inner parameter, mutate the allowlist with `allowed.push(...)`, or reassign the allowlist array.
- **Resolution**: The helper utilizes Babel's lexical scope analysis to verify that:
  1. The allowlist binding is constant, declared with a literal string array, and never mutated via array methods or index assignment.
  2. The target binding at the check matches the target binding at the sink.
  3. No constant violations (reassignments) for the target variable occur between the validation point and the redirect sink.

### P2-V05: Missing Support for Early Return Guards

- **Previous Behavior**: The helper only inspected ancestor `IfStatement` nodes. A common and secure idiom where an invalid destination triggers an early return before the redirect (e.g. `if (!allowed.includes(target)) return; window.location.href = target;`) was not recognized, resulting in false positives.
- **Resolution**: The helper checks preceding sibling statements in the enclosing block. When a preceding sibling is an `IfStatement` with a negated allowlist check whose consequent unconditionally exits (`return` or `throw`), subsequent statements in the block are protected as long as the target has not been reassigned.

---

## Disclosed Review Limitations

The following items are explicit design boundaries for Phase 02 and should be noted during independent verification:

1. **Static Local Allowlists Only**:
   - The helper only supports allowlists defined in the same file as an array literal of fixed strings (e.g. `const allowed = ["https://example.com"];`).
   - Dynamically loaded allowlists (e.g. fetched from an API endpoint, read from a database, or imported from an external JSON file) cannot be verified statically by this visitor and will not suppress findings.

2. **No Inter-Procedural Data Flow**:
   - Validation occurring inside an external utility function (e.g. `if (isValidDestination(target))`) is not analyzed across function boundaries. A general inter-procedural data-flow engine is outside the scope of Phase 02.

3. **Strict Early Return Control Flow**:
   - Early exit detection requires an explicit, unconditional `ReturnStatement` or `ThrowStatement`. Functions that exit via custom process-terminating calls or conditional return paths within the guard are intentionally treated as non-exiting to prevent false negative bypasses.

4. **No Broad Parser Rewrite**:
   - The changes are localized to the `isValidated` helper and its immediate rule callers in `src/scanner/rules/accessControl.js` and `vscode-extension/src/scanner/rules.js`. Unrelated rules, scoring systems, and dataset samples are unchanged.

---

## Next Steps

1. Commit these verification records to the assigned branch.
2. Deliver the final handoff to `jsentinel-4`.
3. An independent verifier will review the implementation and evidence in a separate session.
4. Do not begin Phase 03 work until Phase 02 has received formal independent verification and manager acceptance.

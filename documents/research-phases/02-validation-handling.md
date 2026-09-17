# Phase 02: Correct validation handling

Status: Not started. Depends on Phase 01. Suggested size: 2 to 3 focused blocks.

Resolve the second problem: a condition can currently hide a finding even when it does not prove that the value is allowed.

## Batch A: Small regression set

Prepare browser redirect examples before changing the helper. Cover a permitted destination, the rejected branch of a check, an unrelated validation function, an OR condition, and reassignment of the checked value. These are development regressions, not an independent accuracy benchmark.

## Batch B: Narrow validation logic

Review `isValidated` in `src/scanner/rules/accessControl.js` and the shared helper in `vscode-extension/src/scanner/rules.js`. Check every active caller remaining after Phase 01 so the two implementations behave consistently.

Do not accept a function solely because its name contains `check`, `validate`, or `test`. Do not treat the rejected branch of an allowlist condition as safe.

Only suppress a finding when the supported local code establishes the intended destination constraint. Start with a locally defined, unchanged array of fixed permitted destinations and its matching allowed branch. Support a rejection followed by an early return only when control flow clearly prevents the rejected value from reaching the redirect.

Unsupported validation remains a review limitation. Do not label an unrecognized validator as proven safe or claim that its presence establishes a confirmed vulnerability. A general data-flow engine is outside this phase.

## Checks and stopping point

- [ ] A redirect inside `if (!allowed.includes(target))` is not suppressed as validated.
- [ ] An unrelated function call or an OR condition cannot establish safety by itself.
- [ ] Reassignment, shadowing, mutation, and a check in a different branch cannot incorrectly justify suppression.
- [ ] Supported permitted-destination cases behave correctly in both scanners.
- [ ] Surviving callers receive the same fix, with regressions for affected behavior.

Deliver the helper correction, focused regression results, and a short list of supported validation forms. Stop before HTML finding changes.

# butwhy - Post-Implementation Review Rounds

Each round uses a DIFFERENT lens and a BINARY gate. A single failed check fails the round.
Raw evidence is in `reviews/round_*.json`. The golden baseline in `reviews/baseline/`
was frozen BEFORE optimization and is never overwritten.

| Round | Lens | Gate | Checks passed | Findings |
|---:|---|---|---:|---:|
| 1 | functional completeness | **PASS** | 8/8 | 1 |
| 2 | safety and isolation | **PASS** | 14/14 | 1 |
| 3 | determinism and canonical encoding | **PASS** | 5/5 | 0 |
| 4 | error handling and resource limits | **PASS** | 6/6 | 1 |
| 5 | edge cases and filesystem semantics | **PASS** | 7/7 | 1 |
| 6 | performance and resource governance | **PASS** | 6/6 | 0 |
| 7 | documentation honesty | **PASS** | 6/6 | 0 |
| 8 | adversarial red team | **PASS** | 7/7 | 0 |
| 9 | causal honesty | **PASS** | 6/6 | 0 |
| 10 | golden non-regression gate | **PASS** | 4/4 | 0 |

**Overall: 10/10 rounds PASS.**

## Findings and revisions applied

- **R1 (functional completeness):** No functional gaps found after the fixture TypeError fix.
- **R2 (safety and isolation):** REVISION APPLIED: capsules previously stored innocuously-named host IDs in plaintext. Added value-class token detection in secrets.py; regressed by this check.
- **R4 (error handling and resource limits):** DOCUMENTED DISTINCTION: a child-command timeout is an observed outcome recorded as `inconclusive`; exceeding butwhy's own copy/output caps raises exit 4. Both are correct and are disclosed in README.md.
- **R5 (edge cases and filesystem semantics):** REVISION APPLIED: _safe_join used realpath() on the final component, so retargeting a symlink operated on the symlink's TARGET. Replaced with lexical join + ancestor containment checks; regressed by this check.

## Reject-and-rebuild conditions

Any round returning FAIL sends the relevant module back for revision. 
Faked output, missing cases, nondeterminism, overclaimed causality, 
unredacted secrets, leftover temp state, or a changed canonical byte 
is a release-blocking defect.

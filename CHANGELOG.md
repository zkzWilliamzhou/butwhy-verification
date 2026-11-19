# Changelog

All notable changes to `butwhy` are documented here. The `schema_version`
integer is a persistent output contract: it changes only when canonical
artifact bytes or field semantics change.

## 0.1.0 — 2026-11-07

Initial release. Python >= 3.10, standard library only, offline.

### Added
- Six subcommands: `capture`, `diff`, `run`, `report`, `verify`, `demo`.
- Eight replayable factor families (`env_var`, `locale`, `timezone`,
  `line_endings`, `symlink_target`, `filename_case`, `file_mode`,
  `path_shadow`) and two non-replayable families (`interpreter_version`,
  `platform`).
- Six verdict values with a two-way counter-flip requirement for
  `necessary_and_sufficient`.
- SHA-256 hash-chained evidence ledger with offline verification, tamper
  detection, truncation detection and duplicate-event detection.
- Secret-safe capsules: never-transplant denylist with NFKC confusable
  handling, value-class token detection, and length-bucket redaction.
- Disposable-copy isolation: 0o700 temp roots, symlink/hardlink/special-file
  refusal, argv allowlist, process-group timeout, output byte caps, cleanup
  and quarantine.
- Compact sorted-key canonical JSON with 16 MiB / depth-32 bounds and
  `SOURCE_DATE_EPOCH` support.
- Golden contract: byte-identical non-regression gate before optimization.
- 103 unittest cases across six test modules and a 10-round executable review
  harness.

### Output contract
- `schema_version`: integer `1`.
- Canonical artifacts: `capsule.json`, `diff.json`, `ledger.json`,
  `verdict.json`, `golden.json` (compact canonical JSON, UTF-8, terminating
  newline).
- Human-facing `report.json` uses indent-2 presentation JSON only; it is not
  hashed.
- Closed exit-code set: 0, 1, 2, 3, 4, 5, 6.

### Revisions during review (function-affecting, applied BEFORE the golden freeze)
1. Fixed a test fixture writing a `str` to `sys.stdout.buffer`, which made
   every command fail with `TypeError` and produced false `no_effect` verdicts.
2. Replaced `realpath()` on `_safe_join`'s final path component with a lexical
   join plus ancestor containment checks: retargeting a symlink had been
   editing the symlink's *target* instead of the link.
3. Added value-class token detection so innocuously-named host credentials
   (pod ids, sandbox user ids, client ids) are no longer stored in plaintext
   capsules.
4. Excluded tool-control variables (`SOURCE_DATE_EPOCH`, `BUTWHY_*`) from the
   capsule env snapshot so capsule identity does not drift with provenance.
5. Fixed an argparse `dest` collision between the `run` subcommand and
   `--command`, and handled `--version` before required-subcommand parsing.

### Known limitations
- Cross-platform replay, kernel/ABI/DNS/remote-service differences and
  irreversible side effects are explicitly out of scope.
- `filename_case` is one-way and can never yield `necessary_and_sufficient`.
- Global novelty and GitHub star counts are not technical guarantees.

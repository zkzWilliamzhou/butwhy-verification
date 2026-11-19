# butwhy

> **It works on my machine ... but why?**

`butwhy` is an **offline**, **Python 3.10+**, **standard library only** CLI for
"works on my machine" failures. It has **no third-party dependencies** and makes
no network calls.

Its one defensible primitive is **counterfactual one-factor replay**: it copies
your working tree into a disposable directory, changes **exactly one** declared,
reversible factor, re-runs the same failing command, and emits a SHA-256
hash-chained evidence ledger. A human can then see whether that factor was
necessary, sufficient, both, or irrelevant.

**`butwhy` never claims root cause.** It reports counterfactual evidence, not a
determination of cause. Machine output is forbidden from containing the phrases
`root cause`, `caused by`, or `the bug is`.

---

## Why this exists (Prior art)

Environment capture/diff/ranking is already well covered by
`but-it-works-on-my-machine` / `womm`, `envfixer`, `pycheckem`, `envdiff`, and
ProcDelta. Kavira overlaps the one-factor experiment method at the production
incident layer. Documentation verifiers, fake-green detectors, agent-rule
linters and context profilers are likewise crowded categories.

No tool located in a **bounded search** on 2026-11-07 produces a *local,
pure-stdlib, command-level, one-factor experiment record* with a hash-chained
evidence ledger. That is the narrow gap `butwhy` occupies. Global novelty is
**unprovable** from a bounded search, and a 100k-star target is a distribution
outcome, not an engineering guarantee — see `reviews/` for the disclosed
ideation matrix and adversarial grill.

---

## Install & 30-second demo

No install step is required. Put `src/` on `PYTHONPATH`:

```bash
PYTHONPATH=src python3 -m butwhy demo \
  --work /tmp/bw \
  --confirm=yes-i-understand-butwhy-will-run-this
```

The demo generates a locale-dependent failure, runs `capture`, `diff`, `run`,
`report` and `verify`, demonstrates ledger tamper detection, and writes a golden
manifest. It needs no internet, no fixture download and no manual setup.

---

## CLI

Exactly six subcommands:

| Command | Purpose |
|---|---|
| `capture` | `--root DIR` (repeatable) `--out FILE` — record a secret-safe environment capsule |
| `diff` | `--capsule A --capsule B --out FILE` — propose one-factor changes |
| `run` | `--capsule FILE --diff FILE \| --subject FILE --work DIR --command "ARG..."` plus `--n`, `--timeout`, `--stdout-cap`, `--tree-cap`, `--confirm`, `--ledger`, `--out` |
| `report` | `--ledger FILE [--format text\|json] [--out FILE]` |
| `verify` | `--ledger FILE [--golden FILE] [--strict] [--out FILE]` |
| `demo` | `--work DIR --confirm=TOKEN [--keep]` |

`--command` is **one string**, split by `shlex.split` into an argv list and
never evaluated by a shell. Interpreter expression flags (`python -c`,
`sh -c`), destructive executables, absolute paths and shell metacharacters are
refused before any subprocess is reachable.

**Confirmation is mandatory.** `run` and `demo` require the exact token
`--confirm=yes-i-understand-butwhy-will-run-this`. Without it, `run` prints an
internal dry-run plan as JSON and exits `1` without executing anything.

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | OK |
| 1 | usage / general / report error |
| 2 | verify invalid or incomplete |
| 3 | safety policy denied |
| 4 | resource limit exceeded |
| 5 | unsupported schema or version |
| 6 | capture or replay error |

A child-command timeout is an **observed outcome** recorded as `inconclusive`,
not a tool failure; exceeding `butwhy`'s own copy or output caps raises exit 4.

---

## Verdict taxonomy

Six exact values, derived from a pure truth table over repeated observations:

| Verdict | Meaning |
|---|---|
| `necessary_and_sufficient` | stable baseline, stable flipped outcome, **and** a verified two-way counter-flip |
| `necessary` | one-way evidence, baseline fail → flip pass |
| `sufficient` | one-way evidence, baseline pass → flip fail |
| `no_effect` | baseline and flipped outcomes identical and stable |
| `non_replayable` | factor cannot be replayed offline (`interpreter_version`, `platform`) |
| `inconclusive` | mixed/flaky/timeout/error repeats, failed counter-flip, or multiple independently decisive factors |

Protocol: baseline repeated N times and flip repeated N times (default N = 3,
range 2–10). Any mixed, flaky, timeout or error result forces `inconclusive`.
`necessary_and_sufficient` is **forbidden** from one-way evidence and from
multi-factor cases; those produce an `inconclusive` overall verdict with a
`multi_factor` note.

### Factor families

8 replayable: `env_var`, `locale`, `timezone`, `line_endings`,
`symlink_target`, `filename_case`, `file_mode`, `path_shadow`.
2 non-replayable: `interpreter_version`, `platform`.

---

## Worked example

```bash
# On the machine where it works
PYTHONPATH=src python3 -m butwhy capture --root . --out good.json

# On the machine where it fails
PYTHONPATH=src python3 -m butwhy capture --root . --out bad.json

# Back on either machine
PYTHONPATH=src python3 -m butwhy diff --capsule good.json --capsule bad.json --out diff.json

# Inspect the dry run first (no execution)
PYTHONPATH=src python3 -m butwhy run --capsule good.json --diff diff.json \
  --work . --command "python3 -m pytest -q"

# Execute, then read the evidence
PYTHONPATH=src python3 -m butwhy run --capsule good.json --diff diff.json \
  --work . --command "python3 -m pytest -q" \
  --confirm=yes-i-understand-butwhy-will-run-this
PYTHONPATH=src python3 -m butwhy report --ledger ledger.json
PYTHONPATH=src python3 -m butwhy verify --ledger ledger.json --golden golden.json
```

---

## Safety model (read this)

- Every experiment runs in a **fresh disposable copy** (`mkdtemp`, mode `0o700`).
  The original tree, index, branch and cwd are never modified.
- The temp directory is a **containment boundary, not a kernel sandbox**. It is
  not a container, VM, seccomp filter or mandatory access-control boundary. A
  child process still runs with your own account's privileges.
- `butwhy` **cannot undo** network calls, deployments, database writes, sent
  mail or anything outside the copied tree. It only records counterfactual
  evidence.
- The child environment is rebuilt from scratch. Loader/runtime/identity/
  host-bound variables (`LD_*`, `DYLD_*`, `PYTHON*`, `NODE_OPTIONS`,
  `JAVA_TOOL_OPTIONS`, `BASH_ENV`, `IFS`, `PATH`, `HOME`, `USER`, `SHELL`,
  `TMPDIR`, `GIT_*`, `SSH_*`, `AWS_*`, proxy vars, Unicode confusables) are
  never transplanted. Secrets are removed **before** serialization; sensitive
  values are replaced by a coarse length bucket, never by a value-derived
  digest (a stable digest of a low-entropy secret is brute-forceable).
- Symlinks escaping the tree, hardlinks, FIFOs, device nodes, `.git` hooks and
  `node_modules` are refused or excluded. Process groups are killed on timeout.
- The ledger **does not prove** that a capsule was truthful, that a recorded
  command was safe, or that a verdict is correct. It proves only that an
  accepted event sequence was not altered after genesis. Verification is fully
  offline and needs no external trust anchor.

---

## Determinism & golden contract

Canonical JSON is UTF-8, sorted keys, compact separators, with `NaN`/
`Infinity`, duplicate keys, BOMs and non-canonical text rejected at a 16 MiB /
depth-32 bound. IDs are SHA-256 prefixes of canonical inputs — no ULID, PID,
hostname or wall clock enters a hashed payload. `SOURCE_DATE_EPOCH` controls a
presentation-only `captured_at` field.

Before any optimization, canonical artifacts are frozen in `reviews/baseline/`.
An optimization round is allowed only when every canonical artifact remains
**BYTE-IDENTICAL**, the CLI/verdict/factor/module surface is unchanged, and the
full test suite passes. A function change = any change to the CLI surface, exit
codes, verdict values, factor set, canonical artifact bytes, or ledger hash
chain.

---

## LIMITATIONS

1. Only declared, reversible, replayable factors are tested. Kernel, ABI,
   DNS, registry, container, hardware, wall-clock and remote-service
   differences are out of scope and are reported as `non_replayable` or
   `inconclusive`, never guessed.
2. Results are valid only for the recorded command, tree and environment.
3. A stable outcome is necessary but not sufficient for a causal claim; the
   tool deliberately stops at counterfactual classification.
4. `filename_case` is one-way only (original casing is lost), so it can never
   yield `necessary_and_sufficient`.
5. Cross-platform replay is not supported; `platform` is non-replayable.
6. `case`-insensitive filesystems cannot honestly exercise `filename_case`;
   such scenarios are marked infeasible rather than faked.
7. `python -c` / `sh -c` style commands are denied by policy. Put the code in a
   checked-in script inside the tree.
8. The 100k-star ambition is not a technical milestone. Popularity depends on
   distribution, timing and maintenance that this repository cannot guarantee.

---

## Development

```bash
make test            # 103 unittest cases
make security        # security regressions
make demo            # offline end-to-end demo
make verify-golden   # byte-identical non-regression gate
make check-deps      # stdlib-only / offline import guard
make review          # 10 distinct review rounds
```

No network access is needed for any target. Requires Python >= 3.10.

## License

MIT. See `LICENSE`.

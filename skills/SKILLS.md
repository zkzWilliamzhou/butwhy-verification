# Skills: sources, retrieval status, and how the workflow was actually run

Retrieval date: **2026-11-07**. Location: this `skills/` directory, vendored
into the deliverable so the whole project is self-contained and offline.

## Honest status first

A literal `git clone https://github.com/...` is **not possible in this sandbox**:

```
$ git ls-remote https://github.com/anthropics/skills.git HEAD
fatal: unable to access ... : The requested URL returned error: 403
```

Direct raw-file HTTPS retrieval works for some paths and fails for others. The
table below records exactly what was retrieved and what was not. Nothing here
is claimed to be a full repository install.

| Requested source | Repo URL | Retrieved | Vendored file |
|---|---|---|---|
| Anthropic skills (spec + skill format) | `https://github.com/anthropics/skills` | README + frontmatter requirements (`raw.githubusercontent.com`) | `vendored/anthropics-skills.md` |
| Matt Pocock skills (grill / TDD / diagnose) | `https://github.com/mattpocock/skills` | README + 2 `SKILL.md` files | `vendored/mattpocock-skills.md`, `vendored/grill-me.SKILL.md`, `vendored/grill-with-docs.SKILL.md` |
| Superpowers (brainstorming / plans / subagents / TDD / verification) | `https://github.com/obra/superpowers` | README workflow; individual `SKILL.md` paths could not be fetched | `vendored/superpowers-workflow.md` |
| Individual `SKILL.md` files for superpowers, Anthropic examples, and most Matt Pocock engineering skills | raw paths | **Not retrievable** (404 / blocked) | listed in `vendored/UNAVAILABLE.md` |

`vendored/` files are honest **retrieved excerpts and summaries**, not verbatim
full-file dumps. Where a full raw file was returned, its content is preserved.

## Skills that were already present (used directly)

- `scientific-brainstorming` — independent ideation, transparent criteria,
  adversarial review, decision log. Its `session_scaffold.py`,
  `validate_register.py`, and `evaluate_matrix.py` were executed; outputs are in
  `docs/brainstorm_session.json`, `docs/brainstorm_validation.json`,
  `docs/idea_criteria.json`, `docs/idea_scores.csv`, and `docs/idea_matrix.json`.
- `scientific-critical-thinking` — used to grade the prior-art evidence and to
  grill the research agents' claims.

## How the requested workflow was actually executed

The superpowers-style sequence (brainstorm → grill → spec → plan → TDD →
subagent-driven execution → code review → verification before completion) was
run with six specialized agents, each with a distinct remit, plus a strict
manager gate that rejected and re-commissioned low-quality work:

| Agent | Role | Output |
|---|---|---|
| Scout | prior-art landscape, 5 candidate concepts | `reports/01_prior_art_landscape.md` |
| Griller | adversarial novelty grill, 3 refined concepts | `reports/02_adversarial_novelty_grill.md` |
| Architect | implementation specification | `reports/03_initial_spec_superseded.md` → **REJECTED** → `reports/05_corrected_implementation_spec.md` |
| Red Team | pre-implementation threat model | `reports/04_red_team_threat_model.md` |
| QA Lead | definition of done + test matrix | `reports/06_initial_qa_matrix_superseded.md` → **REJECTED** → `reports/07_corrected_qa_matrix.md` |
| Manager (me) | final decision, strict review, 10 post-implementation rounds, optimization gate | `reviews/REVIEWS.md`, `reviews/optimization_proof.json` |

Two agent deliverables were **rejected and rebuilt** (Architect A1–A9, QA Lead
D1–D7). One QA deliverable was lost to a scratch-directory collision and was
re-commissioned. See `reports/` for the rejection notices.

## Skills installed into the program

`butwhy` itself has **zero third-party dependencies** and deliberately ships no
plugin system, so no external skill is imported at runtime. The engineering
practices from the above sources are instead encoded as executable code:

- TDD / verification-before-completion → 103 unittest cases, 10 review rounds.
- Subagent-driven development → six specialized agents above.
- Requesting code review → Architect + QA Lead rejection cycles.
- Grilling / shared language → the adversarial Griller report and the locked
  contract in `src/butwhy/contract.py`.
- Brainstorming decision log → `docs/idea_criteria.json`, `docs/idea_scores.csv`,
  `docs/idea_matrix.json`.

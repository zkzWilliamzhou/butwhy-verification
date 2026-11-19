# obra/superpowers — retrieved workflow notes

Source: https://github.com/obra/superpowers (README retrieved via
`raw.githubusercontent.com/obra/superpowers/main/README.md`, 2026-11-07).
Marketplace: https://github.com/obra/superpowers-marketplace

## Definition

"Superpowers is a complete software development methodology for your coding
agents, built on top of a set of composable skills and some initial
instructions that make sure your agent uses them."

The agent checks for relevant skills **before any task**. These are mandatory
workflows, not suggestions.

## The mandatory sequence

1. **brainstorming** — activates before building anything. Draws out what you
   actually want and why, through questions, then plays its understanding back
   for correction.
2. **using-git-worktrees** — isolated workspace on a new branch.
3. **writing-plans** — with an approved design, breaks work into bite-sized
   tasks (2–5 minutes each). Every task has exact file paths, complete code,
   and verification steps.
4. **subagent-driven-development** *or* **executing-plans** — dispatch a fresh
   subagent per task with a review after each (most thorough), or implement
   inline with one final review of the whole branch (cheapest).
5. **test-driven-development** — enforces RED-GREEN-REFACTOR: write a failing
   test, watch it fail, write minimal code, watch it pass, commit.
6. **requesting-code-review** — between tasks, against the plan; critical
   issues block progress.
7. **verification-before-completion** — prove everything works with real
   command output before marking done.

Other named skills: `systematic-debugging` (4-phase root cause process),
`root-cause-tracing`, `defense-in-depth`, `condition-based-waiting`,
`testing-anti-patterns`, `finishing-a-development-branch`, `writing-skills`,
`sharing-skills`, `testing-skills-with-subagents`, `using-superpowers`.

Slash commands: `/superpowers:brainstorm`, `/superpowers:write-plan`,
`/superpowers:execute-plan`.

Philosophy: TDD always; systematic over ad-hoc; complexity reduction;
**evidence over claims**; domain over implementation.

## Status

README retrieved. Individual `SKILL.md` paths could not be fetched in this
sandbox (see `UNAVAILABLE.md`). The workflow above was reproduced with six
specialized agents and a strict manager gate; see `../SKILLS.md`.

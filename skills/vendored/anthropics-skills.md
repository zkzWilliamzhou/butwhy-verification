# anthropics/skills — retrieved notes

Source: https://github.com/anthropics/skills (README retrieved via
`raw.githubusercontent.com/anthropics/skills/main/README.md`, 2026-11-07).

## Purpose

"This repository contains skills that demonstrate what's possible with Claude's
skills system." Skills are portable, structured knowledge modules that extend
AI agent capabilities. Each skill is a self-contained folder containing a
`SKILL.md` file with instructions and metadata, optionally bundled with
`scripts/`, `references/`, templates and assets.

## Structure

```
skills/<category>/<skill-name>/SKILL.md   # required
                              references/  # optional detailed docs
                              scripts/     # optional executable code
                              assets/      # optional templates
spec/       # Agent Skills specification
template/   # starter template
```

## SKILL.md frontmatter (required fields only)

```yaml
---
name: skill-name          # lowercase, hyphens for spaces; matches folder name
description: A complete description of what the skill does and when to use it
---
```

Optional metadata keys such as `author` and `version` are allowed. Skill names
MUST be unique across categories. The body contains actionable instructions
for agents; MUST / SHOULD / NEVER language is used for clarity.

## Installation (as documented upstream)

```
/plugin marketplace add anthropics/skills
# then: Browse and install plugins -> anthropic-agent-skills
#       -> document-skills or example-skills -> Install now
```

Contributor CI gates are `./scripts/validate-skills` and `pnpm format:check`.

## Status in this deliverable

Individual example `SKILL.md` files could not be retrieved from raw paths in
this sandbox. This note is an excerpt/summary of the retrieved README and
contributing guidance, not a verbatim copy of the repository.

# Achilles skills

First-party skill library for the Achilles harness. Same idea as
[anthropics/skills](https://github.com/anthropics/skills),
[trailofbits/skills](https://github.com/trailofbits/skills), and
[vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills):
each skill is a **folder** with a `SKILL.md` (and later `references/` / `scripts/`).

These folders are compiled into the desktop/CLI build. Users can still turn
each skill on or off in **Skills**.

Do not vendor other people’s skill repos into this tree. Trail of Bits is
CC BY-SA; Anthropic document skills are mixed-license; Vercel’s pack is
React/design/deploy, not AppSec. We write our own playbooks, ledger-first.

## Shipped

| Folder | When the model should load it |
|--------|-------------------------------|
| [security-review](security-review/) | Review this branch / PR / diff for high-confidence security bugs |
| [threat-model](threat-model/) | “What can go wrong?” from files Achilles already fingerprint-detected |
| [variant-hunt](variant-hunt/) | Same bug as finding X, elsewhere in this repo |
| [auth-review](auth-review/) | Login, session, JWT, permission checks |
| [github-actions-security](github-actions-security/) | Workflow files, secrets in CI, pull_request_target |
| [stack-security](stack-security/) | Framework/language playbook after fingerprint (Next, Django, Go, Rust, Terraform, k8s, …) |

Scan-adjacent skills still live as compact builtins next to the agent
(`review-findings`, `propose-fix`, `code-review`, `rotate-secret`,
`dependency-risk`, `map-attack-surface`, `map-codebase`). This directory is
the **methodology library** — the thing that should feel like a security
engineer, not a scanner UI.

Packaged, parameterized runs (nightly scan recap, SCA report, “review this
PR”) live in [`recipes/`](../recipes/) and can be scheduled. They call the
same AppSec tools; they do not replace these playbooks.

## Utilities

Hash / redact / encrypt / SBOM belong as **tools** on the AppSec extension
(`appsec_utils`), not as a pile of markdown. Skills here only teach *when*
to call those tools once they exist.

## Layout

```
skills/
  <name>/
    SKILL.md          required — frontmatter name + description, then instructions
    references/       optional — loaded on demand, not dumped into every turn
    scripts/          optional — real helpers, reviewed like product code
```

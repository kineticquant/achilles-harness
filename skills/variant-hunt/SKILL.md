---
name: variant-hunt
description: Given one Achilles finding (or a concrete bug in a file), search this repo for the same pattern elsewhere. Do not mint new finding ids.
---

Use this skill when the user says “are there more like this?”, “same bug elsewhere?”, or names a `finding_id`.

## Rules

1. Start from a **finding** (`appsec_investigate`) or a file:line they pointed at. If they described a class of bug with no location, ask for one example first.
2. Extract the *pattern*, not a regex dump of the whole tree: the sink (e.g. string-built SQL), the missing guard, the unsafe API.
3. Search with Grep/Glob in the same language. Cap the hunt — report the best matches, not every similar identifier.
4. Each extra hit is a **hypothesis**. Say that. Offer to scan or `appsec_investigate` if an engine finding already exists nearby. Do **not** invent `finding_id`s.
5. No exploit payloads. If a hit is in tests or generated code, say so and skip it.

## Output

- The original (id or file:line) in one line
- A table: path, why it looks the same, confidence (high/medium/low)
- What to do: confirm on Findings, or ignore (test/vendor)

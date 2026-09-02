---
name: goose-doc-guide
description: Reference Achilles product docs to create, configure, or explain Achilles features like Findings, recipes, extensions, sessions, and providers. You MUST read the relevant docs before answering. You MUST NOT rely on training data for Achilles-specific fields, values, names, syntax, or commands.
---

Use this skill when working with **Achilles-specific features**:
- Creating or editing recipes
- Configuring extensions or providers
- Explaining Findings, scans, or project hints
- Any Achilles configuration or setup task

Do NOT use this skill for general coding unrelated to Achilles.

The docs root for this session is `{{GOOSE_DOCS_ROOT}}`. It may be a local
filesystem path (the repo `docs/` folder) or a GitHub URL. When it is a local
path, read files with the shell/file tools. When it is not set, use
https://github.com/kineticquant/achilles-harness/blob/main/docs

## Steps (COMPLETE ALL BEFORE RESPONDING)
1. **Read official docs**
   - Start with `<docs-root>/README.md` (or `index.html`) for the page list
   - Then read the matching page: `quickstart.html`, `extensions.html`, `hints.html`, `recipes.html`, `troubleshooting.html`
   - Also use the repo root `README.md` and `recipes/README.md` when relevant
   - Do not cite goose-docs.ai or aaif-goose/goose as Achilles product docs

2. **Create/modify content**
   - Match field names and CLI examples from those files
   - The interactive CLI binary is still named `goose` (inherited); the product name is Achilles
   - Project hints still live in `.goosehints`

3. **Provide your answer**
   - Cite the doc file you used
   - Link GitHub blob URLs under `https://github.com/kineticquant/achilles-harness/blob/main/docs/`, not local filesystem paths

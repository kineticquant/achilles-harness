/** Public Achilles destinations used by the desktop app (Help menu, briefs, issues). */
export const ACHILLES_SITE = 'https://achilles.sh';
export const ACHILLES_REPO = 'https://github.com/kineticquant/achilles-harness';
export const ACHILLES_DISCUSSIONS = `${ACHILLES_REPO}/discussions`;
export const ACHILLES_ISSUES = `${ACHILLES_REPO}/issues`;

/**
 * Product guidance lives in `/docs` as static HTML (open locally, or host later).
 * Until GitHub Pages or achilles.sh serves that folder, the app opens the GitHub file view.
 */
const ACHILLES_DOCS_DIR = `${ACHILLES_REPO}/blob/main/docs`;

export const ACHILLES_DOCS = `${ACHILLES_DOCS_DIR}/index.html`;
export const ACHILLES_DOCS_QUICKSTART = `${ACHILLES_DOCS_DIR}/quickstart.html`;
export const ACHILLES_DOCS_EXTENSIONS = `${ACHILLES_DOCS_DIR}/extensions.html`;
export const ACHILLES_DOCS_HINTS = `${ACHILLES_DOCS_DIR}/hints.html`;
export const ACHILLES_DOCS_RECIPES = `${ACHILLES_DOCS_DIR}/recipes.html`;
export const ACHILLES_DOCS_TROUBLESHOOTING = `${ACHILLES_DOCS_DIR}/troubleshooting.html`;
export const ACHILLES_DOCS_DIAGNOSTICS = `${ACHILLES_DOCS_DIR}/troubleshooting.html#diagnostics`;

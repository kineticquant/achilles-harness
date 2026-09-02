/** Browser-safe template path checks — no node:path. */

export const TEMPLATE_EXTS = new Set([
  '.html',
  '.htm',
  '.j2',
  '.jinja',
  '.jinja2',
  '.njk',
  '.ejs',
  '.erb',
  '.haml',
  '.slim',
  '.hbs',
  '.mustache',
  '.twig',
  '.liquid',
  '.pug',
  '.jade',
  '.ftl',
  '.vm',
]);

function extname(file: string): string {
  const base = file.replace(/\\/g, '/').split('/').pop() || file;
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot).toLowerCase();
}

export function isTemplatePath(file: string): boolean {
  const norm = file.replace(/\\/g, '/').toLowerCase();
  const ext = extname(norm);
  if (TEMPLATE_EXTS.has(ext) && ext !== '.html' && ext !== '.htm') return true;
  if ((ext === '.html' || ext === '.htm') && /(?:^|\/)(?:templates|views|mails|emails)\//.test(norm)) {
    return true;
  }
  return false;
}

const API_EXTS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.php',
  '.java',
  '.kt',
  '.vue',
  '.svelte',
]);

export function isApiSourcePath(file: string): boolean {
  return API_EXTS.has(extname(file));
}

export function isTemplateMapPath(file: string): boolean {
  return isTemplatePath(file) || isApiSourcePath(file);
}

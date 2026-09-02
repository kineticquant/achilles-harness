import { enclosingFunction, listFunctionsInSource } from './seedSymbol';
import type { InspectEdge, InspectGraph, InspectNode } from './types';

export type RenderHit = {
  file: string;
  line: number;
  fn: string;
  template: string;
  context: string[];
};

export type TemplateVar = {
  name: string;
  line: number;
};

export type TemplateDoc = {
  file: string;
  vars: TemplateVar[];
  includes: string[];
};

const JINJA_SKIP = new Set([
  'and',
  'or',
  'not',
  'in',
  'is',
  'if',
  'else',
  'elif',
  'endif',
  'for',
  'endfor',
  'block',
  'endblock',
  'extends',
  'include',
  'import',
  'macro',
  'endmacro',
  'set',
  'filter',
  'endfilter',
  'with',
  'endwith',
  'call',
  'endcall',
  'true',
  'false',
  'none',
  'null',
  'loop',
  'super',
  'self',
  'range',
  'dict',
  'lipsum',
  'cycler',
  'namespace',
  'defined',
  'undefined',
  'length',
  'default',
  'e',
  'safe',
  'url_for',
  'csrf_token',
  'static',
  'url',
  'load',
  'trans',
  'blocktrans',
  'pluralize',
  'autoescape',
  'raw',
  'endraw',
  'do',
  'as',
  'only',
  'ignore',
  'missing',
]);

export function normalizeTemplateName(raw: string): string | undefined {
  let value = raw.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (!value || value.length > 180 || value.includes('#{') || value.includes('${')) return undefined;
  value = value.replace(/^(?:app\/views|resources\/views|src\/views|views|templates)\//, '');
  return value.toLowerCase();
}

export function templateFileMatches(file: string, template: string): boolean {
  const key = normalizeTemplateName(template);
  if (!key) return false;
  const norm = file.replace(/\\/g, '/').toLowerCase();
  const noExt = key.replace(/\.(html|htm|j2|jinja2?|njk|ejs|erb|hbs|twig|liquid|pug|jade|ftl)$/i, '');
  const base = noExt.split('/').pop() || noExt;
  const partial = noExt.includes('/')
    ? `${noExt.slice(0, noExt.lastIndexOf('/') + 1)}_${base}`
    : `_${base}`;
  const needles = [key, noExt, `${noExt}.html`, `${noExt}.html.j2`, `${noExt}.html.erb`, partial];
  return needles.some((needle) => norm === needle || norm.endsWith(`/${needle}`));
}

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function fnAt(source: string, line: number): string {
  return enclosingFunction(listFunctionsInSource(source), line) || '<module>';
}

function contextFromArgs(args: string): string[] {
  const names = new Set<string>();
  for (const match of args.matchAll(/\b([A-Za-z_][\w]*)\s*=/g)) {
    const name = match[1];
    if (name && !['template', 'context', 'status', 'request', 'content_type'].includes(name)) {
      names.add(name);
    }
  }
  for (const match of args.matchAll(/(['"])([A-Za-z_][\w]*)\1\s*:/g)) {
    if (match[2]) names.add(match[2]);
  }
  return [...names];
}

const RENDER_CALLS: { re: RegExp; tmpl: number; args?: number }[] = [
  { re: /\brender_template\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\brender_to_string\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\bget_template\s*\(\s*(['"])([^'"]+)\1/gi, tmpl: 2 },
  { re: /\bTemplateResponse\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\.TemplateResponse\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\brender\s*\(\s*[A-Za-z_][\w]*\s*,\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\.render\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\bview\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\bView::make\s*\(\s*(['"])([^'"]+)\1([^)]*)\)/gi, tmpl: 2, args: 3 },
  { re: /\brender\s+(?:template:\s*)?(['"])([^'"]+)\1/gi, tmpl: 2 },
  { re: /\brender\s+partial:\s*(['"])([^'"]+)\1/gi, tmpl: 2 },
  { re: /\bExecuteTemplate\s*\([^,]+,\s*(['"])([^'"]+)\1/gi, tmpl: 2 },
  { re: /\bParseFiles\s*\(\s*(['"])([^'"]+)\1/gi, tmpl: 2 },
];

export function extractRenderHits(source: string, file: string): RenderHit[] {
  if (!source) return [];
  const hits: RenderHit[] = [];
  const seen = new Set<string>();
  for (const spec of RENDER_CALLS) {
    spec.re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = spec.re.exec(source))) {
      const template = normalizeTemplateName(match[spec.tmpl] ?? '');
      if (!template) continue;
      const line = lineOf(source, match.index);
      const fn = fnAt(source, line);
      const context = spec.args ? contextFromArgs(match[spec.args] ?? '') : [];
      const key = `${file}:${line}:${template}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ file, line, fn, template, context });
    }
  }
  return hits;
}

export function extractTemplateDoc(source: string, file: string): TemplateDoc {
  const vars: TemplateVar[] = [];
  const includes: string[] = [];
  const seenVar = new Set<string>();

  const addVar = (name: string | undefined, index: number) => {
    if (!name || JINJA_SKIP.has(name.toLowerCase()) || name.startsWith('_')) return;
    const key = name.toLowerCase();
    if (seenVar.has(key)) return;
    seenVar.add(key);
    vars.push({ name, line: lineOf(source, index) });
  };

  const mustache = /\{\{\s*([A-Za-z_][\w]*)/g;
  let match: RegExpExecArray | null;
  while ((match = mustache.exec(source))) addVar(match[1], match.index);

  const forIn = /\{%-?\s*(?:for|if|elif)\s+(?:[A-Za-z_][\w]*\s+in\s+)?([A-Za-z_][\w]*)/g;
  while ((match = forIn.exec(source))) addVar(match[1], match.index);

  const erb = /<%[=-]?\s*@?([A-Za-z_][\w]*)/g;
  while ((match = erb.exec(source))) addVar(match[1], match.index);

  const includeRe =
    /\{%-?\s*(?:include|extends|import|from)\s+['"]([^'"]+)['"]|<%=\s*render\s+['"]([^'"]+)['"]/gi;
  while ((match = includeRe.exec(source))) {
    const name = normalizeTemplateName(match[1] || match[2] || '');
    if (name) includes.push(name);
  }

  return { file, vars: vars.slice(0, 24), includes: includes.slice(0, 8) };
}

function fileMatches(hitFile: string, want: string | undefined): boolean {
  if (!want) return true;
  const a = hitFile.replace(/\\/g, '/').toLowerCase();
  const b = want.replace(/\\/g, '/').toLowerCase().split('/').filter(Boolean).join('/');
  return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

function capNodes(nodes: InspectNode[], edges: InspectEdge[], maxNodes: number) {
  if (nodes.length <= maxNodes) return { nodes, edges, truncated: false };
  const keep = new Set(nodes.slice(0, maxNodes).map((node) => node.id));
  return {
    nodes: nodes.filter((node) => keep.has(node.id)),
    edges: edges.filter((edge) => keep.has(edge.source) && keep.has(edge.target)),
    truncated: true,
  };
}

/** Handler → template file → names the template reads from context. */
export function buildTemplateGraph(opts: {
  focus: string;
  file?: string;
  fileIsTemplate?: boolean;
  renders: RenderHit[];
  templates: TemplateDoc[];
  filesAnalyzed: number;
  maxNodes?: number;
}): InspectGraph {
  const focus = opts.focus.trim();
  const maxNodes = opts.maxNodes ?? 80;
  const nodesById = new Map<string, InspectNode>();
  const edges: InspectEdge[] = [];
  const addNode = (node: InspectNode) => {
    if (!nodesById.has(node.id)) nodesById.set(node.id, node);
  };
  const addEdge = (source: string, target: string) => {
    const id = `${source}->${target}`;
    if (edges.some((edge) => edge.id === id)) return;
    edges.push({ id, source, target });
  };

  const docsFor = (name: string) =>
    opts.templates.filter((doc) => templateFileMatches(doc.file, name)).slice(0, 4);

  const addTemplateBranch = (
    fromId: string,
    templateName: string,
    context: string[],
    fallbackFile: string,
    fallbackLine: number
  ) => {
    const docs = docsFor(templateName);
    const targets = docs.length
      ? docs
      : [{ file: fallbackFile, vars: [] as TemplateVar[], includes: [] as string[] }];
    for (const doc of targets) {
      const tmplId = `tmpl:${doc.file}:${templateName}`;
      addNode({
        id: tmplId,
        file: doc.file,
        name: templateName,
        line: fallbackLine,
        kind: 'template',
        depth: 1,
      });
      addEdge(fromId, tmplId);
      const preferred = context.length
        ? doc.vars.filter((item) => context.includes(item.name))
        : doc.vars;
      const shown = (preferred.length ? preferred : doc.vars).slice(0, 8);
      for (const item of shown) {
        const varId = `var:${doc.file}:${item.name}`;
        addNode({
          id: varId,
          file: doc.file,
          name: `{{ ${item.name} }}`,
          line: item.line,
          kind: 'callee',
          depth: 2,
        });
        addEdge(tmplId, varId);
      }
      for (const inc of doc.includes) {
        const incDocs = docsFor(inc);
        for (const nested of incDocs.slice(0, 2)) {
          const incId = `tmpl:${nested.file}:${inc}`;
          addNode({
            id: incId,
            file: nested.file,
            name: inc,
            line: 1,
            kind: 'callee',
            depth: 2,
          });
          addEdge(tmplId, incId);
        }
      }
    }
  };

  if (opts.fileIsTemplate && opts.file) {
    const doc = opts.templates.find((item) => fileMatches(item.file, opts.file));
    const tmplName = (opts.file.split('/').pop() || opts.file).toLowerCase();
    const focusId = `tmpl:${opts.file}:${tmplName}`;
    addNode({
      id: focusId,
      file: opts.file,
      name: tmplName,
      line: 1,
      kind: 'focus',
      depth: 0,
    });
    const renders = opts.renders.filter((hit) => templateFileMatches(opts.file || '', hit.template));
    for (const hit of renders.slice(0, 12)) {
      const id = `${hit.file}:${hit.line}:${hit.fn}`;
      addNode({
        id,
        file: hit.file,
        name: hit.fn === '<module>' ? hit.file.split('/').pop() || hit.fn : hit.fn,
        line: hit.line,
        kind: 'caller',
        depth: 1,
      });
      addEdge(id, focusId);
    }
    if (doc) {
      for (const item of doc.vars.slice(0, 8)) {
        const varId = `var:${doc.file}:${item.name}`;
        addNode({
          id: varId,
          file: doc.file,
          name: `{{ ${item.name} }}`,
          line: item.line,
          kind: 'callee',
          depth: 1,
        });
        addEdge(focusId, varId);
      }
    }
  } else {
    const seeds = opts.renders.filter((hit) => fileMatches(hit.file, opts.file));
    for (const hit of seeds) {
      const id = `${hit.file}:${hit.line}:${hit.fn}`;
      addNode({
        id,
        file: hit.file,
        name: hit.fn === '<module>' ? hit.file.split('/').pop() || hit.fn : hit.fn,
        line: hit.line,
        kind: 'focus',
        depth: 0,
      });
      addTemplateBranch(id, hit.template, hit.context, hit.file, hit.line);
    }
  }

  const nodes = [...nodesById.values()];
  const capped = capNodes(nodes, edges, maxNodes);
  return {
    focus,
    found: capped.nodes.length > 0,
    filesAnalyzed: opts.filesAnalyzed,
    truncated: capped.truncated,
    nodes: capped.nodes,
    edges: capped.edges,
  };
}

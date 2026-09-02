import { enclosingFunction, listFunctionsInSource } from './seedSymbol';
import type { InspectEdge, InspectGraph, InspectNode } from './types';
import type { HttpHit, HttpMethod, HttpRole } from './httpTypes';
import { normalizePath, pathsMatch } from './httpPath';
import { isExternalHttpLiteral, isNoiseFile } from './httpNoise';
import {
  isRailsRoutesFile,
  namedRoutesToHits,
  parseRailsRoutes,
} from './railsRoutes';
import {
  isLaravelRoutesFile,
  laravelRoutesToHits,
  parseLaravelRoutes,
} from './laravelRoutes';

export type { HttpHit, HttpMethod, HttpRole } from './httpTypes';
export { normalizePath, pathsMatch } from './httpPath';

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);


function asMethod(raw: string | undefined): HttpMethod {
  const method = (raw || '').toUpperCase();
  if (METHODS.has(method)) return method as HttpMethod;
  return 'ANY';
}

function methodsCompatible(a: HttpMethod, b: HttpMethod): boolean {
  return a === 'ANY' || b === 'ANY' || a === b;
}

function pushHit(
  hits: HttpHit[],
  file: string,
  line: number,
  role: HttpRole,
  method: HttpMethod,
  rawPath: string,
  fn: string
) {
  if (isExternalHttpLiteral(rawPath)) return;
  const path = normalizePath(rawPath);
  if (!path) return;
  hits.push({ method, path, file, line, fn, role });
}

const CLIENT_CALL =
  /\b(?:fetch|axios|ky|got|request|http(?:x)?)\s*\(\s*([`'"])([\s\S]*?)\1/gi;
const CLIENT_METHOD =
  /\b(?:axios|ky|got|api|http|client|this)\.(get|post|put|patch|delete)\s*\(\s*([`'"])([\s\S]*?)\2/gi;
const CLIENT_URL_FIELD = /\b(?:url|endpoint|path|href|action)\s*:\s*([`'"])([^`'"]+)\1/gi;
const HTML_ACTION = /\b(?:action|data-url|data-action-url|hx-get|hx-post|hx-put|hx-patch|hx-delete)\s*=\s*(['"])([^'"]+)\1/gi;

const SERVER_ROUTER =
  /\b(?:app|router|r|api|svc|mux)\.(get|post|put|patch|delete|all|use)\s*\(\s*([`'"])([^`'"]+)\2/gi;
const SERVER_ATTR =
  /@\w+\.(route|get|post|put|patch|delete|api_route)\s*\(\s*([`'"])([^`'"]+)\2([^)]*)\)/gi;
const SERVER_RAILS = /\b(get|post|put|patch|delete)\s+(['"])([^'"]+)\2/gi;
const SERVER_LARAVEL = /\bRoute::(get|post|put|patch|delete|any|match)\s*\(\s*(['"])([^'"]+)\2/gi;
const SERVER_DJANGO = /\b(?:path|re_path|url)\s*\(\s*(['"])([^'"]+)\1/gi;
const SERVER_AXUM = /\.route\s*\(\s*(['"])([^'"]+)\1/gi;

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function fnAt(source: string, line: number, preferNext = false): string {
  const defs = listFunctionsInSource(source);
  if (preferNext) {
    const next = defs.find((item) => item.line > line);
    if (next) return next.name;
  }
  return enclosingFunction(defs, line) || '<module>';
}

function methodNear(source: string, from: number, fallback: HttpMethod): HttpMethod {
  const window = source.slice(from, from + 220);
  const match = /\bmethod\s*:\s*['"](\w+)['"]/i.exec(window);
  if (match?.[1]) return asMethod(match[1]);
  return fallback;
}

function methodsFromArgs(args: string): HttpMethod {
  const listed = [...args.matchAll(/['"](GET|POST|PUT|PATCH|DELETE)['"]/gi)].map((m) =>
    asMethod(m[1])
  );
  if (listed.length === 1) return listed[0];
  if (listed.length > 1) return 'ANY';
  return 'ANY';
}

export function extractHttpHits(source: string, file: string): HttpHit[] {
  if (!source) return [];
  if (isRailsRoutesFile(file)) return namedRoutesToHits(parseRailsRoutes(source, file));
  if (isLaravelRoutesFile(file)) return laravelRoutesToHits(parseLaravelRoutes(source, file));
  if (isNoiseFile(file)) return [];
  const hits: HttpHit[] = [];
  const lower = file.replace(/\\/g, '/').toLowerCase();
  const looksServer =
    /routes?\.(rb|py|ts|js|php)$/.test(lower) ||
    /\/(routes|urls|router|controllers|handlers|api)\//.test(lower) ||
    /(?:^|\/)route\.ts$/.test(lower);

  const scan = (
    regex: RegExp,
    pick: (match: RegExpExecArray) => { role: HttpRole; method: HttpMethod; path: string } | null
  ) => {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(source))) {
      const parsed = pick(match);
      if (!parsed) continue;
      const line = lineOf(source, match.index);
      pushHit(
        hits,
        file,
        line,
        parsed.role,
        parsed.method,
        parsed.path,
        fnAt(source, line, parsed.role === 'server')
      );
    }
  };

  scan(CLIENT_CALL, (match) => ({
    role: 'client',
    method: methodNear(source, match.index + match[0].length, 'GET'),
    path: match[2] ?? '',
  }));
  scan(CLIENT_METHOD, (match) => ({
    role: 'client',
    method: asMethod(match[1]),
    path: match[3] ?? '',
  }));
  scan(CLIENT_URL_FIELD, (match) => ({
    role: looksServer ? 'server' : 'client',
    method: 'ANY',
    path: match[2] ?? '',
  }));
  scan(HTML_ACTION, (match) => {
    const attr = (match[0] || '').toLowerCase();
    let method: HttpMethod = 'GET';
    if (attr.includes('hx-post') || attr.includes('action=')) method = attr.includes('hx-post') ? 'POST' : 'ANY';
    if (attr.includes('hx-put')) method = 'PUT';
    if (attr.includes('hx-patch')) method = 'PATCH';
    if (attr.includes('hx-delete')) method = 'DELETE';
    return { role: 'client', method, path: match[2] ?? '' };
  });
  scan(SERVER_ROUTER, (match) => ({
    role: 'server',
    method: match[1]?.toLowerCase() === 'use' || match[1]?.toLowerCase() === 'all' ? 'ANY' : asMethod(match[1]),
    path: match[3] ?? '',
  }));
  scan(SERVER_ATTR, (match) => {
    const deco = (match[1] || '').toLowerCase();
    const fromDeco = deco === 'route' || deco === 'api_route' ? 'ANY' : asMethod(deco);
    const fromArgs = methodsFromArgs(match[4] ?? '');
    return {
      role: 'server',
      method: fromArgs !== 'ANY' ? fromArgs : fromDeco,
      path: match[3] ?? '',
    };
  });
  scan(SERVER_RAILS, (match) => ({
    role: 'server',
    method: asMethod(match[1]),
    path: match[3] ?? '',
  }));
  scan(SERVER_LARAVEL, (match) => ({
    role: 'server',
    method: asMethod(match[1]),
    path: match[3] ?? '',
  }));
  scan(SERVER_DJANGO, (match) => ({
    role: 'server',
    method: 'ANY',
    path: match[2] ?? '',
  }));
  scan(SERVER_AXUM, (match) => ({
    role: 'server',
    method: 'ANY',
    path: match[2] ?? '',
  }));

  const nextApi = nextApiPath(file);
  if (nextApi) {
    const exportRe = /\bexport\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/g;
    let match: RegExpExecArray | null;
    while ((match = exportRe.exec(source))) {
      const line = lineOf(source, match.index);
      hits.push({
        method: asMethod(match[1]),
        path: nextApi,
        file,
        line,
        fn: match[1] || '<module>',
        role: 'server',
      });
    }
  }

  return dedupeHits(hits);
}

function nextApiPath(file: string): string | undefined {
  const norm = file.replace(/\\/g, '/');
  const match = /(?:^|\/)app\/(api(?:\/.+))\/route\.(ts|js|tsx|jsx)$/i.exec(norm);
  if (!match?.[1]) return undefined;
  const raw = `/${match[1].replace(/\[([^\]]+)\]/g, ':param')}`;
  return normalizePath(raw);
}

function dedupeHits(hits: HttpHit[]): HttpHit[] {
  const seen = new Set<string>();
  const out: HttpHit[] = [];
  for (const hit of hits) {
    const key = `${hit.role}:${hit.method}:${hit.path}:${hit.file}:${hit.line}:${hit.fn}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(hit);
  }
  return out;
}

function fileMatches(hitFile: string, want: string | undefined): boolean {
  if (!want) return true;
  const a = hitFile.replace(/\\/g, '/').toLowerCase();
  const b = want.replace(/\\/g, '/').toLowerCase().split('/').filter(Boolean).join('/');
  return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

function fnId(hit: HttpHit): string {
  return `${hit.file}:${hit.line}:${hit.fn}`;
}

function capNodes(nodes: InspectNode[], edges: InspectEdge[], maxNodes: number): {
  nodes: InspectNode[];
  edges: InspectEdge[];
  truncated: boolean;
} {
  const rank = (kind: string) => (kind === 'api' ? 0 : kind === 'callee' ? 1 : 2);
  const ordered = [...nodes].sort(
    (a, b) => rank(a.kind) - rank(b.kind) || a.name.localeCompare(b.name) || a.file.localeCompare(b.file)
  );
  if (ordered.length <= maxNodes) return { nodes: ordered, edges, truncated: false };
  const keep = new Set(ordered.slice(0, maxNodes).map((node) => node.id));
  return {
    nodes: ordered.filter((node) => keep.has(node.id)),
    edges: edges.filter((edge) => keep.has(edge.source) && keep.has(edge.target)),
    truncated: true,
  };
}

function relatedHits(hits: HttpHit[], seeds: HttpHit[]): HttpHit[] {
  if (!seeds.length) return hits;
  return hits.filter((hit) =>
    seeds.some(
      (seed) => methodsCompatible(seed.method, hit.method) && pathsMatch(seed.path, hit.path)
    )
  );
}

/** Caller (left) → route (center) → handler (right). */
export function buildApiGraph(opts: {
  focus: string;
  file?: string;
  hits: HttpHit[];
  filesAnalyzed: number;
  maxNodes?: number;
}): InspectGraph {
  const focus = opts.focus.trim();
  const maxNodes = opts.maxNodes ?? 80;
  const seeds = opts.hits.filter((hit) => fileMatches(hit.file, opts.file));
  const hits = relatedHits(opts.hits, seeds);

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

  const keys = new Map<string, HttpHit[]>();
  for (const hit of hits) {
    const list = keys.get(hit.path) ?? [];
    list.push(hit);
    keys.set(hit.path, list);
  }

  for (const group of keys.values()) {
    const sample = group[0];
    if (!sample) continue;
    const methods = [...new Set(group.map((hit) => hit.method).filter((method) => method !== 'ANY'))];
    const apiNode: InspectNode = {
      id: `http:${sample.path}`,
      file: sample.file,
      name: `${methods.length ? `${methods.join('|')} ` : ''}${sample.path}`,
      line: sample.line,
      kind: 'api',
      depth: 0,
    };
    addNode(apiNode);
    for (const hit of group) {
      const node: InspectNode = {
        id: fnId(hit),
        file: hit.file,
        name: hit.fn === '<module>' ? hit.file.split('/').pop() || hit.fn : hit.fn,
        line: hit.line,
        kind: hit.role === 'client' ? 'caller' : 'callee',
        depth: 1,
      };
      addNode(node);
      if (hit.role === 'client') addEdge(node.id, apiNode.id);
      else addEdge(apiNode.id, node.id);
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

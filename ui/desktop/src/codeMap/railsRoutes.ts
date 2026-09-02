import type { HttpHit, HttpMethod } from './httpTypes';
import { normalizePath } from './httpPath';

export type NamedRoute = {
  helper: string;
  method: HttpMethod;
  path: string;
  fn: string;
  file: string;
  line: number;
};

type Frame = {
  pathPrefix: string;
  nameParts: string[];
  moduleParts: string[];
  collectionHelper: string;
  memberHelper: string;
};

const REST: { action: string; method: HttpMethod; on: 'collection' | 'member' | 'new' | 'edit' }[] = [
  { action: 'index', method: 'GET', on: 'collection' },
  { action: 'create', method: 'POST', on: 'collection' },
  { action: 'new', method: 'GET', on: 'new' },
  { action: 'show', method: 'GET', on: 'member' },
  { action: 'update', method: 'PATCH', on: 'member' },
  { action: 'update', method: 'PUT', on: 'member' },
  { action: 'destroy', method: 'DELETE', on: 'member' },
  { action: 'edit', method: 'GET', on: 'edit' },
];

const SINGULAR_REST = REST.filter((row) => row.action !== 'index');

export function pluralize(name: string): string {
  if (name.endsWith('s') && !name.endsWith('us')) return name;
  if (name.endsWith('y') && name.length > 1 && !/[aeiou]y$/i.test(name)) return `${name.slice(0, -1)}ies`;
  if (/(?:s|x|z|ch|sh)$/.test(name)) return `${name}es`;
  return `${name}s`;
}

export function singularize(name: string): string {
  if (name.endsWith('ies') && name.length > 4) return `${name.slice(0, -3)}y`;
  if (/(?:ches|shes|sses|xes|zes)$/.test(name) && name.length > 4) return name.slice(0, -2);
  if (name.endsWith('ses') && name.length > 4) return name.slice(0, -2);
  if (name.endsWith('s') && !name.endsWith('ss') && name.length > 1) return name.slice(0, -1);
  return name;
}

function joinPath(...parts: string[]): string {
  const raw = parts
    .join('/')
    .replace(/\/{2,}/g, '/')
    .replace(/\/$/, '');
  return raw.startsWith('/') ? raw : `/${raw}`;
}

function joinName(parts: string[]): string {
  return parts.filter(Boolean).join('_');
}

function stripComment(line: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      out += ch;
      if (ch === quote && line[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '#' && !/[a-zA-Z0-9_]/.test(line[i - 1] || '')) break;
    if (ch === "'" || ch === '"') quote = ch;
    out += ch;
  }
  return out.trim();
}

function symbolAfter(line: string, keyword: string): string | undefined {
  const match = line.match(new RegExp(`\\b${keyword}\\s+:([A-Za-z_][\\w/]*)`));
  return match?.[1]?.replace(/\//g, '_');
}

function optSymbol(line: string, key: string): string | undefined {
  return line.match(new RegExp(`\\b${key}:\\s*:([^,\\s\\]]+)`))?.[1];
}

function optString(line: string, key: string): string | undefined {
  return line.match(new RegExp(`\\b${key}:\\s*['"]([^'"]+)['"]`))?.[1];
}

function parseList(line: string, key: string): string[] | undefined {
  const percent = line.match(new RegExp(`\\b${key}:\\s*%i\\[([^\\]]+)\\]`));
  if (percent?.[1]) {
    return percent[1]
      .trim()
      .split(/\s+/)
      .map((item) => item.replace(/^:/, ''))
      .filter(Boolean);
  }
  const array = line.match(new RegExp(`\\b${key}:\\s*\\[([^\\]]+)\\]`));
  if (array?.[1]) {
    return [...array[1].matchAll(/:([A-Za-z_]\w*)/g)].map((item) => item[1] || '').filter(Boolean);
  }
  const one = optSymbol(line, key);
  if (one) return [one];
  return undefined;
}

function allowed(action: string, line: string): boolean {
  const only = parseList(line, 'only');
  const except = parseList(line, 'except');
  if (only) return only.includes(action);
  if (except) return !except.includes(action);
  return true;
}

function controllerName(modules: string[], resource: string, override?: string): string {
  if (override) return override.replace(/^\//, '');
  return [...modules, resource].filter(Boolean).join('/');
}

function helperFor(
  nameParts: string[],
  resource: string,
  singular: boolean,
  kind: 'collection' | 'member' | 'new' | 'edit'
): string {
  const word = singular ? resource : kind === 'collection' ? resource : singularize(resource);
  if (kind === 'new') return joinName(['new', ...nameParts, singularize(resource)]);
  if (kind === 'edit') return joinName(['edit', ...nameParts, singularize(resource)]);
  if (kind === 'collection') return joinName([...nameParts, resource]);
  return joinName([...nameParts, word]);
}

function emit(
  out: NamedRoute[],
  file: string,
  line: number,
  method: HttpMethod,
  path: string,
  helper: string,
  fn: string
) {
  const normalized = normalizePath(path) ?? (path === '/' ? undefined : normalizePath(`/${path}`));
  if (!normalized) return;
  out.push({ helper, method, path: normalized, fn, file, line });
}

function verbPath(line: string): { method: HttpMethod; path: string; to?: string; as?: string } | null {
  const named = line.match(
    /^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]\s*,\s*to:\s*['"]([^'"]+)['"]/i
  );
  if (named) {
    return {
      method: named[1]!.toUpperCase() as HttpMethod,
      path: named[2]!,
      to: named[3],
      as: optSymbol(line, 'as'),
    };
  }
  const rocket = line.match(
    /^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]\s*=>\s*['"]([^'"]+)['"]/i
  );
  if (rocket) {
    return {
      method: rocket[1]!.toUpperCase() as HttpMethod,
      path: rocket[2]!,
      to: rocket[3],
      as: optSymbol(line, 'as'),
    };
  }
  const plain = line.match(/^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]/i);
  if (plain) {
    return {
      method: plain[1]!.toUpperCase() as HttpMethod,
      path: plain[2]!,
      to: optString(line, 'to'),
      as: optSymbol(line, 'as'),
    };
  }
  const sym = line.match(/^\s*(get|post|put|patch|delete)\s+:([A-Za-z_]\w*)/i);
  if (sym) {
    return {
      method: sym[1]!.toUpperCase() as HttpMethod,
      path: sym[2]!,
      as: optSymbol(line, 'as'),
    };
  }
  return null;
}

function expandResource(
  out: NamedRoute[],
  file: string,
  line: number,
  frame: Frame,
  name: string,
  singular: boolean,
  optsLine: string
) {
  const override = optString(optsLine, 'controller');
  const ctrl = controllerName(
    frame.moduleParts,
    singular ? pluralize(name) : name,
    override
  );
  const collectionPath = joinPath(frame.pathPrefix, name);
  const memberPath = singular ? collectionPath : joinPath(collectionPath, ':param');
  const rows = singular ? SINGULAR_REST : REST;
  for (const row of rows) {
    if (!allowed(row.action, optsLine)) continue;
    let path = collectionPath;
    if (row.on === 'member' || row.on === 'edit') path = memberPath;
    if (row.on === 'new') path = joinPath(collectionPath, 'new');
    if (row.on === 'edit') path = joinPath(memberPath, 'edit');
    const helper = helperFor(frame.nameParts, name, singular, row.on);
    const actionCtrl = ctrl;
    emit(out, file, line, row.method, path, helper, `${actionCtrl}#${row.action}`);
  }
}

function childFrame(parent: Frame, name: string, singular: boolean, optsLine: string): Frame {
  const as = optSymbol(optsLine, 'as');
  const pathOpt = optString(optsLine, 'path');
  const collectionPath = joinPath(parent.pathPrefix, pathOpt || name);
  const memberPath = singular ? collectionPath : joinPath(collectionPath, ':param');
  return {
    pathPrefix: memberPath,
    nameParts: [...parent.nameParts, as || (singular ? name : singularize(name))],
    moduleParts: [...parent.moduleParts],
    collectionHelper: joinName([...parent.nameParts, as || name]),
    memberHelper: joinName([...parent.nameParts, as || (singular ? name : singularize(name))]),
  };
}

export function parseRailsRoutes(source: string, file: string): NamedRoute[] {
  const out: NamedRoute[] = [];
  const lines = source.split(/\r?\n/);
  const stack: Frame[] = [
    { pathPrefix: '', nameParts: [], moduleParts: [], collectionHelper: '', memberHelper: '' },
  ];
  let depth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i] || '');
    if (!line) continue;
    const frame = stack[stack.length - 1] ?? stack[0]!;
    const opens = /\bdo\b/.test(line) && !/\bend\b/.test(line);
    const lineNo = i + 1;

    if (/^\s*end\b/.test(line)) {
      if (stack.length > 1 && depth > 0) stack.pop();
      if (depth > 0) depth -= 1;
      continue;
    }

    if (/^\s*namespace\s+:/.test(line)) {
      const name = symbolAfter(line, 'namespace');
      if (name) {
        const next: Frame = {
          pathPrefix: joinPath(frame.pathPrefix, name),
          nameParts: [...frame.nameParts, name],
          moduleParts: [...frame.moduleParts, name],
          collectionHelper: joinName([...frame.nameParts, name]),
          memberHelper: joinName([...frame.nameParts, name]),
        };
        if (opens) {
          stack.push(next);
          depth += 1;
        }
      }
      continue;
    }

    if (/^\s*nested\b/.test(line)) {
      if (opens) {
        stack.push({ ...frame });
        depth += 1;
      }
      continue;
    }

    if (/^\s*scope\b/.test(line)) {
      const pathOpt = optString(line, 'path') || line.match(/scope\s+['"]([^'"]+)['"]/)?.[1];
      const as = optSymbol(line, 'as');
      const mod = optString(line, 'module');
      const next: Frame = {
        pathPrefix: pathOpt ? joinPath(frame.pathPrefix, pathOpt) : frame.pathPrefix,
        nameParts: as ? [...frame.nameParts, as] : frame.nameParts,
        moduleParts: mod ? [...frame.moduleParts, ...mod.split('/')] : frame.moduleParts,
        collectionHelper: as ? joinName([...frame.nameParts, as]) : frame.collectionHelper,
        memberHelper: as ? joinName([...frame.nameParts, as]) : frame.memberHelper,
      };
      if (opens) {
        stack.push(next);
        depth += 1;
      }
      continue;
    }

    const resources = line.match(/^\s*resources\s+:([A-Za-z_]\w*)/);
    if (resources?.[1]) {
      const name = resources[1];
      expandResource(out, file, lineNo, frame, name, false, line);
      if (opens) {
        stack.push(childFrame(frame, name, false, line));
        depth += 1;
      }
      continue;
    }

    const resource = line.match(/^\s*resource\s+:([A-Za-z_]\w*)/);
    if (resource?.[1]) {
      const name = resource[1];
      expandResource(out, file, lineNo, frame, name, true, line);
      if (opens) {
        stack.push(childFrame(frame, name, true, line));
        depth += 1;
      }
      continue;
    }

    if (/^\s*root\b/.test(line)) {
      const to = optString(line, 'to') || line.match(/root\s+['"]([^'"]+)['"]/)?.[1];
      emit(out, file, lineNo, 'GET', '/', 'root', to || 'application#index');
      continue;
    }

    if (/^\s*direct\b/.test(line)) continue;

    const verb = verbPath(line);
    if (verb) {
      const on = optSymbol(line, 'on');
      const collectionBase = frame.pathPrefix.replace(/\/:param$/, '');
      const memberBase = frame.pathPrefix;
      let path: string;
      if (verb.path.includes('/') || verb.path.startsWith(':') || verb.path.startsWith('@')) {
        path = joinPath(on === 'member' ? memberBase : collectionBase, verb.path);
      } else if (on === 'member') {
        path = joinPath(memberBase, verb.path);
      } else {
        path = joinPath(collectionBase, verb.path);
      }
      const action = verb.path.replace(/[^\w]/g, '_') || 'show';
      const to =
        verb.to ||
        `${controllerName(frame.moduleParts, frame.collectionHelper || 'application')}#${action}`;
      const helper =
        verb.as ||
        (on === 'collection' && frame.collectionHelper
          ? joinName([verb.path.replace(/[^\w]/g, '_'), frame.collectionHelper])
          : joinName([...frame.nameParts, verb.path.replace(/[^\w]/g, '_')]));
      emit(out, file, lineNo, verb.method, path, helper, to);
      continue;
    }

    if (opens) depth += 1;
  }

  return out;
}

export function namedRoutesToHits(routes: NamedRoute[]): HttpHit[] {
  return routes.map((route) => ({
    method: route.method,
    path: route.path,
    file: route.file,
    line: route.line,
    fn: route.fn,
    role: 'server' as const,
    helper: route.helper,
  }));
}

export function isRailsRoutesFile(file: string): boolean {
  return /(?:^|\/)config\/routes\.rb$/.test(file.replace(/\\/g, '/'));
}

export function bindRailsControllers(
  hits: HttpHit[],
  files: { rel: string; source: string }[]
): void {
  const controllers = files.filter((item) => /\/controllers\/.+\.rb$/.test(item.rel.replace(/\\/g, '/')));
  for (const hit of hits) {
    if (hit.role !== 'server' || !hit.fn.includes('#')) continue;
    const [rawCtrl, action] = hit.fn.split('#');
    if (!rawCtrl || !action) continue;
    const suffix = `${rawCtrl}_controller.rb`;
    const found = controllers.find((item) => {
      const rel = item.rel.replace(/\\/g, '/');
      return rel.endsWith(`/${suffix}`) || rel.endsWith(`/controllers/${suffix}`);
    });
    if (!found) continue;
    const match = found.source.match(new RegExp(`^\\s*def\\s+${action}\\b`, 'm'));
    hit.file = found.rel.replace(/\\/g, '/');
    if (match) {
      hit.line = found.source.slice(0, match.index).split(/\r?\n/).length;
    }
  }
}

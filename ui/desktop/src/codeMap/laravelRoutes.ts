import type { HttpHit, HttpMethod } from './httpTypes';
import { normalizePath } from './httpPath';
import type { NamedRoute } from './railsRoutes';

const REST: { action: string; method: HttpMethod; suffix: string; name: string }[] = [
  { action: 'index', method: 'GET', suffix: '', name: 'index' },
  { action: 'create', method: 'GET', suffix: '/create', name: 'create' },
  { action: 'store', method: 'POST', suffix: '', name: 'store' },
  { action: 'show', method: 'GET', suffix: '/:param', name: 'show' },
  { action: 'edit', method: 'GET', suffix: '/:param/edit', name: 'edit' },
  { action: 'update', method: 'PUT', suffix: '/:param', name: 'update' },
  { action: 'update', method: 'PATCH', suffix: '/:param', name: 'update' },
  { action: 'destroy', method: 'DELETE', suffix: '/:param', name: 'destroy' },
];

const API_REST = REST.filter((row) => row.name !== 'create' && row.name !== 'edit');

type Frame = { prefix: string; name: string };

function joinPath(prefix: string, extra: string): string {
  const raw = `${prefix}/${extra}`.replace(/\/{2,}/g, '/');
  return raw.startsWith('/') ? raw.replace(/\/$/, '') || '/' : `/${raw.replace(/\/$/, '')}`;
}

function joinName(prefix: string, extra: string): string {
  if (!extra) return prefix.replace(/\.$/, '');
  if (!prefix) return extra;
  return `${prefix.replace(/\.$/, '')}.${extra}`;
}

function controllerFn(raw: string, action: string): string {
  const named = raw.match(/([A-Za-z_][\w\\]*)Controller/);
  const short = (named?.[1] || raw.replace(/::class/, '').split('\\').pop() || 'Controller')
    .replace(/Controller$/, '')
    .replace(/\\/g, '/');
  return `${short}#${action}`;
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
  const normalized = normalizePath(path);
  if (!normalized) return;
  out.push({ helper, method, path: normalized, fn, file, line });
}

function parseOnly(line: string): Set<string> | null {
  const match = line.match(/->only\(\[([^\]]+)\]\)/) || line.match(/'only'\s*=>\s*\[([^\]]+)\]/);
  if (!match?.[1]) return null;
  return new Set(
    [...match[1].matchAll(/['"](\w+)['"]/g)].map((item) => item[1] || '').filter(Boolean)
  );
}

export function isLaravelRoutesFile(file: string): boolean {
  return /(?:^|\/)routes\/.+\.php$/.test(file.replace(/\\/g, '/'));
}

export function parseLaravelRoutes(source: string, file: string): NamedRoute[] {
  const out: NamedRoute[] = [];
  const stack: Frame[] = [{ prefix: '', name: '' }];
  const lines = source.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] || '';
    const frame = stack[stack.length - 1] ?? stack[0]!;
    const lineNo = i + 1;
    const opens = (line.match(/\{/g) || []).length;
    const closes = (line.match(/\}/g) || []).length;

    const prefix = line.match(/Route::prefix\(\s*['"]([^'"]+)['"]\)/);
    const name = line.match(/Route::name\(\s*['"]([^'"]+)['"]\)/);
    if ((prefix || name) && /->group\s*\(/.test(line)) {
      stack.push({
        prefix: prefix?.[1] ? joinPath(frame.prefix, prefix[1]) : frame.prefix,
        name: name?.[1] ? joinName(frame.name, name[1].replace(/\.$/, '')) : frame.name,
      });
      continue;
    }

    const resource =
      line.match(/Route::(apiResource|resource)\(\s*['"]([^'"]+)['"]\s*,\s*([^,)]+)/);
    if (resource) {
      const api = resource[1] === 'apiResource';
      const slug = resource[2] || '';
      const ctrl = resource[3] || '';
      const only = parseOnly(line);
      const rows = api ? API_REST : REST;
      for (const row of rows) {
        if (only && !only.has(row.name)) continue;
        emit(
          out,
          file,
          lineNo,
          row.method,
          joinPath(frame.prefix, slug + row.suffix),
          joinName(frame.name, `${slug.replace(/\//g, '.')}.${row.name}`),
          controllerFn(ctrl, row.action)
        );
      }
    }

    const verb = line.match(/Route::(get|post|put|patch|delete|any)\(\s*['"]([^'"]+)['"]/);
    if (verb) {
      const named = line.match(/->name\(\s*['"]([^'"]+)['"]\)/);
      const actionMatch = line.match(/['"](\w+)['"]\s*\]/) || line.match(/,\s*['"](\w+)['"]\s*\)/);
      const method = verb[1]?.toLowerCase() === 'any' ? 'ANY' : (verb[1]!.toUpperCase() as HttpMethod);
      emit(
        out,
        file,
        lineNo,
        method,
        joinPath(frame.prefix, verb[2] || ''),
        named?.[1]
          ? joinName(frame.name, named[1])
          : joinName(frame.name, (verb[2] || '').replace(/^\//, '').replace(/\//g, '.')),
        controllerFn(line, actionMatch?.[1] || 'handle')
      );
    }

    for (let n = 0; n < closes - opens; n++) {
      if (stack.length > 1) stack.pop();
    }
    if (opens > closes && !prefix && /function\s*\(/.test(line) && /Route::/.test(line)) {
      stack.push({ ...frame });
    }
  }

  return out;
}

export function laravelRoutesToHits(routes: NamedRoute[]): HttpHit[] {
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

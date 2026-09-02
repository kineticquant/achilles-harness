import type { HttpHit, HttpMethod } from './httpTypes';
import { isSkipHelper } from './httpNoise';
import type { NamedRoute } from './railsRoutes';
import { enclosingFunction, listFunctionsInSource } from './seedSymbol';

const HELPER_RE = /\b((?:new_|edit_|clear_)?[a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:path|url))\b/g;
const ROUTE_CALL = /\broute\(\s*['"]([^'"]+)['"]/g;
const LINK_HINT = /\b(?:link_to|redirect_to|turbo_frame_tag|src:)/;
const FORM_HINT = /\b(?:form_with|form_for|button_to|form_tag|html\.form|@submit|method:\s*:post)\b/;
const DELETE_HINT = /\bmethod:\s*:delete\b|\bmethod:\s*['"]delete['"]/i;

export type HelperRef = {
  helper: string;
  file: string;
  line: number;
  fn: string;
  method: HttpMethod;
};

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function methodFor(source: string, index: number): HttpMethod {
  const start = Math.max(0, index - 160);
  const window = source.slice(start, index + 120);
  if (DELETE_HINT.test(window)) return 'DELETE';
  if (FORM_HINT.test(window)) return 'POST';
  if (LINK_HINT.test(window)) return 'GET';
  if (/\bmethod:\s*:get\b/i.test(window)) return 'GET';
  if (/\bmethod:\s*:patch\b/i.test(window)) return 'PATCH';
  if (/\bmethod:\s*:put\b/i.test(window)) return 'PUT';
  return 'ANY';
}

export function extractNamedRouteRefs(source: string, file: string): HelperRef[] {
  const refs: HelperRef[] = [];
  const defs = listFunctionsInSource(source);
  const seen = new Set<string>();

  const push = (helper: string, index: number) => {
    const key = `${helper}:${index}`;
    if (seen.has(key)) return;
    seen.add(key);
    const line = lineOf(source, index);
    refs.push({
      helper,
      file,
      line,
      fn: enclosingFunction(defs, line) || file.split('/').pop() || '<template>',
      method: methodFor(source, index),
    });
  };

  HELPER_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = HELPER_RE.exec(source))) {
    const raw = match[1] || '';
    const helper = raw.replace(/_(?:path|url)$/, '');
    if (isSkipHelper(helper)) continue;
    push(helper, match.index);
  }

  ROUTE_CALL.lastIndex = 0;
  while ((match = ROUTE_CALL.exec(source))) {
    push(match[1] || '', match.index);
  }

  return refs;
}

export function resolveNamedRouteRefs(refs: HelperRef[], routes: NamedRoute[]): HttpHit[] {
  const byHelper = new Map<string, NamedRoute[]>();
  for (const route of routes) {
    const list = byHelper.get(route.helper) ?? [];
    list.push(route);
    byHelper.set(route.helper, list);
  }
  const hits: HttpHit[] = [];
  const seen = new Set<string>();
  for (const ref of refs) {
    const matches = byHelper.get(ref.helper);
    if (!matches?.length) continue;
    const pick =
      matches.find((route) => route.method === ref.method) ||
      (ref.method === 'ANY' ? matches[0] : matches.find((route) => route.method === 'GET')) ||
      matches[0];
    if (!pick) continue;
    const key = `${ref.file}:${ref.line}:${pick.path}:${ref.method}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hits.push({
      method: ref.method === 'ANY' ? pick.method : ref.method,
      path: pick.path,
      file: ref.file,
      line: ref.line,
      fn: ref.fn,
      role: 'client',
      helper: ref.helper,
    });
  }
  return hits;
}

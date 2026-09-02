const KEYWORDS = new Set([
  'if',
  'for',
  'while',
  'return',
  'switch',
  'match',
  'catch',
  'else',
  'fn',
  'def',
  'class',
  'function',
  'async',
  'await',
  'pub',
  'let',
  'const',
  'var',
  'use',
  'import',
  'from',
  'self',
  'this',
  'super',
  'crate',
  'mod',
  'impl',
  'struct',
  'enum',
  'trait',
  'type',
  'where',
  'new',
  'typeof',
  'sizeof',
  'yield',
  'with',
  'try',
  'throw',
  'in',
  'of',
  'as',
  'is',
  'extends',
  'implements',
  'interface',
  'default',
  'export',
  'static',
  'get',
  'set',
  'void',
  'null',
  'undefined',
  'true',
  'false',
]);

const CALLABLE_PATTERNS: RegExp[] = [
  /^\s*(?:static\s+)?(?:async\s+)?(?:get|set\s+)?([A-Za-z_][\w]*)\s*\([^;]*\)\s*\{/,
  /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)/,
  /\bdef\s+([A-Za-z_][\w]*)/,
  /\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_][\w]*)/,
  /\bfunc\s+(?:\([^)]*\)\s+)?([A-Za-z_][\w]*)/,
  /\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(?:async\s*)?(?:\(|function\b)/,
  /\b([A-Za-z_][\w]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_][\w]*)\s*=>/,
];

const CALL = /(?:(?:[A-Za-z_][\w]*::)*)([A-Za-z_][\w]*)\s*\(/g;
const IDENT = /[A-Za-z_][\w]*/g;

const PROPERTIES = new Set(
  [
    'innerHTML',
    'outerHTML',
    'innerhtml',
    'textContent',
    'innerText',
    'insertAdjacentHTML',
    'document',
    'window',
    'location',
    'cookie',
    'write',
    'writeln',
    'eval',
    'html',
    'href',
  ].map((name) => name.toLowerCase())
);

export function isPropertyLikeName(name: string): boolean {
  return PROPERTIES.has(name.trim().toLowerCase());
}

function clean(name: string | undefined): string | undefined {
  if (!name || KEYWORDS.has(name) || isPropertyLikeName(name) || name.length > 80) {
    return undefined;
  }
  return name;
}

function definitionOnLine(line: string): string | undefined {
  for (const pattern of CALLABLE_PATTERNS) {
    const match = pattern.exec(line);
    if (match?.[1]) return clean(match[1]);
  }
  return undefined;
}

function callOnLine(line: string): string | undefined {
  CALL.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CALL.exec(line))) {
    const name = clean(match[1]);
    if (name) return name;
  }
  return undefined;
}

function identOnLine(line: string): string | undefined {
  IDENT.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IDENT.exec(line))) {
    const name = clean(match[0]);
    if (name) return name;
  }
  return undefined;
}

export type ListedFn = { name: string; line: number };

export function listFunctionsInSource(source: string): ListedFn[] {
  if (!source) return [];
  const listed: ListedFn[] = [];
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const name = definitionOnLine(lines[i] ?? '');
    if (name) listed.push({ name, line: i + 1 });
  }
  return listed;
}

export function enclosingFunction(defs: ListedFn[], line: number): string | undefined {
  let best: ListedFn | undefined;
  for (const def of defs) {
    if (def.line <= line && (!best || def.line > best.line)) best = def;
  }
  return best?.name;
}

/** Best-effort symbol for the inspector: enclosing function, else a call on the line. */
export function seedSymbolFromSource(
  source: string,
  lineStart?: number | null,
  lineEnd?: number | null,
  opts?: { preferEnclosing?: boolean }
): string | undefined {
  if (!source) return undefined;
  const lines = source.split(/\r?\n/);
  const start = Math.min(Math.max(1, lineStart ?? 1), lines.length);
  const end = Math.min(Math.max(start, lineEnd ?? start), lines.length);

  if (opts?.preferEnclosing !== false) {
    const enc = enclosingFunction(listFunctionsInSource(source), start);
    if (enc) return enc;
  }

  for (let i = start; i <= end; i++) {
    const fromDef = definitionOnLine(lines[i - 1] ?? '');
    if (fromDef) return fromDef;
  }
  for (let i = start; i <= end; i++) {
    const fromCall = callOnLine(lines[i - 1] ?? '');
    if (fromCall) return fromCall;
  }
  for (let i = start; i <= end; i++) {
    const fromIdent = identOnLine(lines[i - 1] ?? '');
    if (fromIdent) return fromIdent;
  }
  return undefined;
}

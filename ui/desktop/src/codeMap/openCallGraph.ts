import { seedSymbolFromSource } from './seedSymbol';

export function treeRelPath(rel: string | undefined | null): string | undefined {
  if (!rel) return undefined;
  const slash = String(rel)
    .replace(/\\/g, '/')
    .replace(/\/+$/, '')
    .replace(/^git:[^/]+\//, '');
  return slash || undefined;
}

/** Directory to walk from a file path so callers in sibling files can show up. */
export function parentWalkPath(rel: string | undefined | null): string | undefined {
  const slash = treeRelPath(rel);
  if (!slash) return undefined;
  const cut = slash.lastIndexOf('/');
  if (cut <= 0) return undefined;
  return slash.slice(0, cut);
}

export function openCallGraphWindow(options: {
  workingDir: string;
  relPath?: string | null;
  source?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
}): void {
  if (!options.workingDir) return;
  const file = treeRelPath(options.relPath);
  const focus = seedSymbolFromSource(options.source ?? '', options.lineStart, options.lineEnd);
  void window.electron.openCodeMapWindow({
    workingDir: options.workingDir,
    path: parentWalkPath(options.relPath),
    file,
    line: options.lineStart ?? undefined,
    focus,
  });
}

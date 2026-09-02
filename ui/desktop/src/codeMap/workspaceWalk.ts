import fs from 'node:fs';
import path from 'node:path';
import { TEMPLATE_EXTS, isTemplatePath } from './templatePath';

export { TEMPLATE_EXTS, isTemplatePath };

export const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  'coverage',
  '.next',
  '.nuxt',
  '.venv',
  'venv',
  '__pycache__',
  '.turbo',
  'out',
  '.cache',
  'tmp',
  'temp',
  'Pods',
  'test',
  'tests',
  'spec',
  'specs',
  '__tests__',
  'fixtures',
]);

export const SOURCE_EXTS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.rb',
  '.py',
  '.go',
  '.rs',
  '.php',
  '.java',
  '.kt',
  '.vue',
  '.svelte',
]);

export const MAX_FILES = 10000;
export const MAX_BYTES = 400_000;
export const MAX_MAP_NODES = 2500;

export type ScanProgress = {
  current: number;
  total: number;
  file: string;
};

export function resolveWalkRoot(workingDir: string): string | null {
  if (!workingDir) return null;
  try {
    const stat = fs.statSync(workingDir);
    return stat.isDirectory() ? workingDir : path.dirname(workingDir);
  } catch {
    return null;
  }
}

export function yieldTick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

export function isContained(root: string, candidate: string): boolean {
  const base = path.resolve(root);
  const target = path.resolve(candidate);
  if (target === base) return true;
  const prefix = base.endsWith(path.sep) ? base : `${base}${path.sep}`;
  return target.startsWith(prefix);
}

export function relFile(root: string, file: string): string {
  return path.relative(root, file).replace(/\\/g, '/');
}

export function walkWorkspaceFiles(root: string, exts: Set<string>, maxFiles = MAX_FILES): string[] {
  const out: string[] = [];
  const stack = [root];
  while (stack.length && out.length < maxFiles) {
    const dir = stack.pop();
    if (!dir) break;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        stack.push(path.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name).toLowerCase();
      if (!exts.has(ext)) continue;
      if (entry.name.endsWith('.min.js')) continue;
      out.push(path.join(dir, entry.name));
      if (out.length >= maxFiles) break;
    }
  }
  return out;
}

export async function listCodeMapFiles(workingDir: string): Promise<string[]> {
  const root = resolveWalkRoot(workingDir);
  if (!root) return [];
  const exts = new Set([...SOURCE_EXTS, ...TEMPLATE_EXTS]);
  const absFiles = walkWorkspaceFiles(root, exts);
  const out: string[] = [];
  for (let i = 0; i < absFiles.length; i++) {
    out.push(relFile(root, absFiles[i] ?? ''));
    if (i % 200 === 0) await yieldTick();
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

export async function readWorkspaceSources(
  workingDir: string,
  onProgress?: (progress: ScanProgress) => void
): Promise<{ root: string; files: { rel: string; abs: string; source: string }[] }> {
  const root = resolveWalkRoot(workingDir);
  if (!root) return { root: workingDir, files: [] };
  const exts = new Set([...SOURCE_EXTS, ...TEMPLATE_EXTS]);
  const absFiles = walkWorkspaceFiles(root, exts);
  const files: { rel: string; abs: string; source: string }[] = [];
  for (let i = 0; i < absFiles.length; i++) {
    const abs = absFiles[i] ?? '';
    const rel = relFile(root, abs);
    onProgress?.({ current: i + 1, total: absFiles.length, file: rel });
    let stat: fs.Stats;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue;
    }
    if (stat.size > MAX_BYTES) continue;
    let source = '';
    try {
      source = fs.readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    files.push({ rel, abs, source });
    if (i % 2 === 0) await yieldTick();
  }
  return { root, files };
}

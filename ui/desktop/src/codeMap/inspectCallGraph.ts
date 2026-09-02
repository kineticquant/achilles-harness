import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { findGooseBinaryPath } from '../gooseServe';
import type { InspectCallGraphRequest, InspectCallGraphResult, InspectGraph } from './types';

const execFileAsync = promisify(execFile);

function isContained(root: string, candidate: string): boolean {
  const base = path.resolve(root);
  const target = path.resolve(candidate);
  if (target === base) return true;
  const prefix = base.endsWith(path.sep) ? base : `${base}${path.sep}`;
  return target.startsWith(prefix);
}

function parseGraph(stdout: string): InspectGraph {
  const text = stdout.trim();
  const parsed = JSON.parse(text) as InspectGraph;
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.nodes)) {
    throw new Error('Call graph response was not JSON.');
  }
  return parsed;
}

export async function inspectCallGraph(
  request: InspectCallGraphRequest,
  opts: { isPackaged: boolean; resourcesPath: string }
): Promise<InspectCallGraphResult> {
  const workingDir = String(request.workingDir || '').trim();
  const focus = String(request.focus || '').trim();
  if (!workingDir) {
    return { ok: false, error: 'Pick a workspace folder first.' };
  }
  if (!focus) {
    return { ok: false, error: 'Enter a function or type name to inspect.' };
  }
  if (!fs.existsSync(workingDir)) {
    return { ok: false, error: 'Workspace folder is missing on disk.' };
  }

  const rel = String(request.path || '').trim();
  const target = rel ? path.resolve(workingDir, rel) : path.resolve(workingDir);
  if (!isContained(workingDir, target)) {
    return { ok: false, error: 'Path must stay inside the workspace.' };
  }

  let goosePath: string;
  try {
    goosePath = findGooseBinaryPath(opts);
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : 'Could not find the goose CLI.',
    };
  }

  const maxDepth = Math.min(Math.max(request.maxDepth ?? 3, 1), 6);
  const followDepth = Math.min(Math.max(request.followDepth ?? 2, 0), 3);

  try {
    const { stdout } = await execFileAsync(
      goosePath,
      [
        'analyze',
        '--json',
        '--focus',
        focus,
        '--path',
        target,
        '--depth',
        String(maxDepth),
        '--follow',
        String(followDepth),
      ],
      {
        cwd: workingDir,
        windowsHide: true,
        timeout: 90_000,
        maxBuffer: 10 * 1024 * 1024,
      }
    );
    return { ok: true, graph: parseGraph(stdout) };
  } catch (error) {
    const err = error as { stderr?: string; message?: string };
    const detail = String(err.stderr || err.message || 'Call graph failed.').trim();
    return { ok: false, error: detail.split('\n').slice(-8).join('\n') };
  }
}

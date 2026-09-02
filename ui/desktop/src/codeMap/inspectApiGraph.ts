import fs from 'node:fs';
import path from 'node:path';
import { buildApiGraph, extractHttpHits, type HttpHit } from './httpRoutes';
import { isNoiseFile } from './httpNoise';
import { bindRailsControllers, isRailsRoutesFile, type NamedRoute } from './railsRoutes';
import { isLaravelRoutesFile } from './laravelRoutes';
import { extractNamedRouteRefs, resolveNamedRouteRefs } from './routeHelpers';
import {
  MAX_MAP_NODES,
  isContained,
  readWorkspaceSources,
  yieldTick,
  type ScanProgress,
} from './workspaceWalk';
import type { CodeMapProgress, InspectCallGraphRequest, InspectCallGraphResult } from './types';

/** Whole-workspace HTTP client ↔ server route map for the Call graph APIs tab. */
export async function inspectApiGraph(
  request: InspectCallGraphRequest,
  onProgress?: (progress: CodeMapProgress) => void
): Promise<InspectCallGraphResult> {
  const workingDir = String(request.workingDir || '').trim();
  const file = String(request.path || request.file || '').trim();
  if (!workingDir) {
    return { ok: false, error: 'Pick a workspace folder first.' };
  }
  if (!fs.existsSync(workingDir)) {
    return { ok: false, error: 'Workspace folder is missing on disk.' };
  }

  const { files } = await readWorkspaceSources(workingDir, onProgress as ((p: ScanProgress) => void) | undefined);
  const rels = files.map((item) => item.rel);
  const hits: HttpHit[] = [];
  const named: NamedRoute[] = [];
  const focusNorm = file.replace(/\\/g, '/').toLowerCase();
  const keepNoise = (rel: string) => {
    if (!focusNorm) return false;
    const a = rel.replace(/\\/g, '/').toLowerCase();
    return a === focusNorm || a.endsWith(`/${focusNorm}`) || focusNorm.endsWith(`/${a}`);
  };

  for (let i = 0; i < files.length; i++) {
    const item = files[i];
    if (!item) continue;
    if (isNoiseFile(item.rel) && !keepNoise(item.rel)) continue;
    const part = extractHttpHits(item.source, item.rel);
    hits.push(...part);
    if (isRailsRoutesFile(item.rel) || isLaravelRoutesFile(item.rel)) {
      for (const hit of part) {
        if (hit.helper) {
          named.push({
            helper: hit.helper,
            method: hit.method,
            path: hit.path,
            fn: hit.fn,
            file: hit.file,
            line: hit.line,
          });
        }
      }
    }
    if (i % 4 === 0) {
      onProgress?.({ current: i + 1, total: files.length, file: item.rel });
      await yieldTick();
    }
  }

  // Views may be walked before routes.rb; resolve helpers against the full table.
  const fromViews: HttpHit[] = [];
  for (const item of files) {
    if (isNoiseFile(item.rel) && !keepNoise(item.rel)) continue;
    if (isRailsRoutesFile(item.rel) || isLaravelRoutesFile(item.rel)) continue;
    fromViews.push(...resolveNamedRouteRefs(extractNamedRouteRefs(item.source, item.rel), named));
  }
  hits.push(...fromViews);
  bindRailsControllers(hits, files);

  const graph = buildApiGraph({
    focus: file ? file.split(/[/\\]/).pop() || file : 'workspace',
    file: file || undefined,
    hits,
    filesAnalyzed: files.length,
    maxNodes: MAX_MAP_NODES,
  });
  return { ok: true, graph, files: rels };
}

export async function inspectApiGraphSafe(
  request: InspectCallGraphRequest & { file?: string },
  onProgress?: (progress: CodeMapProgress) => void
): Promise<InspectCallGraphResult> {
  const workingDir = String(request.workingDir || '').trim();
  const rel = String(request.file || request.path || '').trim();
  if (rel && workingDir) {
    const target = path.resolve(workingDir, rel);
    if (!isContained(workingDir, target)) {
      return { ok: false, error: 'Path must stay inside the workspace.' };
    }
  }
  return inspectApiGraph(
    {
      workingDir: request.workingDir,
      focus: request.focus,
      path: request.file || request.path,
      file: request.file,
    },
    onProgress
  );
}

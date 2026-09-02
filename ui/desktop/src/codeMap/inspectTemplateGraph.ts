import path from 'node:path';
import fs from 'node:fs';
import { TEMPLATE_EXTS, isTemplatePath } from './templatePath';
import {
  SOURCE_EXTS,
  MAX_MAP_NODES,
  isContained,
  readWorkspaceSources,
  yieldTick,
  type ScanProgress,
} from './workspaceWalk';
import {
  buildTemplateGraph,
  extractRenderHits,
  extractTemplateDoc,
  type RenderHit,
  type TemplateDoc,
} from './templateRoutes';
import type { CodeMapProgress, InspectCallGraphRequest, InspectCallGraphResult } from './types';

export async function inspectTemplateGraph(
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
  const renders: RenderHit[] = [];
  const templates: TemplateDoc[] = [];
  for (let i = 0; i < files.length; i++) {
    const item = files[i];
    if (!item) continue;
    const ext = path.extname(item.abs).toLowerCase();
    if (SOURCE_EXTS.has(ext)) {
      renders.push(...extractRenderHits(item.source, item.rel));
    }
    if (isTemplatePath(item.rel) || TEMPLATE_EXTS.has(ext)) {
      templates.push(extractTemplateDoc(item.source, item.rel));
    }
    if (i % 4 === 0) {
      onProgress?.({ current: i + 1, total: files.length, file: item.rel });
      await yieldTick();
    }
  }

  const graph = buildTemplateGraph({
    focus: file ? file.split('/').pop() || file : 'workspace',
    file: file || undefined,
    fileIsTemplate: Boolean(file && isTemplatePath(file)),
    renders,
    templates,
    filesAnalyzed: files.length,
    maxNodes: MAX_MAP_NODES,
  });
  return { ok: true, graph, files: rels };
}

export async function inspectTemplateGraphSafe(
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
  return inspectTemplateGraph(
    {
      workingDir: request.workingDir,
      focus: request.focus,
      path: request.file || request.path,
      file: request.file,
    },
    onProgress
  );
}

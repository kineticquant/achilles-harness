import { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import { X } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { cn } from '../../utils';
import { relativeToWorkspace } from '../tools/toolsCatalog';
import { getInitialWorkingDir } from '../../utils/workingDir';
import { errorMessage } from '../../utils/conversionUtils';
import { resolveFindingPath } from '../findings/filePreview';
import {
  enclosingFunction,
  isPropertyLikeName,
  listFunctionsInSource,
  seedSymbolFromSource,
  type ListedFn,
} from '../../codeMap/seedSymbol';
import { pinGraphToFileSymbol } from '../../codeMap/pinGraph';
import type { InspectGraph } from '../../codeMap/types';
import CodeMapCanvas from './CodeMapCanvas';
import CodeMapFileSelect from './CodeMapFileSelect';

type MapMode = 'functions' | 'apis' | 'templates';

const i18n = defineMessages({
  title: { id: 'codeMap.title', defaultMessage: 'Call graph' },
  close: { id: 'codeMap.close', defaultMessage: 'Close' },
  intro: {
    id: 'codeMap.intro',
    defaultMessage:
      'Callers on the left, callees on the right. Opened from a finding, this maps the enclosing function.',
  },
  focus: { id: 'codeMap.focus', defaultMessage: 'Function' },
  fileLabel: { id: 'codeMap.fileLabel', defaultMessage: 'Filter' },
  fileSearch: {
    id: 'codeMap.fileSearch',
    defaultMessage: 'Type to search files…',
  },
  allFiles: {
    id: 'codeMap.allFiles',
    defaultMessage: 'Entire workspace',
  },
  focusPlaceholder: {
    id: 'codeMap.focusPlaceholder',
    defaultMessage: 'Or click a name below',
  },
  path: { id: 'codeMap.path', defaultMessage: 'Folder' },
  pathPlaceholder: {
    id: 'codeMap.pathPlaceholder',
    defaultMessage: 'Optional',
  },
  browse: { id: 'codeMap.browse', defaultMessage: 'Browse' },
  map: { id: 'codeMap.map', defaultMessage: 'Map' },
  mapping: { id: 'codeMap.mapping', defaultMessage: 'Mapping…' },
  scanning: {
    id: 'codeMap.scanning',
    defaultMessage: 'Scanning {current} of {total} · {file}',
  },
  follow: { id: 'codeMap.follow', defaultMessage: 'Hops' },
  followHelp: {
    id: 'codeMap.followHelp',
    defaultMessage: 'How far to follow callers and callees',
  },
  tabFunctions: { id: 'codeMap.tabFunctions', defaultMessage: 'Functions' },
  tabApis: { id: 'codeMap.tabApis', defaultMessage: 'APIs' },
  tabTemplates: { id: 'codeMap.tabTemplates', defaultMessage: 'Templates' },
  apiHint: {
    id: 'codeMap.apiHint',
    defaultMessage:
      'Caller → route → handler. Rails/Hotwire and Laravel resources, plus fetch/axios and string routes. Tests and third-party URLs are skipped.',
  },
  apiEmptyTitle: {
    id: 'codeMap.apiEmptyTitle',
    defaultMessage: 'No HTTP paths found',
  },
  apiEmpty: {
    id: 'codeMap.apiEmpty',
    defaultMessage:
      'Leave Entire workspace and click Map. Expands Rails/Laravel resources, Hotwire/Blade helpers (room_messages_path, route(\'…\')), and fetch/axios. Big repos just take longer.',
  },
  mappingWorkspace: {
    id: 'codeMap.mappingWorkspace',
    defaultMessage: 'Mapping the workspace file by file…',
  },
  tplHint: {
    id: 'codeMap.tplHint',
    defaultMessage:
      'Render → template → variables, across the workspace. Jinja, Django, ERB, EJS, Twig, Handlebars, Laravel, Rails, and similar — not Jinja only.',
  },
  tplEmptyTitle: {
    id: 'codeMap.tplEmptyTitle',
    defaultMessage: 'No templates found in this workspace',
  },
  tplEmpty: {
    id: 'codeMap.tplEmpty',
    defaultMessage:
      'Leave Entire workspace and click Map. Looks for render_template, res.render, Rails render, view(), Django render, and the template files they open. Type to filter to one file.',
  },
  inFile: { id: 'codeMap.inFile', defaultMessage: 'Functions in {file}' },
  hint: {
    id: 'codeMap.hint',
    defaultMessage: 'Click a box to open that line. Double-click to map that function instead.',
  },
  emptyTitle: {
    id: 'codeMap.emptyTitle',
    defaultMessage: 'Pick a function in this file',
  },
  empty: {
    id: 'codeMap.empty',
    defaultMessage: 'Click a name above. Typing is optional.',
  },
  notFound: {
    id: 'codeMap.notFound',
    defaultMessage: 'Nothing named “{name}” in these files.',
  },
  propertyHint: {
    id: 'codeMap.propertyHint',
    defaultMessage: '“{name}” is not a function. Pick a method from the list.',
  },
  truncated: {
    id: 'codeMap.truncated',
    defaultMessage: 'Stopped at {count} nodes so the map stays readable.',
  },
  stats: {
    id: 'codeMap.stats',
    defaultMessage: '{files} files · {nodes} functions',
  },
  noDir: {
    id: 'codeMap.noDir',
    defaultMessage: 'Pick a workspace folder in Chat or Scan first.',
  },
});

function param(params: URLSearchParams, key: string): string {
  return params.get(key) ?? '';
}

function mergeFiles(prev: string[], extra: string[]): string[] {
  const seen = new Set(prev);
  const out = [...prev];
  for (const item of extra) {
    if (!item || seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

export default function CodeMapWindow() {
  const intl = useIntl();
  const [params] = useSearchParams();
  const workingDir = param(params, 'workingDir') || getInitialWorkingDir();
  const initialPath = param(params, 'path');
  const file = param(params, 'file');
  const line = Number(param(params, 'line')) || 0;
  const initialFocus = param(params, 'focus');

  const [focus, setFocus] = useState(initialFocus);
  const [mapFile, setMapFile] = useState('');
  const [workspaceFiles, setWorkspaceFiles] = useState<string[]>(() => (file ? [file] : []));
  const [relPath, setRelPath] = useState(initialPath);
  const [followDepth, setFollowDepth] = useState(2);
  const [mode, setMode] = useState<MapMode>('functions');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [graph, setGraph] = useState<InspectGraph | null>(null);
  const [listed, setListed] = useState<ListedFn[]>([]);
  const [scan, setScan] = useState<{ current: number; total: number; file: string } | null>(null);

  const runMap = useCallback(
    async (
      symbol: string,
      atLine?: number,
      pinFile?: string,
      nextMode: MapMode = mode,
      targetFile = mapFile
    ) => {
      const name = symbol.trim();
      if (!workingDir) {
        setError(intl.formatMessage(i18n.noDir));
        return;
      }
      const fileMode = nextMode === 'apis' || nextMode === 'templates';
      if (!fileMode) {
        if (!name) return;
        if (isPropertyLikeName(name)) {
          setGraph(null);
          setError(intl.formatMessage(i18n.propertyHint, { name }));
          return;
        }
        setFocus(name);
      }
      setBusy(true);
      setError(null);
      setScan(null);
      try {
        if (nextMode === 'apis') {
          const result = await window.electron.inspectApiGraph({
            workingDir,
            focus: targetFile.split('/').pop() || 'workspace',
            file: targetFile || undefined,
          });
          if (!result.ok) {
            setGraph(null);
            setError(result.error);
            return;
          }
          if (result.files?.length) {
            setWorkspaceFiles((prev) => mergeFiles(prev, result.files ?? []));
          }
          setGraph(result.graph);
          return;
        }
        if (nextMode === 'templates') {
          const result = await window.electron.inspectTemplateGraph({
            workingDir,
            focus: targetFile.split('/').pop() || 'workspace',
            file: targetFile || undefined,
          });
          if (!result.ok) {
            setGraph(null);
            setError(result.error);
            return;
          }
          if (result.files?.length) {
            setWorkspaceFiles((prev) => mergeFiles(prev, result.files ?? []));
          }
          setGraph(result.graph);
          return;
        }
        const result = await window.electron.inspectCallGraph({
          workingDir,
          focus: name,
          path: relPath.trim() || undefined,
          followDepth,
          maxDepth: 3,
        });
        if (!result.ok) {
          setGraph(null);
          setError(result.error);
          return;
        }
        const pinned = pinGraphToFileSymbol(
          result.graph,
          pinFile ?? (targetFile || file),
          name,
          atLine
        );
        setGraph(pinned);
        if (!pinned.found) {
          setError(intl.formatMessage(i18n.notFound, { name }));
        }
      } catch (err) {
        setGraph(null);
        setError(errorMessage(err, intl.formatMessage(i18n.map)));
      } finally {
        setBusy(false);
        setScan(null);
      }
    },
    [file, followDepth, intl, mapFile, mode, relPath, workingDir]
  );

  useEffect(() => {
    if (!workingDir) return;
    let cancelled = false;
    const load = window.electron.listCodeMapFiles
      ? window.electron.listCodeMapFiles(workingDir)
      : Promise.resolve([]);
    void load
      .then((listed) => {
        if (!cancelled && Array.isArray(listed)) {
          setWorkspaceFiles((prev) => mergeFiles(prev, listed));
        }
      })
      .catch(() => {
        if (!cancelled) setWorkspaceFiles([]);
      });
    return () => {
      cancelled = true;
    };
  }, [workingDir]);

  useEffect(() => {
    if (!window.electron.onCodeMapProgress) return undefined;
    return window.electron.onCodeMapProgress((progress) => setScan(progress));
  }, []);

  useEffect(() => {
    let cancelled = false;
    setRelPath(initialPath);
    setMapFile('');
    setGraph(null);
    setListed([]);
    setError(null);

    const boot = async () => {
      let defs: ListedFn[] = [];
      let source = '';
      if (workingDir && file) {
        const abs = resolveFindingPath(workingDir, file);
        const read = await window.electron.readFile(abs);
        if (cancelled) return;
        if (read.found && read.file) {
          source = read.file;
          defs = listFunctionsInSource(source);
          setListed(defs);
        } else {
          setError(read.error || abs);
        }
      }
      const fromFile =
        (line > 0 ? enclosingFunction(defs, line) : undefined) ||
        seedSymbolFromSource(source, line || undefined) ||
        initialFocus.trim();
      const bootMode: MapMode = 'functions';
      const name = fromFile && !isPropertyLikeName(fromFile) ? fromFile : '';
      if (name) {
        const at = defs.find((item) => item.name === name)?.line;
        setFocus(name);
        await runMap(name, at, undefined, bootMode);
      } else {
        setFocus(initialFocus);
      }
    };
    void boot();
    return () => {
      cancelled = true;
    };
    // Intentionally not depending on runMap: hops/folder edits shouldn't reload the file.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workingDir, file, line, initialPath, initialFocus]);

  const pickPath = async () => {
    const selected = await window.electron.selectFileOrDirectory(workingDir || undefined);
    if (!selected) return;
    setRelPath(relativeToWorkspace(workingDir, selected));
  };

  const pickMapFile = async () => {
    const selected = await window.electron.selectFileOrDirectory(workingDir || undefined);
    if (!selected || !workingDir) return;
    const rel = relativeToWorkspace(workingDir, selected);
    if (!rel || rel === selected.replace(/\\/g, '/')) {
      setMapFile('');
      void runMap('', undefined, undefined, mode, '');
      return;
    }
    setWorkspaceFiles((prev) => mergeFiles(prev, [rel]));
    setMapFile(rel);
    void runMap('', undefined, undefined, mode, rel);
  };

  const openNode = (path: string, at: number) => {
    if (!workingDir || !path) return;
    void window.electron.openFilePreviewWindow({
      workingDir,
      path,
      lineStart: at,
      lineEnd: at,
    });
  };

  const fileBase = file.split('/').pop() || file;

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background-primary">
      <header
        className={`relative z-[60] flex h-9 shrink-0 items-center gap-2 border-b border-border-primary bg-background-secondary px-2 [-webkit-app-region:drag] ${
          window.electron?.platform === 'darwin' ? 'pl-[72px]' : ''
        }`}
      >
        <button
          type="button"
          onClick={() => window.electron.closeWindow()}
          className="no-drag inline-flex size-7 shrink-0 items-center justify-center rounded-md text-text-secondary hover:bg-background-tertiary hover:text-text-primary"
          aria-label={intl.formatMessage(i18n.close)}
        >
          <X className="size-3.5" />
        </button>
        <span className="text-sm font-medium text-text-primary">
          {intl.formatMessage(i18n.title)}
        </span>
        <div className="no-drag ml-2 flex rounded-md border border-border-primary p-0.5">
          {(['functions', 'apis', 'templates'] as const).map((item) => (
            <button
              key={item}
              type="button"
              className={cn(
                'h-6 rounded px-2 text-xs',
                mode === item
                  ? 'bg-background-inverse text-text-inverse'
                  : 'text-text-secondary hover:text-text-primary'
              )}
              onClick={() => {
                setMode(item);
                setGraph(null);
                setError(null);
                if (item === 'functions') {
                  if (focus.trim()) void runMap(focus, undefined, undefined, item);
                } else {
                  void runMap('', undefined, undefined, item);
                }
              }}
            >
              {intl.formatMessage(
                item === 'functions'
                  ? i18n.tabFunctions
                  : item === 'apis'
                    ? i18n.tabApis
                    : i18n.tabTemplates
              )}
            </button>
          ))}
        </div>
      </header>

      <div className="no-drag shrink-0 border-b border-border-primary bg-background-secondary px-4 py-3">
        <form
          className="grid w-full grid-cols-[minmax(0,1fr)_7.5rem] items-end gap-x-2 gap-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (mode === 'functions') void runMap(focus);
            else void runMap('', undefined, undefined, mode);
          }}
        >
          {mode === 'functions' ? (
            <label className="flex min-w-0 flex-col gap-1.5 text-xs text-text-secondary">
              {intl.formatMessage(i18n.focus)}
              <Input
                value={focus}
                onChange={(event) => setFocus(event.target.value)}
                placeholder={intl.formatMessage(i18n.focusPlaceholder)}
                spellCheck={false}
                className="h-9 font-mono"
                autoComplete="off"
              />
            </label>
          ) : (
            <label className="flex min-w-0 flex-col gap-1.5 text-xs text-text-secondary">
              {intl.formatMessage(i18n.fileLabel)}
              <span className="flex gap-2">
                <span className="min-w-0 flex-1">
                  <CodeMapFileSelect
                    files={workspaceFiles}
                    value={mapFile}
                    placeholder={intl.formatMessage(i18n.fileSearch)}
                    allLabel={intl.formatMessage(i18n.allFiles)}
                    onChange={(next) => {
                      setMapFile(next);
                      void runMap('', undefined, undefined, mode, next);
                    }}
                  />
                </span>
                <Button
                  type="button"
                  variant="outline"
                  className="h-9 shrink-0"
                  onClick={() => void pickMapFile()}
                >
                  {intl.formatMessage(i18n.browse)}
                </Button>
              </span>
            </label>
          )}
          <Button
            type="submit"
            disabled={busy || !workingDir}
            className="h-9 w-full px-0"
          >
            {busy ? intl.formatMessage(i18n.mapping) : intl.formatMessage(i18n.map)}
          </Button>
          {mode === 'functions' ? (
            <>
          <label className="flex min-w-0 flex-col gap-1.5 text-xs text-text-secondary">
            {intl.formatMessage(i18n.path)}
            <span className="flex gap-2">
              <Input
                value={relPath}
                onChange={(event) => setRelPath(event.target.value)}
                placeholder={intl.formatMessage(i18n.pathPlaceholder)}
                spellCheck={false}
                className="h-9 min-w-0 flex-1 font-mono"
              />
              <Button type="button" variant="outline" className="h-9 shrink-0" onClick={() => void pickPath()}>
                {intl.formatMessage(i18n.browse)}
              </Button>
            </span>
          </label>
          <label
            className="flex min-w-0 flex-col gap-1.5 text-xs text-text-secondary"
            title={intl.formatMessage(i18n.followHelp)}
          >
            {intl.formatMessage(i18n.follow)}
            <select
              value={followDepth}
              onChange={(event) => setFollowDepth(Number(event.target.value))}
              aria-label={intl.formatMessage(i18n.followHelp)}
              className="h-9 w-full rounded-md border bg-background-primary px-2 text-sm text-text-primary"
            >
              <option value={1}>1</option>
              <option value={2}>2</option>
              <option value={3}>3</option>
            </select>
          </label>
            </>
          ) : (
            <p className="col-span-2 text-xs text-text-tertiary">
              {intl.formatMessage(mode === 'templates' ? i18n.tplEmpty : i18n.apiEmpty)}
            </p>
          )}
        </form>

        {scan && scan.total > 0 ? (
          <div className="mt-3">
            <div className="h-1.5 overflow-hidden rounded-full bg-background-tertiary">
              <div
                className="h-full bg-text-info transition-[width] duration-150"
                style={{ width: `${Math.min(100, Math.round((scan.current / scan.total) * 100))}%` }}
              />
            </div>
            <p className="mt-1.5 truncate font-mono text-[11px] text-text-tertiary">
              {intl.formatMessage(i18n.scanning, {
                current: scan.current,
                total: scan.total,
                file: scan.file,
              })}
            </p>
          </div>
        ) : null}

        {mode === 'functions' && listed.length > 0 ? (
          <div className="mt-3">
            <p className="mb-1.5 text-xs text-text-tertiary">
              {intl.formatMessage(i18n.inFile, { file: fileBase })}
            </p>
            <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
              {listed.map((item) => (
                <button
                  key={`${item.name}:${item.line}`}
                  type="button"
                  onClick={() => void runMap(item.name, item.line)}
                  className={cn(
                    'h-7 rounded-md border px-2 font-mono text-xs',
                    item.name === focus
                      ? 'border-transparent bg-background-inverse text-text-inverse'
                      : 'border-border-primary text-text-secondary hover:bg-background-tertiary hover:text-text-primary'
                  )}
                >
                  {item.name}
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </div>

      {graph?.found ? (
        <p className="shrink-0 px-4 py-2 text-xs text-text-tertiary">
          {intl.formatMessage(
            mode === 'apis' ? i18n.apiHint : mode === 'templates' ? i18n.tplHint : i18n.hint
          )}
          {` · ${intl.formatMessage(i18n.stats, {
            files: graph.filesAnalyzed,
            nodes: graph.nodes.length,
          })}`}
          {graph.truncated
            ? ` · ${intl.formatMessage(i18n.truncated, { count: graph.nodes.length })}`
            : null}
        </p>
      ) : null}

      {error && !busy ? (
        <p role="alert" className="shrink-0 px-4 py-2 text-sm leading-relaxed text-text-danger">
          {error}
        </p>
      ) : null}

      <div className="min-h-0 flex-1">
        {busy && !graph?.found && mode !== 'functions' ? (
          <div className="px-4 py-8">
            <p className="text-base text-text-primary">
              {intl.formatMessage(i18n.mappingWorkspace)}
            </p>
            <p className="mt-2 text-sm text-text-secondary">
              {intl.formatMessage(mode === 'templates' ? i18n.tplEmpty : i18n.apiEmpty)}
            </p>
          </div>
        ) : graph?.found ? (
          <CodeMapCanvas
            graph={graph}
            onOpenNode={openNode}
            onFocusNode={(name, nodeFile, nodeLine) => {
              setMode('functions');
              void runMap(name, nodeLine, nodeFile, 'functions');
            }}
          />
        ) : (
          <div className="px-4 py-8">
            <p className="text-base text-text-primary">
              {intl.formatMessage(
                !workingDir
                  ? i18n.noDir
                  : mode === 'apis'
                    ? i18n.apiEmptyTitle
                    : mode === 'templates'
                      ? i18n.tplEmptyTitle
                      : i18n.emptyTitle
              )}
            </p>
            {workingDir ? (
              <p className="mt-2 text-sm text-text-secondary">
                {intl.formatMessage(
                  mode === 'apis' ? i18n.apiEmpty : mode === 'templates' ? i18n.tplEmpty : i18n.empty
                )}
              </p>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}

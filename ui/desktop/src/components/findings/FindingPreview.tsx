import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { openCallGraphWindow } from '../../codeMap/openCallGraph';
import { GitFork, SquareArrowOutUpRight, X } from 'lucide-react';
import { toast } from 'react-toastify';
import { defineMessages, useIntl } from '../../i18n';
import { cn } from '../../utils';
import {
  fileBasename,
  languageFromPath,
  previewFromRead,
  resolveFindingPath,
  type PreviewLoad,
} from './filePreview';

const FindingMonaco = lazy(() => import('./FindingMonaco'));

const SAVE_MS = 400;

const i18n = defineMessages({
  region: {
    id: 'findingsView.previewRegion',
    defaultMessage: 'File preview',
  },
  close: {
    id: 'findingsView.previewClose',
    defaultMessage: 'Close preview',
  },
  missing: {
    id: 'findingsView.previewMissing',
    defaultMessage: 'This file is not on disk. It may have been moved or deleted.',
  },
  tooLarge: {
    id: 'findingsView.previewTooLarge',
    defaultMessage: 'This file is too large to preview here.',
  },
  binary: {
    id: 'findingsView.previewBinary',
    defaultMessage: 'This file is not text, so it cannot be previewed.',
  },
  error: {
    id: 'findingsView.previewError',
    defaultMessage: 'Could not read this file.',
  },
  line: {
    id: 'findingsView.previewLine',
    defaultMessage: 'L{start}',
  },
  lineRange: {
    id: 'findingsView.previewLineRange',
    defaultMessage: 'L{start}–{end}',
  },
  modePreview: {
    id: 'findingsView.previewModePreview',
    defaultMessage: 'Preview',
  },
  modeEdit: {
    id: 'findingsView.previewModeEdit',
    defaultMessage: 'Edit',
  },
  popOut: {
    id: 'findingsView.previewPopOut',
    defaultMessage: 'Pop out',
  },
  callGraph: {
    id: 'findingsView.previewCallGraph',
    defaultMessage: 'Call graph',
  },
  saving: {
    id: 'findingsView.previewSaving',
    defaultMessage: 'Saving',
  },
  saveFailed: {
    id: 'findingsView.previewSaveFailed',
    defaultMessage: 'Could not save this file.',
  },
});

function PreviewSkeleton() {
  return (
    <div className="flex h-full min-h-0" aria-hidden>
      <div className="w-8 shrink-0 border-r border-border-primary bg-background-secondary" />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5 px-3 py-3">
        <div className="h-2.5 w-3/5 rounded-sm bg-background-tertiary" />
        <div className="h-2.5 w-4/5 rounded-sm bg-background-tertiary" />
        <div className="h-2.5 w-2/5 rounded-sm bg-background-tertiary" />
        <div className="h-2.5 w-3/4 rounded-sm bg-background-tertiary" />
        <div className="h-2.5 w-1/2 rounded-sm bg-background-tertiary" />
      </div>
    </div>
  );
}

function PreviewMessage({ children }: { children: string }) {
  return <p className="max-w-prose px-4 py-6 text-sm text-text-secondary">{children}</p>;
}

function ModeButton({
  pressed,
  onClick,
  children,
}: {
  pressed: boolean;
  onClick: () => void;
  children: string;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={cn(
        'no-drag h-6 px-2 text-[11px] text-text-primary',
        pressed ? 'bg-background-tertiary' : 'hover:bg-background-tertiary/70'
      )}
    >
      {children}
    </button>
  );
}

export default function FindingPreview({
  path: rel,
  workingDir,
  lineStart,
  lineEnd,
  onClose,
  variant = 'embedded',
}: {
  path: string;
  workingDir: string;
  lineStart?: number | null;
  lineEnd?: number | null;
  onClose: () => void;
  variant?: 'embedded' | 'window';
}) {
  const intl = useIntl();
  const abs = resolveFindingPath(workingDir, rel);
  const language = languageFromPath(rel || abs);
  const [load, setLoad] = useState<PreviewLoad | { status: 'loading' }>({ status: 'loading' });
  const [editable, setEditable] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [activeLine, setActiveLine] = useState<number | null>(lineStart ?? null);
  const draftRef = useRef(draft);
  const lastSavedRef = useRef('');
  const saveTimer = useRef<number | null>(null);
  const modeChosen = useRef(false);
  draftRef.current = draft;

  useEffect(() => {
    let cancelled = false;
    void window.electron.getSetting('findingsFileEdit').then((value) => {
      if (cancelled || modeChosen.current) return;
      setEditable(value === true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoad({ status: 'loading' });
    void window.electron
      .readFile(abs)
      .then((result) => {
        if (cancelled) return;
        const next = previewFromRead(result, rel || abs);
        setLoad(next);
        if (next.status === 'ready') {
          setDraft(next.value);
          lastSavedRef.current = next.value;
        }
      })
      .catch(() => {
        if (!cancelled) setLoad({ status: 'error' });
      });
    return () => {
      cancelled = true;
    };
  }, [abs, rel]);

  useEffect(() => {
    setActiveLine(lineStart ?? null);
  }, [lineStart, rel]);

  useEffect(() => {
    return () => {
      if (saveTimer.current != null) window.clearTimeout(saveTimer.current);
      const pending = draftRef.current;
      if (pending !== lastSavedRef.current) {
        void window.electron.writeFile(abs, pending);
      }
    };
  }, [abs]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      if (editable) return;
      event.preventDefault();
      onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, editable]);

  const persistMode = (next: boolean) => {
    modeChosen.current = true;
    if (!next && saveTimer.current != null) {
      window.clearTimeout(saveTimer.current);
      saveTimer.current = null;
      void flushSave(draftRef.current);
    }
    setEditable(next);
    void window.electron.setSetting('findingsFileEdit', next);
  };

  const flushSave = async (content: string) => {
    if (content === lastSavedRef.current) return;
    setSaving(true);
    const ok = await window.electron.writeFile(abs, content);
    setSaving(false);
    if (ok) {
      lastSavedRef.current = content;
    } else {
      toast.error(intl.formatMessage(i18n.saveFailed));
    }
  };

  const handleDraftChange = (next: string) => {
    setDraft(next);
    if (saveTimer.current != null) window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => {
      saveTimer.current = null;
      void flushSave(next);
    }, SAVE_MS);
  };

  const handlePopOut = () => {
    void window.electron.openFilePreviewWindow({
      workingDir,
      path: rel,
      lineStart,
      lineEnd,
    });
    onClose();
  };

  const handleCallGraph = () => {
    openCallGraphWindow({
      workingDir,
      relPath: rel,
      source: draft,
      lineStart: activeLine ?? lineStart,
      lineEnd,
    });
  };

  const lineLabel =
    lineStart != null && lineEnd != null && lineEnd !== lineStart
      ? intl.formatMessage(i18n.lineRange, { start: lineStart, end: lineEnd })
      : lineStart != null
        ? intl.formatMessage(i18n.line, { start: lineStart })
        : null;

  return (
    <section
      role="region"
      aria-label={intl.formatMessage(i18n.region)}
      className="finding-preview flex h-full min-h-0 min-w-0 flex-col bg-background-primary"
    >
      <header
        className={cn(
          // Sit above `.titlebar-drag-region` (z-50). Findings uses full-bleed
          // layout, so this 32px bar is otherwise undraggable click-through.
          'relative z-[60] flex h-8 shrink-0 items-center gap-2 border-b border-border-primary bg-background-secondary px-1.5',
          variant === 'embedded' && 'no-drag',
          variant === 'window' && '[-webkit-app-region:drag]',
          variant === 'window' && window.electron?.platform === 'darwin' && 'pl-[72px]'
        )}
      >
        <button
          type="button"
          onClick={onClose}
          className="no-drag inline-flex size-6 shrink-0 items-center justify-center rounded-md text-text-secondary hover:bg-background-tertiary hover:text-text-primary"
          aria-label={intl.formatMessage(i18n.close)}
        >
          <X className="size-3.5" />
        </button>
        <span className="min-w-0 truncate font-mono text-[12px] leading-none text-text-primary">
          {fileBasename(rel) || rel}
        </span>
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-wide text-text-tertiary">
          {language}
        </span>
        {lineLabel && (
          <span className="shrink-0 font-mono text-[10px] text-text-secondary">{lineLabel}</span>
        )}
        {rel && fileBasename(rel) !== rel && (
          <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-text-tertiary">
            {rel}
          </span>
        )}
        <div className="no-drag ml-auto flex shrink-0 items-center gap-1">
          {saving && (
            <span className="font-mono text-[10px] text-text-tertiary">
              {intl.formatMessage(i18n.saving)}
            </span>
          )}
          <div
            role="group"
            className="inline-flex overflow-hidden rounded-md border border-border-primary"
          >
            <ModeButton pressed={!editable} onClick={() => persistMode(false)}>
              {intl.formatMessage(i18n.modePreview)}
            </ModeButton>
            <ModeButton pressed={editable} onClick={() => persistMode(true)}>
              {intl.formatMessage(i18n.modeEdit)}
            </ModeButton>
          </div>
          {variant === 'embedded' && (
            <button
              type="button"
              onClick={handlePopOut}
              className="no-drag inline-flex size-6 items-center justify-center rounded-md text-text-secondary hover:bg-background-tertiary hover:text-text-primary"
              title={intl.formatMessage(i18n.popOut)}
              aria-label={intl.formatMessage(i18n.popOut)}
            >
              <SquareArrowOutUpRight className="size-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={handleCallGraph}
            className="no-drag inline-flex size-6 items-center justify-center rounded-md text-text-secondary hover:bg-background-tertiary hover:text-text-primary"
            title={intl.formatMessage(i18n.callGraph)}
            aria-label={intl.formatMessage(i18n.callGraph)}
          >
            <GitFork className="size-3.5" />
          </button>
        </div>
      </header>
      <div className="min-h-0 flex-1">
        {load.status === 'loading' && <PreviewSkeleton />}
        {load.status === 'missing' && (
          <PreviewMessage>{intl.formatMessage(i18n.missing)}</PreviewMessage>
        )}
        {load.status === 'tooLarge' && (
          <PreviewMessage>{intl.formatMessage(i18n.tooLarge)}</PreviewMessage>
        )}
        {load.status === 'binary' && (
          <PreviewMessage>{intl.formatMessage(i18n.binary)}</PreviewMessage>
        )}
        {load.status === 'error' && (
          <PreviewMessage>{intl.formatMessage(i18n.error)}</PreviewMessage>
        )}
        {load.status === 'ready' && (
          <Suspense fallback={<PreviewSkeleton />}>
            <FindingMonaco
              key={abs}
              value={draft}
              language={language}
              path={abs}
              lineStart={lineStart}
              lineEnd={lineEnd}
              editable={editable}
              onChange={handleDraftChange}
              onActiveLine={setActiveLine}
            />
          </Suspense>
        )}
      </div>
    </section>
  );
}

import { useEffect, useState } from 'react';
import { defineMessages, useIntl } from '../../i18n';
import { cn } from '../../utils';
import { resolveFindingPath } from './filePreview';

export { resolveFindingPath } from './filePreview';

const i18n = defineMessages({
  snippetUnavailable: {
    id: 'findingsView.snippetUnavailable',
    defaultMessage: 'Could not read this file.',
  },
});

const CONTEXT = 3;
const MAX_FILE_CHARS = 400_000;

export default function FindingSnippet({
  workingDir,
  path,
  lineStart,
  lineEnd,
  fallback,
}: {
  workingDir: string;
  path: string;
  lineStart?: number | null;
  lineEnd?: number | null;
  fallback?: string | null;
}) {
  const intl = useIntl();
  const [rows, setRows] = useState<Array<{ n: number; text: string }> | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (lineStart == null) {
      setRows(null);
      setFailed(false);
      return;
    }
    let cancelled = false;
    const abs = resolveFindingPath(workingDir, path);
    void window.electron
      .readFile(abs)
      .then((result) => {
        if (cancelled) return;
        if (!result.found || result.error || !result.file) {
          setFailed(true);
          return;
        }
        if (result.file.length > MAX_FILE_CHARS) {
          setFailed(true);
          return;
        }
        const all = result.file.split(/\r?\n/);
        const hitStart = Math.max(1, lineStart ?? 1);
        const hitEnd = Math.max(hitStart, lineEnd ?? hitStart);
        const from = Math.max(0, hitStart - 1 - CONTEXT);
        const to = Math.min(all.length, hitEnd + CONTEXT);
        setRows(
          all.slice(from, to).map((text, index) => ({
            n: from + index + 1,
            text,
          }))
        );
        setFailed(false);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [workingDir, path, lineStart, lineEnd]);

  const hitStart = lineStart ?? 0;
  const hitEnd = lineEnd ?? lineStart ?? 0;

  if (rows && rows.length > 0) {
    return (
      <pre className="mt-2 max-w-full min-w-0 overflow-x-auto rounded-md bg-background-primary/70 font-mono text-[11px] leading-5">
        {rows.map((row) => {
          const hit = hitStart > 0 && row.n >= hitStart && row.n <= hitEnd;
          return (
            <div
              key={row.n}
              className={cn('flex gap-2 px-2', hit && 'bg-[rgb(255_213_0_/_0.28)]')}
            >
              <span className="shrink-0 w-7 text-right text-text-muted select-none">{row.n}</span>
              <span className="text-text-primary whitespace-pre">{row.text || ' '}</span>
            </div>
          );
        })}
      </pre>
    );
  }

  if (fallback) {
    return (
      <pre className="mt-2 max-w-full min-w-0 overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-background-primary/70 px-2 py-1.5 font-mono text-[11px] leading-5 text-text-secondary">
        {fallback}
      </pre>
    );
  }

  if (failed) {
    return (
      <p className="mt-2 text-[11px] text-text-muted">{intl.formatMessage(i18n.snippetUnavailable)}</p>
    );
  }

  return null;
}

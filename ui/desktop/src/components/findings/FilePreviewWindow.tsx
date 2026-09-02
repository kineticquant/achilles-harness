import { useMemo } from 'react';
import { useSearchParams } from 'react-router';
import FindingPreview from './FindingPreview';

function intParam(params: URLSearchParams, key: string): number | null {
  const raw = params.get(key);
  if (raw == null || raw === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

export default function FilePreviewWindow() {
  const [params] = useSearchParams();
  const workingDir = params.get('workingDir') ?? '';
  const path = params.get('path') ?? '';
  const lineStart = intParam(params, 'lineStart');
  const lineEnd = intParam(params, 'lineEnd');

  const source = useMemo(
    () => ({ workingDir, path, lineStart, lineEnd }),
    [workingDir, path, lineStart, lineEnd]
  );

  if (!source.workingDir || !source.path) {
    return null;
  }

  return (
    <div className="h-screen w-screen overflow-hidden bg-background-primary">
      <FindingPreview
        path={source.path}
        workingDir={source.workingDir}
        lineStart={source.lineStart}
        lineEnd={source.lineEnd}
        variant="window"
        onClose={() => window.electron.closeWindow()}
      />
    </div>
  );
}

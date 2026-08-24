import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { FolderOpen, ShieldAlert } from 'lucide-react';
import { toast } from 'react-toastify';
import { ScrollArea } from '../ui/scroll-area';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { defineMessages, useIntl } from '../../i18n';
import { getInitialWorkingDir } from '../../utils/workingDir';
import {
  acpGetAssessment,
  acpListAssessments,
  acpListFindings,
  acpStartAssessment,
  type AchillesAssessment,
  type AchillesFinding,
} from '../../acp/achilles';

const i18n = defineMessages({
  title: {
    id: 'findingsView.title',
    defaultMessage: 'Findings',
  },
  description: {
    id: 'findingsView.description',
    defaultMessage:
      'Secrets and dependency results from Scan my repo. Ledger lives in achilles.db, not chat.',
  },
  scanMyRepo: {
    id: 'findingsView.scanMyRepo',
    defaultMessage: 'Scan my repo',
  },
  rescan: {
    id: 'findingsView.rescan',
    defaultMessage: 'Rescan',
  },
  scanning: {
    id: 'findingsView.scanning',
    defaultMessage: 'Scanning…',
  },
  empty: {
    id: 'findingsView.empty',
    defaultMessage: 'No findings yet. Pick a workspace, then run Scan my repo.',
  },
  noFindings: {
    id: 'findingsView.noFindings',
    defaultMessage: 'No open findings on this scan.',
  },
  noDir: {
    id: 'findingsView.noDir',
    defaultMessage: 'Pick a workspace folder first.',
  },
  scanFailed: {
    id: 'findingsView.scanFailed',
    defaultMessage: 'Scan failed: {error}',
  },
  lastScan: {
    id: 'findingsView.lastScan',
    defaultMessage: 'Last scan {status} · {count} open',
  },
  chooseWorkspace: {
    id: 'findingsView.chooseWorkspace',
    defaultMessage: 'Choose workspace…',
  },
  workspace: {
    id: 'findingsView.workspace',
    defaultMessage: 'Workspace: {dir}',
  },
  phaseQueued: {
    id: 'findingsView.phaseQueued',
    defaultMessage: 'queued',
  },
  phaseRunning: {
    id: 'findingsView.phaseRunning',
    defaultMessage: 'running',
  },
  phaseDone: {
    id: 'findingsView.phaseDone',
    defaultMessage: 'done',
  },
});

function severityClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-red-600 dark:text-red-400';
    case 'high':
      return 'text-orange-600 dark:text-orange-400';
    case 'medium':
      return 'text-amber-600 dark:text-amber-400';
    default:
      return 'text-text-secondary';
  }
}

function phaseTone(status: string): string {
  if (status === 'done' || status === 'completed') {
    return 'bg-green-500/15 text-green-700 dark:text-green-400';
  }
  if (status === 'running') {
    return 'bg-amber-500/15 text-amber-800 dark:text-amber-300';
  }
  if (status === 'failed') {
    return 'bg-red-500/15 text-red-700 dark:text-red-400';
  }
  return 'bg-background-subtle text-text-muted';
}

export default function FindingsView() {
  const intl = useIntl();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [workingDir, setWorkingDir] = useState(() => getInitialWorkingDir());
  const [assessment, setAssessment] = useState<AchillesAssessment | null>(null);
  const [findings, setFindings] = useState<AchillesFinding[]>([]);
  const [scanning, setScanning] = useState(false);

  const loadForAssessment = useCallback(async (id: string) => {
    const [nextAssessment, nextFindings] = await Promise.all([
      acpGetAssessment(id),
      acpListFindings({ assessmentId: id }),
    ]);
    setAssessment(nextAssessment);
    setFindings(nextFindings);
    if (nextAssessment.workingDir) {
      setWorkingDir(nextAssessment.workingDir);
    }
    return nextAssessment;
  }, []);

  const refreshLatest = useCallback(async () => {
    if (!workingDir) return;
    const listed = await acpListAssessments(workingDir);
    const latest = listed[0];
    if (!latest) {
      setAssessment(null);
      setFindings([]);
      return;
    }
    await loadForAssessment(latest.id);
  }, [loadForAssessment, workingDir]);

  useEffect(() => {
    const requested = searchParams.get('assessmentId');
    if (requested) {
      void loadForAssessment(requested).catch((error) => {
        console.error(error);
      });
      return;
    }
    void refreshLatest().catch((error) => console.error(error));
  }, [loadForAssessment, refreshLatest, searchParams]);

  useEffect(() => {
    if (!assessment || (assessment.status !== 'running' && assessment.status !== 'queued')) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadForAssessment(assessment.id).catch((error) => console.error(error));
    }, 1200);
    return () => window.clearInterval(timer);
  }, [assessment, loadForAssessment]);

  const handlePickWorkspace = async () => {
    const result = await window.electron.directoryChooser();
    if (result.canceled || result.filePaths.length === 0) {
      return;
    }
    const next = result.filePaths[0];
    setWorkingDir(next);
    setAssessment(null);
    setFindings([]);
    navigate('/findings', { replace: true });
  };

  const handleScan = async () => {
    if (!workingDir) {
      toast.error(intl.formatMessage(i18n.noDir));
      return;
    }
    setScanning(true);
    try {
      const started = await acpStartAssessment(workingDir, {
        parentAssessmentId: assessment?.id,
      });
      setAssessment(started);
      setFindings([]);
      navigate(`/findings?assessmentId=${encodeURIComponent(started.id)}`, { replace: true });
    } catch (error) {
      toast.error(
        intl.formatMessage(i18n.scanFailed, {
          error: error instanceof Error ? error.message : String(error),
        })
      );
    } finally {
      setScanning(false);
    }
  };

  const statusLabel = useMemo(() => {
    if (!assessment) return null;
    return intl.formatMessage(i18n.lastScan, {
      status: assessment.status,
      count: assessment.openFindingCount,
    });
  }, [assessment, intl]);

  const phases = useMemo(() => {
    if (!assessment) return [];
    return Object.entries(assessment.phases).map(([name, value]) => ({
      name,
      status: String(value ?? ''),
    }));
  }, [assessment]);

  const busy = scanning || assessment?.status === 'running' || assessment?.status === 'queued';
  const emptyMessage =
    assessment?.status === 'completed' || assessment?.status === 'failed'
      ? intl.formatMessage(i18n.noFindings)
      : intl.formatMessage(i18n.empty);

  return (
    <MainPanelLayout>
      <div className="flex flex-col h-full px-6 pt-6 pb-4">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="min-w-0">
            <h1 className="text-3xl font-light text-text-primary mb-1">
              {intl.formatMessage(i18n.title)}
            </h1>
            <p className="text-sm text-text-secondary max-w-2xl">
              {intl.formatMessage(i18n.description)}
            </p>
            <p className="text-xs text-text-muted mt-2 truncate">
              {workingDir
                ? intl.formatMessage(i18n.workspace, { dir: workingDir })
                : intl.formatMessage(i18n.noDir)}
            </p>
            {statusLabel && <p className="text-xs text-text-muted mt-1">{statusLabel}</p>}
            {assessment?.errorMessage && (
              <p className="text-xs text-red-600 dark:text-red-400 mt-1">{assessment.errorMessage}</p>
            )}
            {phases.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {phases.map((phase) => (
                  <span
                    key={phase.name}
                    className={`text-[11px] px-2 py-0.5 rounded-full ${phaseTone(phase.status)}`}
                  >
                    {phase.name}: {phase.status || intl.formatMessage(i18n.phaseQueued)}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex shrink-0 gap-2">
            <Button variant="outline" onClick={() => void handlePickWorkspace()} disabled={busy}>
              <FolderOpen className="size-4" />
              {intl.formatMessage(i18n.chooseWorkspace)}
            </Button>
            <Button onClick={() => void handleScan()} disabled={busy}>
              <ShieldAlert className="size-4" />
              {busy
                ? intl.formatMessage(i18n.scanning)
                : assessment
                  ? intl.formatMessage(i18n.rescan)
                  : intl.formatMessage(i18n.scanMyRepo)}
            </Button>
          </div>
        </div>

        <ScrollArea className="flex-1">
          {findings.length === 0 ? (
            <p className="text-sm text-text-secondary py-8">{emptyMessage}</p>
          ) : (
            findings.map((finding) => (
              <Card
                key={finding.id}
                className="py-3 px-4 mb-2 bg-background-secondary border-border-default"
              >
                <div className="flex items-baseline gap-2 mb-1">
                  <span className={`text-xs font-medium uppercase ${severityClass(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className="text-xs text-text-muted">{finding.category}</span>
                  <span className="text-xs text-text-muted truncate">{finding.ruleId}</span>
                </div>
                <h3 className="text-base text-text-primary">{finding.title}</h3>
                {finding.path && (
                  <p className="text-xs text-text-muted mt-1">
                    {finding.path}
                    {finding.lineStart ? `:${finding.lineStart}` : ''}
                  </p>
                )}
                <p className="text-sm text-text-secondary mt-2">{finding.description}</p>
              </Card>
            ))
          )}
        </ScrollArea>
      </div>
    </MainPanelLayout>
  );
}

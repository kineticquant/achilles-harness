import { useMemo, useState, type ComponentProps, type ReactNode } from 'react';
import { toast } from 'react-toastify';
import {
  Ban,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Copy,
  File,
  GitFork,
  RotateCcw,
  Sparkle,
  type LucideIcon,
} from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/Tooltip';
import { defineMessages, useIntl } from '../../i18n';
import { ScrollArea } from '../ui/scroll-area';
import { cn } from '../../utils';
import { AchillesWordmark } from '../icons';
import EnvironmentBadge from '../GooseSidebar/EnvironmentBadge';
import type { AchillesAssessment, AchillesFinding } from '../../acp/achilles';
import FindingSnippet from './FindingSnippet';
import AchillesMcpHelp from './AchillesMcpHelp';
import { findingAsEditorBrief } from './findingChat';
import { openCallGraphWindow } from '../../codeMap/openCallGraph';
import {
  ENGINE_LABELS,
  ENGINE_HELP,
  ENGINE_GROUPS,
  ENGINE_ORDER,
  type EngineGroupId,
  filesIndexedCount,
  findingMatchesEngine,
  indexedFilesOf,
  phaseStatus,
  relativeTimeFrom,
  startupPathsOf,
  evidenceGraphOf,
  type EngineFilter,
  type ScanEngine,
} from './scanEvents';

type StateFilter = 'active' | 'dismissed' | 'verified_fixed' | 'all';

const i18n = defineMessages({
  openCount: {
    id: 'findingsView.openCount',
    defaultMessage: 'Open {count}',
  },
  lastScan: {
    id: 'findingsView.lastScan',
    defaultMessage: 'Last scan {when}',
  },
  pastScans: {
    id: 'findingsView.pastScans',
    defaultMessage: 'Past scans',
  },
  scanningNow: {
    id: 'findingsView.scanningNow',
    defaultMessage: 'Scan in progress',
  },
  vsParent: {
    id: 'findingsView.vsParent',
    defaultMessage: '{newCount} new / {goneCount} gone since last',
  },
  filterActive: { id: 'findingsView.filterActive', defaultMessage: 'Open' },
  filterDismissed: { id: 'findingsView.filterFalsePositives', defaultMessage: 'False positives' },
  filterFixed: { id: 'findingsView.filterFixed', defaultMessage: 'Fixed' },
  filterAll: { id: 'findingsView.filterAll', defaultMessage: 'All' },
  countCritical: { id: 'findingsView.countCritical', defaultMessage: '{count} critical' },
  countHigh: { id: 'findingsView.countHigh', defaultMessage: '{count} high' },
  countMedium: { id: 'findingsView.countMedium', defaultMessage: '{count} medium' },
  countLow: { id: 'findingsView.countLow', defaultMessage: '{count} low' },
  countInfo: { id: 'findingsView.countInfo', defaultMessage: '{count} info' },
  noFindings: {
    id: 'findingsView.noFindings',
    defaultMessage: 'No findings in this filter.',
  },
  confirm: { id: 'findingsView.confirm', defaultMessage: 'Confirm' },
  falsePositive: { id: 'findingsView.falsePositive', defaultMessage: 'False positive' },
  falsePositiveHint: {
    id: 'findingsView.falsePositiveHint',
    defaultMessage: 'Marked as a false positive',
  },
  reopen: { id: 'findingsView.reopen', defaultMessage: 'Reopen' },
  engineKind: {
    id: 'findingsView.engineKind',
    defaultMessage: 'Kind: {kind}',
  },
  agentVerdict: {
    id: 'findingsView.agentVerdict',
    defaultMessage: '{role}: {verdict}{reason}',
  },
  needsAgent: {
    id: 'findingsView.needsAgent',
    defaultMessage: 'needs agent',
  },
  openFile: {
    id: 'findingsView.openFile',
    defaultMessage: 'Open file',
  },
  kevFlag: {
    id: 'findingsView.kevFlag',
    defaultMessage: 'Known exploited (CISA KEV catalog)',
  },
  notSecurity: {
    id: 'findingsView.notSecurityFinding',
    defaultMessage: 'Not a security finding — stability / config hygiene',
  },
  envTemplateNote: {
    id: 'findingsView.envTemplateNote',
    defaultMessage:
      'Looks like an env template, not a filled-in .env. Fast does not read values — dismiss if this is only placeholders.',
  },
  localChangeOrigin: {
    id: 'findingsView.localChangeOrigin',
    defaultMessage: 'Introduced by {origin} local changes',
  },
  engineAll: { id: 'findingsView.engineAll', defaultMessage: 'All' },
  engineGroupSource: { id: 'findingsView.engineGroupSource', defaultMessage: 'Source' },
  engineGroupStack: { id: 'findingsView.engineGroupStack', defaultMessage: 'Stack' },
  engineGroupReview: { id: 'findingsView.engineGroupReview', defaultMessage: 'Review' },
  engineToolbar: {
    id: 'findingsView.engineToolbar',
    defaultMessage: 'Finding type',
  },
  fingerprintEmpty: {
    id: 'findingsView.fingerprintEmpty',
    defaultMessage: 'Fingerprint has not finished yet.',
  },
  fingerprintNeedsRescan: {
    id: 'findingsView.fingerprintNeedsRescan',
    defaultMessage: '{count} files were indexed. Rescan to show the full tree.',
  },
  fingerprintFiles: {
    id: 'findingsView.fingerprintFiles',
    defaultMessage: '{count, plural, one {# file} other {# files}}',
  },
  startupHeading: {
    id: 'findingsView.startupHeading',
    defaultMessage: 'How it starts',
  },
  startupEmpty: {
    id: 'findingsView.startupEmpty',
    defaultMessage: 'No start command found in manifests or usual entry files.',
  },
  graphHeading: {
    id: 'findingsView.graphHeading',
    defaultMessage: 'Surfaces ↔ findings',
  },
  graphEmpty: {
    id: 'findingsView.graphEmpty',
    defaultMessage: 'No surface-to-finding overlaps on this scan.',
  },
  noEngineFindings: {
    id: 'findingsView.noEngineFindings',
    defaultMessage: 'No {engine} findings in this filter.',
  },
  collapseFinding: {
    id: 'findingsView.collapseFinding',
    defaultMessage: 'Collapse finding',
  },
  expandFinding: {
    id: 'findingsView.expandFinding',
    defaultMessage: 'Expand finding',
  },
  askAi: {
    id: 'findingsView.askAi',
    defaultMessage: 'Ask about this finding',
  },
  copyForEditor: {
    id: 'findingsView.copyForEditor',
    defaultMessage: 'Copy as prompt',
  },
  copyForEditorHint: {
    id: 'findingsView.copyForEditorHint',
    defaultMessage:
      'Copies a prompt. Paste it into Cursor, Claude Code, Codex, or OpenCode to fix this there, then Rescan here.',
  },
  copiedForEditor: {
    id: 'findingsView.copiedForEditor',
    defaultMessage: 'Copied as a prompt — paste it into your coding app to fix this, then Rescan here',
  },
  copyFailed: {
    id: 'findingsView.copyForEditorFailed',
    defaultMessage: 'Could not copy',
  },
  callGraph: {
    id: 'findingsView.railCallGraph',
    defaultMessage: 'Call graph',
  },
});

function severityCount(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-[#c98a8a]';
    case 'high':
      return 'text-[#e6d06a]';
    case 'medium':
      return 'text-[#7eb8b2]';
    case 'info':
      return 'text-text-info';
    default:
      return 'text-text-secondary';
  }
}

function severityPill(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-[#c45c5c]/15 text-[#c98a8a]';
    case 'high':
      return 'bg-[#edcc4a]/28 text-[#e6d06a]';
    case 'medium':
      return 'bg-[#13bbaf]/15 text-[#7eb8b2]';
    case 'info':
      return 'bg-background-info/10 text-text-info';
    default:
      return 'bg-background-tertiary/80 text-text-secondary';
  }
}

function severitySurface(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-[color-mix(in_srgb,#c45c5c_3%,var(--color-background-secondary))]';
    case 'high':
      return 'bg-[color-mix(in_srgb,#edcc4a_3%,var(--color-background-secondary))]';
    case 'medium':
      return 'bg-[color-mix(in_srgb,#13bbaf_3%,var(--color-background-secondary))]';
    default:
      return 'bg-background-secondary';
  }
}

function severityRank(severity: string): number {
  switch (severity) {
    case 'critical':
      return 0;
    case 'high':
      return 1;
    case 'medium':
      return 2;
    case 'low':
      return 3;
    case 'info':
      return 4;
    default:
      return 5;
  }
}

function matchesFilter(finding: AchillesFinding, filter: StateFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'active') return finding.state === 'open' || finding.state === 'confirmed';
  return finding.state === filter;
}

function FindingTool({
  icon: Icon,
  children,
  ...props
}: ComponentProps<'button'> & { icon: LucideIcon; children?: ReactNode }) {
  return (
    <button
      type="button"
      {...props}
      className={cn(
        'inline-flex h-full shrink-0 items-center gap-1 border-l border-border-primary px-2 text-[11px] whitespace-nowrap text-text-primary first:border-l-0 hover:bg-background-tertiary',
        props.className
      )}
    >
      <Icon className="size-3" />
      {children}
    </button>
  );
}

type FileTreeNode = {
  name: string;
  path: string;
  children: FileTreeNode[];
};

function insertPath(nodes: FileTreeNode[], parts: string[], acc: string): void {
  if (parts.length === 0) return;
  const [head, ...rest] = parts;
  const nextPath = acc ? `${acc}/${head}` : head;
  let node = nodes.find((row) => row.name === head);
  if (!node) {
    node = { name: head, path: nextPath, children: [] };
    nodes.push(node);
  }
  insertPath(node.children, rest, nextPath);
}

function sortTree(nodes: FileTreeNode[]): FileTreeNode[] {
  nodes.sort((a, b) => {
    const aDir = a.children.length > 0 ? 0 : 1;
    const bDir = b.children.length > 0 ? 0 : 1;
    if (aDir !== bDir) return aDir - bDir;
    return a.name.localeCompare(b.name);
  });
  for (const node of nodes) {
    sortTree(node.children);
  }
  return nodes;
}

function buildFileTree(paths: string[]): FileTreeNode[] {
  const root: FileTreeNode[] = [];
  const seen = new Set<string>();
  for (const path of paths) {
    if (seen.has(path)) continue;
    seen.add(path);
    const parts = path.split(/[\\/]+/).filter(Boolean);
    insertPath(root, parts, '');
  }
  return sortTree(root);
}

function FileTree({ nodes, depth = 0 }: { nodes: FileTreeNode[]; depth?: number }) {
  return (
    <ul className={cn(depth === 0 ? 'flex flex-col gap-0.5' : 'ml-3 border-l border-border-primary pl-2')}>
      {nodes.map((node) => {
        const isFolder = node.children.length > 0;
        if (!isFolder) {
          return (
            <li key={node.path} className="text-xs text-text-secondary font-mono py-0.5 break-all">
              {node.name}
            </li>
          );
        }
        return (
          <li key={node.path}>
            <details className="group" open={depth < 1}>
              <summary className="flex items-center gap-1 text-xs text-text-primary cursor-pointer py-0.5 list-none [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-3 shrink-0 text-text-muted transition-transform group-open:rotate-90" />
                <span className="font-mono break-all">{node.name}</span>
              </summary>
              <FileTree nodes={node.children} depth={depth + 1} />
            </details>
          </li>
        );
      })}
    </ul>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function investigationOf(finding: AchillesFinding): Record<string, unknown> {
  return asRecord(finding.evidence.investigation);
}

function findingNeedsAgent(finding: AchillesFinding): boolean {
  return investigationOf(finding).needsAgent === true;
}

function passReason(finding: AchillesFinding, role: string): string | null {
  const reason = asRecord(asRecord(investigationOf(finding).passes)[role]).reason;
  return typeof reason === 'string' && reason.trim() ? reason.trim() : null;
}

function passVerdict(finding: AchillesFinding, role: string): string | null {
  const verdict = asRecord(asRecord(investigationOf(finding).passes)[role]).verdict;
  return typeof verdict === 'string' ? verdict : null;
}

function triageReason(finding: AchillesFinding): string | null {
  const reason = asRecord(finding.evidence.triage).reason;
  return typeof reason === 'string' ? reason : null;
}

function isFalsePositive(finding: AchillesFinding): boolean {
  if (triageReason(finding) === 'false_positive') return true;
  return (
    passVerdict(finding, 'investigator') === 'false_positive' &&
    passVerdict(finding, 'validator') === 'false_positive'
  );
}

function snippetFallback(finding: AchillesFinding): string | null {
  const investigation = investigationOf(finding);
  if (typeof investigation.snippet === 'string' && investigation.snippet.trim()) {
    return investigation.snippet;
  }
  if (typeof finding.evidence.preview === 'string' && finding.evidence.preview.trim()) {
    return finding.evidence.preview;
  }
  return null;
}

function scanRunLabel(run: AchillesAssessment): string {
  const raw = run.finishedAt || run.startedAt;
  const at = Date.parse(raw);
  if (!Number.isFinite(at)) {
    return run.id.slice(0, 8);
  }
  return new Date(at).toLocaleString();
}

export default function FindingsRail({
  findings,
  workingDir,
  filter,
  onFilter,
  onTriage,
  headerAction,
  assessment,
  scanRuns = [],
  onSelectScanRun,
  onAskAi,
  previewFindingId,
  onOpenFile,
}: {
  findings: AchillesFinding[];
  workingDir: string;
  filter: StateFilter;
  onFilter: (filter: StateFilter) => void;
  onTriage: (finding: AchillesFinding, state: string, reason?: string) => void;
  headerAction?: ReactNode;
  assessment?: AchillesAssessment | null;
  scanRuns?: AchillesAssessment[];
  onSelectScanRun?: (assessmentId: string) => void;
  onAskAi: (finding: AchillesFinding) => void;
  previewFindingId?: string | null;
  onOpenFile: (finding: AchillesFinding) => void;
}) {
  const intl = useIntl();
  const [engineFilter, setEngineFilter] = useState<EngineFilter>('all');
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(() => new Set());

  const toggleCollapsed = (id: string) => {
    setCollapsedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const copyForEditor = async (finding: AchillesFinding) => {
    try {
      await navigator.clipboard.writeText(findingAsEditorBrief(finding));
      toast.success(intl.formatMessage(i18n.copiedForEditor));
    } catch {
      toast.error(intl.formatMessage(i18n.copyFailed));
    }
  };

  const indexedFiles = useMemo(() => indexedFilesOf(assessment ?? null), [assessment]);
  const indexedCount = useMemo(() => filesIndexedCount(assessment ?? null), [assessment]);
  const startupPaths = useMemo(() => startupPathsOf(assessment ?? null), [assessment]);
  const evidenceGraph = useMemo(() => evidenceGraphOf(assessment ?? null), [assessment]);
  const fingerprintTree = useMemo(() => buildFileTree(indexedFiles), [indexedFiles]);

  const visible = useMemo(
    () =>
      findings
        .filter((finding) => matchesFilter(finding, filter))
        .filter((finding) => findingMatchesEngine(finding, engineFilter))
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [findings, filter, engineFilter]
  );

  const counts = useMemo(() => {
    const active = findings.filter((f) => f.state === 'open' || f.state === 'confirmed');
    const tally = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of active) {
      if (finding.severity === 'critical') tally.critical += 1;
      else if (finding.severity === 'high') tally.high += 1;
      else if (finding.severity === 'medium') tally.medium += 1;
      else if (finding.severity === 'low') tally.low += 1;
      else tally.info += 1;
    }
    return { ...tally, open: active.length };
  }, [findings]);

  const openCount = assessment?.openFindingCount ?? counts.open;
  const lastScanLabel = useMemo(() => {
    if (!assessment) return null;
    if (
      assessment.status === 'running' ||
      assessment.status === 'queued' ||
      assessment.status === 'paused'
    ) {
      return intl.formatMessage(i18n.scanningNow);
    }
    if (!assessment.finishedAt) return null;
    const rel = relativeTimeFrom(assessment.finishedAt);
    const when = rel
      ? intl.formatRelativeTime(rel.value, rel.unit)
      : assessment.finishedAt;
    return intl.formatMessage(i18n.lastScan, { when });
  }, [assessment, intl]);
  const vsParent =
    assessment?.parentAssessmentId &&
    assessment.newFindingCount != null &&
    assessment.goneFindingCount != null
      ? intl.formatMessage(i18n.vsParent, {
          newCount: assessment.newFindingCount,
          goneCount: assessment.goneFindingCount,
        })
      : null;

  const engineChips = useMemo((): EngineFilter[] => {
    if (!assessment) return ['all'];
    return [
      'all',
      ...ENGINE_ORDER.filter((engine) => {
        if (engine !== 'literals' && engine !== 'delta') return true;
        const phase = phaseStatus(assessment.phases[engine]);
        return (
          Boolean(phase) ||
          findings.some((finding) => finding.category.toLowerCase() === engine)
        );
      }),
    ];
  }, [assessment, findings]);

  const engineCount = (engine: EngineFilter): number | null => {
    if (engine === 'all') return null;
    if (engine === 'fingerprint') {
      return indexedCount;
    }
    return findings.filter(
      (finding) => matchesFilter(finding, filter) && findingMatchesEngine(finding, engine)
    ).length;
  };

  const visibleEngines = useMemo(() => new Set(engineChips), [engineChips]);
  const engineGroups = useMemo(
    () =>
      ENGINE_GROUPS.map((group) => ({
        ...group,
        engines: group.engines.filter((engine) => visibleEngines.has(engine)),
      })).filter((group) => group.engines.length > 0),
    [visibleEngines]
  );

  const engineGroupLabel = (id: EngineGroupId): string => {
    switch (id) {
      case 'source':
        return intl.formatMessage(i18n.engineGroupSource);
      case 'stack':
        return intl.formatMessage(i18n.engineGroupStack);
      case 'review':
        return intl.formatMessage(i18n.engineGroupReview);
    }
  };

  const engineChip = (engine: EngineFilter) => {
    const selected = engineFilter === engine;
    const label =
      engine === 'all'
        ? intl.formatMessage(i18n.engineAll)
        : ENGINE_LABELS[engine as ScanEngine];
    const count = engineCount(engine);
    return (
      <button
        type="button"
        key={engine}
        title={engine === 'all' ? undefined : ENGINE_HELP[engine as ScanEngine]}
        aria-pressed={selected}
        onClick={() => setEngineFilter(engine)}
        className={cn(
          'inline-flex shrink-0 items-center gap-1 overflow-visible whitespace-nowrap rounded-md border border-border-primary px-2 py-1 text-[11px] leading-4',
          selected
            ? 'bg-background-tertiary text-text-primary'
            : 'bg-background-primary text-text-muted hover:text-text-primary'
        )}
      >
        <span>{label}</span>
        {count != null ? (
          <span className="tabular-nums text-text-muted">{count}</span>
        ) : null}
      </button>
    );
  };

  const filterBtn = (id: StateFilter, label: string) => (
    <button
      type="button"
      key={id}
      onClick={() => onFilter(id)}
      className={cn(
        'text-[11px] px-2 py-0.5 border-border-primary',
        filter === id
          ? 'bg-background-tertiary text-text-primary'
          : 'text-text-muted hover:text-text-primary'
      )}
    >
      {label}
    </button>
  );

  return (
    <aside className="relative flex min-h-0 min-w-0 w-full h-full flex-col overflow-x-hidden md:border-l-0 border-border-primary">
      <div className="absolute top-[14px] right-4 z-[60] flex flex-row items-center gap-1">
        <div className="flex flex-row items-center gap-1 text-text-secondary">
          <AchillesWordmark className="text-[13px]" />
        </div>
        <EnvironmentBadge />
      </div>
      <div className="pt-4 pb-2 shrink-0">
        <div className="px-4 pr-28">
          <div className="flex items-baseline justify-between gap-2 mb-1">
            <h2 className="text-sm font-medium text-text-primary">
              {intl.formatMessage(i18n.openCount, { count: openCount })}
            </h2>
            {headerAction}
          </div>
          {lastScanLabel || vsParent ? (
            <p className="text-xs text-text-muted mb-2">
              {lastScanLabel}
              {lastScanLabel && vsParent ? ' · ' : null}
              {vsParent}
            </p>
          ) : null}
          {scanRuns.length > 1 && onSelectScanRun ? (
            <label className="mb-2 flex min-w-0 flex-col gap-1">
              <span className="text-[10px] uppercase tracking-wider text-text-secondary">
                {intl.formatMessage(i18n.pastScans)}
              </span>
              <select
                className="max-w-full rounded-md border border-border-primary bg-background-primary px-2 py-1 text-[11px] text-text-primary"
                value={assessment?.id ?? scanRuns[0]?.id ?? ''}
                onChange={(event) => onSelectScanRun(event.target.value)}
              >
                {scanRuns.map((run) => (
                  <option key={run.id} value={run.id}>
                    {scanRunLabel(run)}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>
        <div className="px-4">
        <div
          className="inline-flex items-stretch rounded-md border border-border-primary overflow-hidden mb-2"
          role="group"
        >
          {filterBtn('active', intl.formatMessage(i18n.filterActive))}
          <span className="w-px bg-border-primary" aria-hidden="true" />
          {filterBtn('dismissed', intl.formatMessage(i18n.filterDismissed))}
          <span className="w-px bg-border-primary" aria-hidden="true" />
          {filterBtn('verified_fixed', intl.formatMessage(i18n.filterFixed))}
          <span className="w-px bg-border-primary" aria-hidden="true" />
          {filterBtn('all', intl.formatMessage(i18n.filterAll))}
        </div>
        <p className="text-xs flex flex-wrap gap-x-2 gap-y-0.5 mb-2">
          <span className={severityCount('critical')}>
            {intl.formatMessage(i18n.countCritical, { count: counts.critical })}
          </span>
          <span className={severityCount('high')}>
            {intl.formatMessage(i18n.countHigh, { count: counts.high })}
          </span>
          <span className={severityCount('medium')}>
            {intl.formatMessage(i18n.countMedium, { count: counts.medium })}
          </span>
          <span className={severityCount('low')}>
            {intl.formatMessage(i18n.countLow, { count: counts.low })}
          </span>
          <span className={severityCount('info')}>
            {intl.formatMessage(i18n.countInfo, { count: counts.info })}
          </span>
        </p>
        {engineChips.length > 1 && (
          <div
            role="group"
            aria-label={intl.formatMessage(i18n.engineToolbar)}
            className="flex flex-col gap-1.5"
          >
            <div className="flex items-start gap-2">
              <span className="w-14 shrink-0" aria-hidden="true" />
              {engineChip('all')}
            </div>
            {engineGroups.map((group) => (
              <div
                key={group.id}
                role="group"
                aria-label={engineGroupLabel(group.id)}
                className="flex items-start gap-2"
              >
                <span className="flex min-h-7 w-14 shrink-0 items-center text-[10px] uppercase tracking-wider text-text-secondary">
                  {engineGroupLabel(group.id)}
                </span>
                <div className="flex min-w-0 flex-wrap gap-1">{group.engines.map(engineChip)}</div>
              </div>
            ))}
          </div>
        )}
        </div>
      </div>
      <ScrollArea className="flex-1 min-h-0" paddingX={0} paddingY={0}>
        {engineFilter === 'fingerprint' ? (
          fingerprintTree.length === 0 ? (
            <p className="text-sm text-text-secondary px-4 py-6">
              {indexedCount > 0
                ? intl.formatMessage(i18n.fingerprintNeedsRescan, { count: indexedCount })
                : intl.formatMessage(i18n.fingerprintEmpty)}
            </p>
          ) : (
            <div className="px-3 py-2">
              {startupPaths.length > 0 ? (
                <div className="mb-3">
                  <p className="text-xs text-text-muted mb-1.5">
                    {intl.formatMessage(i18n.startupHeading)}
                  </p>
                  <ul className="flex flex-col gap-1.5">
                    {startupPaths.map((row, index) => (
                      <li
                        key={`${row.kind}-${row.path}-${row.command ?? ''}-${index}`}
                        className="text-[12px] leading-snug"
                      >
                        <span className="text-text-muted">{row.kind}</span>
                        <span className="break-all text-text-primary"> {row.path}</span>
                        {row.command ? (
                          <span className="block font-mono text-text-secondary truncate">
                            {row.command}
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : indexedFiles.length > 0 ? (
                <p className="text-xs text-text-muted mb-2">
                  {intl.formatMessage(i18n.startupEmpty)}
                </p>
              ) : null}
              {evidenceGraph ? (
                <div className="mb-3">
                  <p className="text-xs text-text-muted mb-1.5">
                    {intl.formatMessage(i18n.graphHeading)}
                  </p>
                  {evidenceGraph.edges.length === 0 ? (
                    <p className="text-[12px] text-text-secondary">
                      {intl.formatMessage(i18n.graphEmpty)}
                    </p>
                  ) : (
                    <ul className="flex flex-col gap-1">
                      {evidenceGraph.edges.slice(0, 40).map((edge, index) => {
                        const from =
                          evidenceGraph.nodes.find((n) => n.id === edge.from)?.label ?? edge.from;
                        const to =
                          evidenceGraph.nodes.find((n) => n.id === edge.to)?.label ?? edge.to;
                        return (
                          <li
                            key={`${edge.from}-${edge.to}-${index}`}
                            className="text-[12px] leading-snug text-text-primary"
                          >
                            <span className="text-text-muted">{from}</span>
                            <span className="text-text-secondary"> → </span>
                            <span className="break-all">{to}</span>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  <p className="mt-1.5 text-[11px] text-text-muted">{evidenceGraph.note}</p>
                </div>
              ) : null}
              <p className="text-xs text-text-muted mb-2">
                {intl.formatMessage(i18n.fingerprintFiles, {
                  count: indexedFiles.length,
                })}
              </p>
              <FileTree nodes={fingerprintTree} />
            </div>
          )
        ) : visible.length === 0 ? (
          <p className="text-sm text-text-secondary px-4 py-6">
            {engineFilter === 'all'
              ? intl.formatMessage(i18n.noFindings)
              : intl.formatMessage(i18n.noEngineFindings, {
                  engine: ENGINE_LABELS[engineFilter],
                })}
          </p>
        ) : (
          <div className="flex min-w-0 flex-col gap-1 px-3 py-2">
            {visible.map((finding) => {
              const collapsed = collapsedIds.has(finding.id);
              return (
              <article
                key={finding.id}
                className={cn(
                  'min-w-0 overflow-hidden rounded-md',
                  severitySurface(finding.severity),
                  collapsed ? 'px-2.5 py-1' : 'px-3 py-2'
                )}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={cn(
                      'shrink-0 text-[10px] font-medium uppercase tracking-wide px-1.5 py-0.5 rounded-sm',
                      severityPill(finding.severity)
                    )}
                  >
                    {finding.severity}
                  </span>
                  <h3 className="min-w-0 flex-1 text-sm text-text-primary leading-tight truncate">
                    {finding.title}
                  </h3>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => onAskAi(finding)}
                        aria-label={intl.formatMessage(i18n.askAi)}
                        className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-text-muted hover:text-text-primary hover:bg-background-primary/50"
                      >
                        <Sparkle className="size-3.5" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent
                      side="left"
                      className="bg-background-secondary text-text-primary border border-border-primary"
                      arrowClassName="bg-background-secondary fill-background-secondary"
                    >
                      {intl.formatMessage(i18n.askAi)}
                    </TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => toggleCollapsed(finding.id)}
                        aria-expanded={!collapsed}
                        aria-label={
                          collapsed
                            ? intl.formatMessage(i18n.expandFinding)
                            : intl.formatMessage(i18n.collapseFinding)
                        }
                        className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-text-muted hover:text-text-primary hover:bg-background-primary/50"
                      >
                        {collapsed ? (
                          <ChevronDown className="size-3.5" />
                        ) : (
                          <ChevronUp className="size-3.5" />
                        )}
                      </button>
                    </TooltipTrigger>
                    <TooltipContent
                      side="left"
                      className="bg-background-secondary text-text-primary border border-border-primary"
                      arrowClassName="bg-background-secondary fill-background-secondary"
                    >
                      {collapsed
                        ? intl.formatMessage(i18n.expandFinding)
                        : intl.formatMessage(i18n.collapseFinding)}
                    </TooltipContent>
                  </Tooltip>
                </div>
                {!collapsed && (
                  <>
                <p className="mt-1 min-w-0 truncate text-xs text-text-muted">
                  {finding.ruleId}
                  {finding.path
                    ? ` · ${finding.path}${finding.lineStart ? `:${finding.lineStart}` : ''}`
                    : ''}
                </p>
                {finding.evidence.inKev === true && (
                  <p className="text-xs text-text-danger mt-1">
                    {intl.formatMessage(i18n.kevFlag)}
                  </p>
                )}
                {finding.category.toLowerCase() === 'literals' && (
                  <p className="text-xs text-text-muted mt-1">
                    {intl.formatMessage(i18n.notSecurity)}
                  </p>
                )}
                {finding.ruleId === 'dotenv-template' && (
                  <p className="text-xs text-text-muted mt-1">
                    {intl.formatMessage(i18n.envTemplateNote)}
                  </p>
                )}
                {finding.category.toLowerCase() === 'delta' && (
                  <p className="text-xs text-text-muted mt-1">
                    {intl.formatMessage(i18n.localChangeOrigin, {
                      origin:
                        typeof finding.evidence.origin === 'string' && finding.evidence.origin
                          ? finding.evidence.origin
                          : 'uncommitted',
                    })}
                  </p>
                )}
                {typeof investigationOf(finding).kind === 'string' && (
                  <p className="text-xs text-text-muted mt-1">
                    {intl.formatMessage(i18n.engineKind, {
                      kind: String(investigationOf(finding).kind),
                    })}
                    {findingNeedsAgent(finding)
                      ? ` · ${intl.formatMessage(i18n.needsAgent)}`
                      : ''}
                  </p>
                )}
                {(['investigator', 'validator'] as const).map((role) => {
                  const verdict = passVerdict(finding, role);
                  if (!verdict) return null;
                  const reason = passReason(finding, role);
                  return (
                    <p key={role} className="text-xs text-text-muted mt-1">
                      {intl.formatMessage(i18n.agentVerdict, {
                        role,
                        verdict,
                        reason: reason ? ` — ${reason}` : '',
                      })}
                    </p>
                  );
                })}
                <p className="mt-2 min-w-0 break-all text-sm text-text-secondary">
                  {finding.description}
                </p>
                {finding.state === 'dismissed' && isFalsePositive(finding) && (
                  <p className="text-xs text-text-muted mt-1">
                    {intl.formatMessage(i18n.falsePositiveHint)}
                  </p>
                )}
                {finding.path && workingDir && (
                  <FindingSnippet
                    workingDir={workingDir}
                    path={finding.path}
                    lineStart={finding.lineStart}
                    lineEnd={finding.lineEnd}
                    fallback={snippetFallback(finding)}
                  />
                )}
                <div
                  role="toolbar"
                  className="mt-2 inline-flex h-7 max-w-full items-stretch overflow-x-auto rounded-md border border-border-primary bg-background-primary"
                >
                  {(finding.state === 'open' || finding.state === 'confirmed') && (
                    <>
                      {finding.state === 'open' && (
                        <FindingTool
                          icon={Check}
                          onClick={() => onTriage(finding, 'confirmed')}
                        >
                          {intl.formatMessage(i18n.confirm)}
                        </FindingTool>
                      )}
                      <FindingTool
                        icon={Ban}
                        onClick={() => onTriage(finding, 'dismissed', 'false_positive')}
                      >
                        {intl.formatMessage(i18n.falsePositive)}
                      </FindingTool>
                    </>
                  )}
                  {(finding.state === 'dismissed' || finding.state === 'verified_fixed') && (
                    <FindingTool
                      icon={RotateCcw}
                      onClick={() => onTriage(finding, 'open')}
                    >
                      {intl.formatMessage(i18n.reopen)}
                    </FindingTool>
                  )}
                  {finding.path && workingDir && (
                    <FindingTool
                      icon={File}
                      className={
                        previewFindingId === finding.id ? 'bg-background-tertiary' : undefined
                      }
                      aria-pressed={previewFindingId === finding.id}
                      onClick={() => onOpenFile(finding)}
                    >
                      {intl.formatMessage(i18n.openFile)}
                    </FindingTool>
                  )}
                  {(finding.state === 'open' || finding.state === 'confirmed') && (
                    <FindingTool
                      icon={Copy}
                      title={intl.formatMessage(i18n.copyForEditorHint)}
                      onClick={() => void copyForEditor(finding)}
                    >
                      {intl.formatMessage(i18n.copyForEditor)}
                    </FindingTool>
                  )}
                  {finding.path && workingDir && (
                    <FindingTool
                      icon={GitFork}
                      title={intl.formatMessage(i18n.callGraph)}
                      aria-label={intl.formatMessage(i18n.callGraph)}
                      onClick={() =>
                        openCallGraphWindow({
                          workingDir,
                          relPath: finding.path,
                          source: snippetFallback(finding),
                          lineStart: finding.lineStart,
                          lineEnd: finding.lineEnd,
                        })
                      }
                    />
                  )}
                </div>
                  </>
                )}
              </article>
              );
            })}
          </div>
        )}
      </ScrollArea>
      <AchillesMcpHelp />
    </aside>
  );
}

import type { AchillesAssessment, AchillesFinding } from '../../acp/achilles';

export type ScanDepth = 'fast' | 'investigate' | 'deep';

export const ENGINE_ORDER = [
  'fingerprint',
  'secrets',
  'history',
  'sast',
  'delta',
  'literals',
  'investigate',
  'surfaces',
  'harden',
  'sca',
  'intel',
  'agent',
] as const;

export type ScanEngine = (typeof ENGINE_ORDER)[number];

export const ENGINE_LABELS: Record<ScanEngine, string> = {
  fingerprint: 'Files',
  secrets: 'Secrets',
  history: 'Git history',
  sast: 'Code patterns',
  delta: 'Local changes',
  literals: 'Hardcoded values',
  investigate: 'Needs review',
  surfaces: 'Deploy / CI',
  harden: 'App config',
  sca: 'Dependencies',
  intel: 'Threats',
  agent: 'AI review',
};

/** Extra title text so SAST/SCA and other jargon are spelled out. */
export const ENGINE_HELP: Record<ScanEngine, string> = {
  fingerprint: 'Files the scan indexed in this workspace, plus how the process is supposed to start (package.json start, Dockerfile CMD, Procfile, Cargo bin, and similar).',
  secrets: 'Keys, tokens, and passwords found in the tree.',
  history: 'The same secret patterns, but in git history after the file left the working tree. Rotate and purge history; deleting the file is not enough.',
  sast: 'SAST (static analysis): insecure patterns in your source code.',
  delta:
    'Staged, unstaged, and untracked edits. Compacts the logic they introduce, then checks it against the rest of the tree — especially when this change uses a sink the repo already wraps more safely.',
  literals:
    'Not a security scan. Limits, timeouts, and magic numbers rank above URLs (URLs in source are often fine). Also flags IPs, paths, and connection strings that usually belong in config.',
  investigate: 'Code-pattern hits the AI is confirming or rejecting. They stay on the list unless both passes call them a false positive.',
  surfaces: 'Deploy, CI, and cloud config that looks exposed.',
  harden: 'Cookie flags, CORS wildcards, and CSP unsafe-inline in application source.',
  sca: 'SCA (software composition analysis): lockfile packages against OSV (known CVEs/GHSAs, including MAL-* malware advisories), unpinned dependencies, install-time scripts, and lookalike package names. Optional Socket add-on layers extra package-risk signals on top.',
  intel: 'Matches against CISA’s known-exploited list, EPSS, and (with ACHILLES_NVD_API_KEY) NVD CVSS. OpenSSF Scorecard for the GitHub origin lands under dependencies.',
  agent: 'The configured model reviews Fast engine hits (Investigate: investigator + validator on each). Deep also inspects functions one by one and can record cited findings. Hits stay on the list unless both passes call a false positive.',
};

export function scanDepthOf(assessment: AchillesAssessment | null): ScanDepth {
  const raw = String(assessment?.stats.scanDepth ?? 'fast').toLowerCase();
  if (raw === 'investigate' || raw === 'deep') return raw;
  return 'fast';
}

export function isScanKickoffText(text: string): boolean {
  const trimmed = text.trim();
  return (
    trimmed === 'Scan my repo' ||
    trimmed === 'Scan changed files' ||
    /^Perform an? (Fast|Investigative|Deep) Scan on (my repo|changed files)$/.test(trimmed)
  );
}

export type EngineFilter = 'all' | ScanEngine;

export type EngineGroupId = 'source' | 'stack' | 'review';

/** How finding types cluster in the rail. Every engine appears in exactly one group. */
export const ENGINE_GROUPS: { id: EngineGroupId; engines: ScanEngine[] }[] = [
  {
    id: 'source',
    engines: ['fingerprint', 'secrets', 'history', 'sast', 'delta', 'literals'],
  },
  {
    id: 'stack',
    engines: ['surfaces', 'harden', 'sca', 'intel'],
  },
  {
    id: 'review',
    engines: ['investigate', 'agent'],
  },
];

export type DetectedSurface = {
  id: string;
  label: string;
  paths: string[];
};

export type EvidenceGraph = {
  nodes: { id: string; kind: string; label: string }[];
  edges: { from: string; to: string; kind: string }[];
  note: string;
};

export function evidenceGraphOf(assessment: AchillesAssessment | null): EvidenceGraph | null {
  const raw = asRecord(assessment?.stats.graph);
  const nodesRaw = raw.nodes;
  const edgesRaw = raw.edges;
  if (!Array.isArray(nodesRaw) || !Array.isArray(edgesRaw)) return null;
  const nodes = nodesRaw.map((item) => {
    const row = asRecord(item);
    return {
      id: String(row.id ?? ''),
      kind: String(row.kind ?? ''),
      label: String(row.label ?? ''),
    };
  });
  const edges = edgesRaw.map((item) => {
    const row = asRecord(item);
    return {
      from: String(row.from ?? ''),
      to: String(row.to ?? ''),
      kind: String(row.kind ?? ''),
    };
  });
  if (nodes.length === 0 && edges.length === 0) return null;
  return {
    nodes,
    edges,
    note: String(raw.note ?? 'v0 file-overlap graph. Not a dataflow or attack-path proof.'),
  };
}

export type ScanLine =
  | { id: string; role: 'user'; text: string }
  | {
      id: string;
      role: 'assistant';
      engine?: string;
      status: 'running' | 'done' | 'skipped' | 'summary' | 'error' | 'paused';
      detailKey?: 'files' | 'findings';
      detailCount?: number;
      live?: boolean;
      text?: string;
    };

function pushAgentNotes(lines: ScanLine[], assessment: AchillesAssessment) {
  const log = Array.isArray(assessment.stats.agentLog) ? assessment.stats.agentLog : [];
  log.slice(0, 80).forEach((item, index) => {
    const row = asRecord(item);
    const text = typeof row.text === 'string' ? row.text.trim() : '';
    if (!text) return;
    lines.push({
      id: `${assessment.id}-agent-note-${index}`,
      role: 'assistant',
      engine: 'agent',
      status: 'done',
      text,
    });
  });
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function phaseStatus(value: unknown): string {
  return String(value ?? '').toLowerCase();
}

function categoryOf(finding: AchillesFinding): string {
  return finding.category.toLowerCase();
}

export function findingMatchesEngine(finding: AchillesFinding, engine: EngineFilter): boolean {
  if (engine === 'all') return true;
  if (engine === 'fingerprint') return false;
  if (engine === 'intel') {
    return (
      finding.evidence.inKev === true ||
      typeof finding.evidence.epss === 'number' ||
      typeof finding.evidence.cvss === 'number'
    );
  }
  if (engine === 'investigate') {
    return asRecord(finding.evidence.investigation).needsAgent === true;
  }
  if (engine === 'agent') {
    return finding.evidence.source === 'agent' || finding.evidence.engine === 'achilles-agent-v0';
  }
  const category = categoryOf(finding);
  if (engine === 'surfaces') {
    return category === 'surface' || category === 'surfaces';
  }
  if (category === 'delta') {
    return engine === 'delta';
  }
  if (typeof finding.evidence.kind === 'string' && finding.evidence.kind === engine) {
    return true;
  }
  return category === engine;
}

function isActiveFinding(finding: AchillesFinding): boolean {
  return finding.state === 'open' || finding.state === 'confirmed';
}

function countByEngine(findings: AchillesFinding[], engine: ScanEngine): number {
  return findings.filter(
    (finding) => isActiveFinding(finding) && findingMatchesEngine(finding, engine)
  ).length;
}

export function detectedSurfacesOf(assessment: AchillesAssessment | null): DetectedSurface[] {
  const raw = assessment?.stats.detectedSurfaces;
  if (!Array.isArray(raw)) return [];
  const out: DetectedSurface[] = [];
  for (const item of raw) {
    const row = asRecord(item);
    const paths = Array.isArray(row.paths)
      ? row.paths.filter((path): path is string => typeof path === 'string')
      : [];
    out.push({
      id: String(row.id ?? ''),
      label: String(row.label ?? row.id ?? 'Surface'),
      paths,
    });
  }
  return out;
}

export type StartupPath = {
  kind: string;
  path: string;
  command?: string;
  note: string;
};

export function startupPathsOf(assessment: AchillesAssessment | null): StartupPath[] {
  const raw = assessment?.stats.startupPaths;
  if (!Array.isArray(raw)) return [];
  const out: StartupPath[] = [];
  for (const item of raw) {
    const row = asRecord(item);
    const command = typeof row.command === 'string' ? row.command : undefined;
    out.push({
      kind: String(row.kind ?? 'start'),
      path: String(row.path ?? ''),
      command,
      note: String(row.note ?? ''),
    });
  }
  return out;
}

export function indexedFilesOf(assessment: AchillesAssessment | null): string[] {
  const raw = assessment?.stats.indexedFiles;
  if (!Array.isArray(raw)) return [];
  return raw.filter((path): path is string => typeof path === 'string' && path.length > 0);
}

export function filesIndexedCount(assessment: AchillesAssessment | null): number {
  const listed = indexedFilesOf(assessment).length;
  if (listed > 0) return listed;
  return asNumber(assessment?.stats.filesIndexed) ?? 0;
}

function engineDetail(
  engine: ScanEngine,
  assessment: AchillesAssessment,
  findings: AchillesFinding[]
): { detailKey: 'files' | 'findings'; detailCount: number } | undefined {
  if (engine === 'fingerprint') {
    const filesIndexed = filesIndexedCount(assessment);
    if (filesIndexed > 0) {
      return { detailKey: 'files', detailCount: filesIndexed };
    }
  }
  if (engine === 'agent') {
    const reviewed = asNumber(assessment.stats.agentReviewed) ?? 0;
    const units = asNumber(assessment.stats.agentUnits) ?? 0;
    const total = reviewed + units;
    if (total > 0) {
      return { detailKey: 'findings', detailCount: total };
    }
  }
  const fromStats = asNumber(assessment.stats[engine]);
  if (fromStats != null) {
    return { detailKey: 'findings', detailCount: fromStats };
  }
  const counted = countByEngine(findings, engine);
  if (counted > 0) {
    return { detailKey: 'findings', detailCount: counted };
  }
  return undefined;
}

export function buildScanTranscript(
  assessment: AchillesAssessment | null,
  findings: AchillesFinding[],
  userText: string | null
): ScanLine[] {
  if (!assessment) return [];

  const lines: ScanLine[] = [];
  if (userText) {
    lines.push({ id: `user-${assessment.id}`, role: 'user', text: userText });
  }

  for (const engine of ENGINE_ORDER) {
    const status = phaseStatus(assessment.phases[engine]);
    if (!status || status === 'queued') continue;

    if (status === 'skipped') {
      lines.push({
        id: `${assessment.id}-${engine}-skipped`,
        role: 'assistant',
        engine,
        status: 'skipped',
      });
      continue;
    }

    if (status === 'running' || status === 'paused') {
      lines.push({
        id: `${assessment.id}-${engine}-running`,
        role: 'assistant',
        engine,
        status: 'running',
        live: true,
      });
      if (engine === 'agent') {
        pushAgentNotes(lines, assessment);
      }
      continue;
    }

    if (status === 'done' || status === 'completed') {
      const detail = engineDetail(engine, assessment, findings);
      lines.push({
        id: `${assessment.id}-${engine}-done`,
        role: 'assistant',
        engine,
        status: 'done',
        detailKey: detail?.detailKey,
        detailCount: detail?.detailCount,
      });
      if (engine === 'agent') {
        pushAgentNotes(lines, assessment);
      }
    }
  }

  if (assessment.status === 'paused') {
    lines.push({
      id: `${assessment.id}-paused`,
      role: 'assistant',
      status: 'paused',
      live: true,
    });
  } else if (assessment.status === 'cancelled' || assessment.status === 'partial') {
    lines.push({
      id: `${assessment.id}-cancelled`,
      role: 'assistant',
      status: 'summary',
    });
  } else if (assessment.status === 'failed') {
    lines.push({
      id: `${assessment.id}-failed`,
      role: 'assistant',
      status: 'error',
    });
  } else if (assessment.status === 'completed') {
    lines.push({
      id: `${assessment.id}-complete`,
      role: 'assistant',
      status: 'summary',
      detailKey: 'findings',
      detailCount: assessment.openFindingCount,
    });
  }

  return lines;
}

export function relativeTimeFrom(iso: string, nowMs = Date.now()): {
  value: number;
  unit: Intl.RelativeTimeFormatUnit;
} | null {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  const deltaSec = Math.round((then - nowMs) / 1000);
  const abs = Math.abs(deltaSec);
  if (abs < 60) return { value: deltaSec, unit: 'second' };
  if (abs < 3600) return { value: Math.round(deltaSec / 60), unit: 'minute' };
  if (abs < 86400) return { value: Math.round(deltaSec / 3600), unit: 'hour' };
  if (abs < 86400 * 30) return { value: Math.round(deltaSec / 86400), unit: 'day' };
  return { value: Math.round(deltaSec / (86400 * 30)), unit: 'month' };
}

export function runningEngine(assessment: AchillesAssessment | null): string | null {
  if (!assessment || (assessment.status !== 'running' && assessment.status !== 'queued')) {
    return null;
  }
  for (const engine of ENGINE_ORDER) {
    if (phaseStatus(assessment.phases[engine]) === 'running') {
      return engine;
    }
  }
  return 'fingerprint';
}

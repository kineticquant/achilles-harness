import { getAcpClient } from './acpConnection';

export type AchillesAssessment = {
  id: string;
  engagementId: string;
  workingDir: string;
  sessionId?: string | null;
  mode: string;
  status: string;
  startedAt: string;
  finishedAt?: string | null;
  updatedAt: string;
  phases: Record<string, unknown>;
  stats: Record<string, unknown>;
  errorMessage?: string | null;
  trigger: string;
  parentAssessmentId?: string | null;
  openFindingCount: number;
};

export type AchillesFinding = {
  id: string;
  engagementId: string;
  assessmentId: string;
  lastSeenAssessmentId: string;
  fingerprint: string;
  state: string;
  severity: string;
  confidence: string;
  category: string;
  ruleId: string;
  title: string;
  description: string;
  path?: string | null;
  lineStart?: number | null;
  lineEnd?: number | null;
  cwe: unknown;
  cve: unknown;
  evidence: Record<string, unknown>;
  firstSeenAt: string;
  lastSeenAt: string;
};

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function mapAssessment(raw: Record<string, unknown>): AchillesAssessment {
  return {
    id: String(raw.id ?? ''),
    engagementId: String(raw.engagementId ?? ''),
    workingDir: String(raw.workingDir ?? ''),
    sessionId: (raw.sessionId as string | null) ?? null,
    mode: String(raw.mode ?? 'quick'),
    status: String(raw.status ?? 'running'),
    startedAt: String(raw.startedAt ?? ''),
    finishedAt: (raw.finishedAt as string | null) ?? null,
    updatedAt: String(raw.updatedAt ?? ''),
    phases: asRecord(raw.phases),
    stats: asRecord(raw.stats),
    errorMessage: (raw.errorMessage as string | null) ?? null,
    trigger: String(raw.trigger ?? 'scan_cta'),
    parentAssessmentId: (raw.parentAssessmentId as string | null) ?? null,
    openFindingCount: Number(raw.openFindingCount ?? 0),
  };
}

function mapFinding(raw: Record<string, unknown>): AchillesFinding {
  return {
    id: String(raw.id ?? ''),
    engagementId: String(raw.engagementId ?? ''),
    assessmentId: String(raw.assessmentId ?? ''),
    lastSeenAssessmentId: String(raw.lastSeenAssessmentId ?? ''),
    fingerprint: String(raw.fingerprint ?? ''),
    state: String(raw.state ?? 'open'),
    severity: String(raw.severity ?? 'medium'),
    confidence: String(raw.confidence ?? 'high'),
    category: String(raw.category ?? ''),
    ruleId: String(raw.ruleId ?? ''),
    title: String(raw.title ?? ''),
    description: String(raw.description ?? ''),
    path: (raw.path as string | null) ?? null,
    lineStart: (raw.lineStart as number | null) ?? null,
    lineEnd: (raw.lineEnd as number | null) ?? null,
    cwe: raw.cwe,
    cve: raw.cve,
    evidence: asRecord(raw.evidence),
    firstSeenAt: String(raw.firstSeenAt ?? ''),
    lastSeenAt: String(raw.lastSeenAt ?? ''),
  };
}

export async function acpStartAssessment(
  workingDir: string,
  options?: { sessionId?: string; parentAssessmentId?: string }
): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/start', {
    workingDir,
    ...(options?.sessionId ? { sessionId: options.sessionId } : {}),
    ...(options?.parentAssessmentId
      ? { parentAssessmentId: options.parentAssessmentId }
      : {}),
    mode: 'quick',
  });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpGetAssessment(assessmentId: string): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/get', { assessmentId });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpListAssessments(workingDir?: string): Promise<AchillesAssessment[]> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/list', {
    ...(workingDir ? { workingDir } : {}),
  });
  const list = Array.isArray(raw.assessments) ? raw.assessments : [];
  return list.map((item) => mapAssessment(asRecord(item)));
}

export async function acpListFindings(options: {
  assessmentId?: string;
  workingDir?: string;
}): Promise<AchillesFinding[]> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/findings/list', {
    ...(options.assessmentId ? { assessmentId: options.assessmentId } : {}),
    ...(options.workingDir ? { workingDir: options.workingDir } : {}),
  });
  const list = Array.isArray(raw.findings) ? raw.findings : [];
  return list.map((item) => mapFinding(asRecord(item)));
}

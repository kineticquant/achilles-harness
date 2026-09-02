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
  baseGitSha?: string | null;
  headGitSha?: string | null;
  contentFingerprint?: string | null;
  modelClass?: string | null;
  openFindingCount: number;
  newFindingCount?: number | null;
  goneFindingCount?: number | null;
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
  statusReason?: string | null;
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
    baseGitSha: (raw.baseGitSha as string | null) ?? null,
    headGitSha: (raw.headGitSha as string | null) ?? null,
    contentFingerprint: (raw.contentFingerprint as string | null) ?? null,
    modelClass: (raw.modelClass as string | null) ?? null,
    openFindingCount: Number(raw.openFindingCount ?? 0),
    newFindingCount:
      raw.newFindingCount == null || raw.newFindingCount === ''
        ? null
        : Number(raw.newFindingCount),
    goneFindingCount:
      raw.goneFindingCount == null || raw.goneFindingCount === ''
        ? null
        : Number(raw.goneFindingCount),
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
    statusReason: (raw.statusReason as string | null) ?? null,
  };
}

export async function acpStartAssessment(
  workingDir: string,
  options?: {
    sessionId?: string;
    parentAssessmentId?: string;
    mode?: string;
    includeVendor?: boolean;
    scanLiterals?: boolean;
    scanDelta?: boolean;
    depth?: string;
    resumeAssessmentId?: string;
    maxDurationSecs?: number;
    maxCostUsd?: number;
  }
): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/start', {
    workingDir,
    ...(options?.sessionId ? { sessionId: options.sessionId } : {}),
    ...(options?.parentAssessmentId
      ? { parentAssessmentId: options.parentAssessmentId }
      : {}),
    ...(options?.resumeAssessmentId
      ? { resumeAssessmentId: options.resumeAssessmentId }
      : {}),
    ...(options?.maxDurationSecs != null
      ? { maxDurationSecs: options.maxDurationSecs }
      : {}),
    ...(options?.maxCostUsd != null ? { maxCostUsd: options.maxCostUsd } : {}),
    mode: options?.mode ?? 'quick',
    includeVendor: options?.includeVendor ?? false,
    scanLiterals: options?.scanLiterals ?? false,
    scanDelta: options?.scanDelta ?? false,
    depth: options?.depth ?? 'fast',
  });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpCancelAssessment(assessmentId: string): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/cancel', {
    assessmentId,
  });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpPauseAssessment(
  assessmentId: string,
  paused: boolean
): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/pause', {
    assessmentId,
    paused,
  });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpGetAssessment(assessmentId: string): Promise<AchillesAssessment> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/get', { assessmentId });
  return mapAssessment(asRecord(raw.assessment));
}

export async function acpListAssessments(options?: {
  workingDir?: string;
  sessionId?: string;
}): Promise<AchillesAssessment[]> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/assessments/list', {
    ...(options?.workingDir ? { workingDir: options.workingDir } : {}),
    ...(options?.sessionId ? { sessionId: options.sessionId } : {}),
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

export async function acpSetFindingState(
  findingId: string,
  state: string,
  reason?: string
): Promise<AchillesFinding> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/findings/setState', {
    findingId,
    state,
    ...(reason ? { reason } : {}),
  });
  return mapFinding(asRecord(raw.finding));
}

export async function acpRunUtils(options: {
  workingDir: string;
  action: string;
  path?: string;
  text?: string;
  passphrase?: string;
  expected?: string;
  confirm?: boolean;
}): Promise<Record<string, unknown>> {
  const client = await getAcpClient();
  const raw = await client.extMethod('_achilles/unstable/utils/run', {
    workingDir: options.workingDir,
    action: options.action,
    ...(options.path ? { path: options.path } : {}),
    ...(options.text ? { text: options.text } : {}),
    ...(options.passphrase ? { passphrase: options.passphrase } : {}),
    ...(options.expected ? { expected: options.expected } : {}),
    ...(options.confirm ? { confirm: true } : {}),
  });
  return asRecord(raw.result);
}

import { AppEvents } from '../../constants/events';
import { createSession } from '../../sessions';
import { acpListRecentSessions, acpRenameSession } from '../../acp/sessions';
import {
  acpListAssessments,
  acpStartAssessment,
  type AchillesAssessment,
} from '../../acp/achilles';
import type { FixedExtensionEntry } from '../ConfigContext';
import { normalizeProjectPath } from '../../utils/projectSessions';

const scanSessionByAssessment = new Map<string, string>();
const assessmentByScanSession = new Map<string, string>();

export const SCAN_SESSION_NAME_PREFIX = 'Scan · ';

/** Desktop ACP sessions are UUIDs. CLI leftover ids look like `20260831_1`. */
export function isDesktopChatSessionId(sessionId: string | null | undefined): sessionId is string {
  if (!sessionId?.trim()) return false;
  return !/^\d{8}_\d+$/.test(sessionId);
}

export function scanSessionTitle(workingDir: string): string {
  const normalized = normalizeProjectPath(workingDir);
  const leaf = normalized.split('/').filter(Boolean).pop() || workingDir;
  return `${SCAN_SESSION_NAME_PREFIX}${leaf}`;
}

export function rememberScanSession(sessionId: string, assessmentId: string) {
  if (!isDesktopChatSessionId(sessionId)) return;
  scanSessionByAssessment.set(assessmentId, sessionId);
  assessmentByScanSession.set(sessionId, assessmentId);
}

export function rememberAssessments(assessments: Array<{ id: string; sessionId?: string | null }>) {
  // lists are newest-first; keep the first session→assessment mapping
  const seenSessions = new Set<string>();
  for (const assessment of assessments) {
    if (!isDesktopChatSessionId(assessment.sessionId)) continue;
    scanSessionByAssessment.set(assessment.id, assessment.sessionId);
    if (seenSessions.has(assessment.sessionId)) continue;
    seenSessions.add(assessment.sessionId);
    assessmentByScanSession.set(assessment.sessionId, assessment.id);
  }
}

export function forgetScanSession(sessionId: string) {
  const assessmentId = assessmentByScanSession.get(sessionId);
  assessmentByScanSession.delete(sessionId);
  if (assessmentId) {
    scanSessionByAssessment.delete(assessmentId);
  }
}

export function assessmentIdForScanSession(sessionId: string): string | undefined {
  return assessmentByScanSession.get(sessionId);
}

export function sessionIdForAssessment(assessmentId: string): string | undefined {
  return scanSessionByAssessment.get(assessmentId);
}

/** The session that ran this scan, not a leftover Scan History duplicate. */
export function pickScanChatSession(options: {
  assessmentId: string;
  assessmentSessionId?: string | null;
  sessionId?: string | null;
  urlSessionId?: string | null;
}): string | null {
  const candidates = [
    options.sessionId,
    options.assessmentSessionId,
    sessionIdForAssessment(options.assessmentId),
    options.urlSessionId,
  ];
  for (const id of candidates) {
    if (isDesktopChatSessionId(id)) {
      rememberScanSession(id, options.assessmentId);
      return id;
    }
  }
  return null;
}

export async function findExistingScanSessionForDir(workingDir: string): Promise<string | null> {
  const want = normalizeProjectPath(workingDir);
  const wantTitle = scanSessionTitle(workingDir).toLowerCase();
  if (!want && !wantTitle) return null;
  try {
    const recent = await acpListRecentSessions(80);
    const match = recent.find((session) => {
      if (!isDesktopChatSessionId(session.id) || !isScanHistorySession(session)) {
        return false;
      }
      if (want && normalizeProjectPath(session.workingDir) === want) {
        return true;
      }
      return session.name.trim().toLowerCase() === wantTitle;
    });
    return match?.id ?? null;
  } catch (error) {
    console.error('Failed to list scan sessions:', error);
    return null;
  }
}

export function isScanHistorySession(session: { id: string; name: string }): boolean {
  return (
    Boolean(assessmentIdForScanSession(session.id)) ||
    session.name.startsWith(SCAN_SESSION_NAME_PREFIX)
  );
}

function pickListedAssessment(
  listed: AchillesAssessment[],
  sessionId: string,
  allowUnrelated: boolean
): AchillesAssessment | undefined {
  const forSession = listed.filter((assessment) => assessment.sessionId === sessionId);
  const pool = forSession.length > 0 ? forSession : allowUnrelated ? listed : [];
  return pool.find((assessment) => assessment.openFindingCount > 0) ?? pool[0];
}

export async function resolveScanAssessmentId(
  sessionId: string,
  workingDir?: string,
  options?: { fallbackToWorkingDir?: boolean }
): Promise<string | undefined> {
  const cached = assessmentIdForScanSession(sessionId);
  if (cached) {
    return cached;
  }
  const listed = await acpListAssessments({ sessionId });
  let match = pickListedAssessment(listed, sessionId, false);
  if (!match && options?.fallbackToWorkingDir && workingDir) {
    const byDir = await acpListAssessments({ workingDir });
    match = pickListedAssessment(byDir, sessionId, true);
  }
  if (!match) {
    return undefined;
  }
  rememberScanSession(sessionId, match.id);
  return match.id;
}

/** Scan History rows should open the findings workbench, not Pair chat. */
export async function destinationForHistorySession(session: {
  id: string;
  name: string;
  workingDir?: string;
}): Promise<{ view: 'findings' | 'pair'; assessmentId?: string }> {
  const scan = isScanHistorySession(session);
  try {
    const assessmentId = await resolveScanAssessmentId(session.id, session.workingDir, {
      fallbackToWorkingDir: scan,
    });
    if (assessmentId) {
      return { view: 'findings', assessmentId };
    }
    if (scan) {
      return { view: 'findings' };
    }
  } catch (error) {
    console.error('Failed to resolve scan session:', error);
    if (scan) {
      return { view: 'findings' };
    }
  }
  return { view: 'pair' };
}

export async function resolveScanChatSession(options: {
  assessmentId: string;
  assessmentSessionId?: string | null;
  sessionId?: string | null;
  urlSessionId?: string | null;
  workingDir: string;
}): Promise<string | null> {
  const picked = pickScanChatSession(options);
  if (picked) {
    return picked;
  }
  const listed = await acpListAssessments({ workingDir: options.workingDir }).catch(() => []);
  const fromDir = listed.find((assessment) => assessment.id === options.assessmentId);
  if (isDesktopChatSessionId(fromDir?.sessionId)) {
    rememberScanSession(fromDir.sessionId, options.assessmentId);
    return fromDir.sessionId;
  }
  const all = await acpListAssessments().catch(() => []);
  const row = all.find((assessment) => assessment.id === options.assessmentId);
  if (isDesktopChatSessionId(row?.sessionId)) {
    rememberScanSession(row.sessionId, options.assessmentId);
    return row.sessionId;
  }
  const existing = await findExistingScanSessionForDir(options.workingDir);
  if (existing) {
    rememberScanSession(existing, options.assessmentId);
    return existing;
  }
  return null;
}

const ensureScanChatInFlight = new Map<string, Promise<string>>();

export async function ensureScanChatSession(options: {
  workingDir: string;
  assessmentId: string;
  extensionsList?: FixedExtensionEntry[];
}): Promise<string> {
  const resolved = await resolveScanChatSession({
    assessmentId: options.assessmentId,
    workingDir: options.workingDir,
  });
  if (resolved) {
    return resolved;
  }
  const pending = ensureScanChatInFlight.get(options.assessmentId);
  if (pending) {
    return pending;
  }
  const created = (async () => {
    const again = await resolveScanChatSession({
      assessmentId: options.assessmentId,
      workingDir: options.workingDir,
    });
    if (again) {
      return again;
    }
    const session = await createSession(options.workingDir, {
      allExtensions: options.extensionsList,
    });
    const title = scanSessionTitle(options.workingDir);
    try {
      await acpRenameSession(session.id, title);
    } catch (error) {
      console.error('Failed to name scan session:', error);
    }
    window.dispatchEvent(
      new CustomEvent(AppEvents.SESSION_CREATED, {
        detail: {
          session: {
            ...session,
            name: title,
            user_set_name: true,
          },
        },
      })
    );
    window.dispatchEvent(
      new CustomEvent(AppEvents.SESSION_RENAMED, {
        detail: { sessionId: session.id, newName: title, userInitiated: true },
      })
    );
    rememberScanSession(session.id, options.assessmentId);
    return session.id;
  })();
  ensureScanChatInFlight.set(options.assessmentId, created);
  try {
    return await created;
  } finally {
    ensureScanChatInFlight.delete(options.assessmentId);
  }
}

export async function startScanSession(options: {
  workingDir: string;
  mode: 'quick' | 'diff';
  includeVendor: boolean;
  depth: string;
  scanLiterals?: boolean;
  scanDelta?: boolean;
  parentAssessmentId?: string;
  resumeAssessmentId?: string;
  existingSessionId?: string | null;
  extensionsList?: FixedExtensionEntry[];
}): Promise<{ assessment: AchillesAssessment; sessionId: string }> {
  let sessionId = isDesktopChatSessionId(options.existingSessionId)
    ? options.existingSessionId
    : '';

  if (!sessionId) {
    sessionId = (await findExistingScanSessionForDir(options.workingDir)) ?? '';
  }

  if (!sessionId) {
    const session = await createSession(options.workingDir, {
      allExtensions: options.extensionsList,
    });
    sessionId = session.id;
    const title = scanSessionTitle(options.workingDir);
    try {
      await acpRenameSession(sessionId, title);
    } catch (error) {
      console.error('Failed to name scan session:', error);
    }
    window.dispatchEvent(
      new CustomEvent(AppEvents.SESSION_CREATED, {
        detail: {
          session: {
            ...session,
            name: title,
            user_set_name: true,
          },
        },
      })
    );
    window.dispatchEvent(
      new CustomEvent(AppEvents.SESSION_RENAMED, {
        detail: { sessionId, newName: title, userInitiated: true },
      })
    );
  }

  const assessment = await acpStartAssessment(options.workingDir, {
    sessionId,
    parentAssessmentId: options.parentAssessmentId,
    resumeAssessmentId: options.resumeAssessmentId,
    mode: options.mode,
    includeVendor: options.includeVendor,
    scanLiterals: options.scanLiterals ?? false,
    scanDelta: options.scanDelta ?? false,
    depth: options.depth,
  });
  rememberScanSession(sessionId, assessment.id);
  return { assessment, sessionId };
}

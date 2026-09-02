import type { SessionListItem } from '../acp/sessions';

export interface ProjectGroup {
  path: string;
  label: string;
  sessions: SessionListItem[];
  lastActivityAt: string;
}

function getSessionActivityTime(session: SessionListItem): string {
  return session.lastMessageAt ?? session.updatedAt;
}

const UNKNOWN_PROJECT_LABEL = 'Unknown';

/** Git Bash `/h/foo`, Cygwin `/cygdrive/h/foo`, WSL `/mnt/h/foo` → `h:/foo`. */
function windowsPathFromPosixDrive(path: string): string {
  const cygwin = path.match(/^\/cygdrive\/([a-zA-Z])(\/.*)?$/i);
  if (cygwin) {
    return `${cygwin[1].toLowerCase()}:${cygwin[2] ?? ''}`;
  }
  const wsl = path.match(/^\/mnt\/([a-zA-Z])(\/.*)?$/i);
  if (wsl) {
    return `${wsl[1].toLowerCase()}:${wsl[2] ?? ''}`;
  }
  const gitBash = path.match(/^\/([a-zA-Z])(\/.*)$/);
  if (gitBash) {
    return `${gitBash[1].toLowerCase()}:${gitBash[2]}`;
  }
  return path;
}

export function normalizeProjectPath(workingDir: string): string {
  const trimmed = workingDir.trim();
  if (!trimmed) {
    return '';
  }

  let normalized = trimmed.replace(/\\/g, '/');
  normalized = normalized.replace(/^\/\/\?\/UNC\//i, '//').replace(/^\/\/\?\//, '').replace(/^\/\?\//, '');
  normalized = normalized.replace(/\/+/g, '/').replace(/\/+$/, '');
  if (!normalized) {
    return trimmed;
  }

  normalized = windowsPathFromPosixDrive(normalized);

  if (/^[a-zA-Z]:/.test(normalized)) {
    normalized = normalized.toLowerCase();
  }

  return normalized;
}

/** SCAN HISTORY shows one thread per workspace, not every leftover duplicate. */
export function collapseScanHistorySessions(
  sessions: SessionListItem[],
  keepId?: string
): SessionListItem[] {
  const newestFirst = [...sessions].sort(
    (a, b) =>
      new Date(getSessionActivityTime(b)).getTime() - new Date(getSessionActivityTime(a)).getTime()
  );
  const byProject = new Map<string, SessionListItem>();
  for (const session of newestFirst) {
    const key = normalizeProjectPath(session.workingDir) || `id:${session.id}`;
    if (!byProject.has(key)) {
      byProject.set(key, session);
    }
  }
  const collapsed = [...byProject.values()];
  if (keepId && !collapsed.some((session) => session.id === keepId)) {
    const keep = sessions.find((session) => session.id === keepId);
    if (keep) {
      collapsed.push(keep);
    }
  }

  collapsed.sort(
    (a, b) =>
      new Date(getSessionActivityTime(b)).getTime() - new Date(getSessionActivityTime(a)).getTime()
  );

  const byTitle = new Map<string, SessionListItem>();
  for (const session of collapsed) {
    const titleKey = session.name.trim().toLowerCase();
    if (!byTitle.has(titleKey)) {
      byTitle.set(titleKey, session);
    }
  }
  const titled = [...byTitle.values()];
  if (keepId && !titled.some((session) => session.id === keepId)) {
    const keep = collapsed.find((session) => session.id === keepId);
    if (keep) {
      titled.push(keep);
    }
  }
  return titled.sort(
    (a, b) =>
      new Date(getSessionActivityTime(b)).getTime() - new Date(getSessionActivityTime(a)).getTime()
  );
}

export function getProjectLabel(workingDir: string): string {
  const normalized = workingDir.trim();
  if (!normalized) {
    return UNKNOWN_PROJECT_LABEL;
  }

  const withoutTrailingSeparators = normalizeProjectPath(workingDir);
  if (!withoutTrailingSeparators) {
    return normalized;
  }

  const parts = withoutTrailingSeparators.split(/[\\/]+/);
  return parts[parts.length - 1] || normalized;
}

export function groupSessionsByProject(sessions: SessionListItem[]): ProjectGroup[] {
  const groups = new Map<string, SessionListItem[]>();

  for (const session of sessions) {
    const path = normalizeProjectPath(session.workingDir);
    const existing = groups.get(path);
    if (existing) {
      existing.push(session);
    } else {
      groups.set(path, [session]);
    }
  }

  const baseGroups = Array.from(groups.entries()).map(([path, projectSessions]) => {
    const sortedSessions = [...projectSessions].sort(
      (a, b) =>
        new Date(getSessionActivityTime(b)).getTime() -
        new Date(getSessionActivityTime(a)).getTime()
    );
    return {
      path,
      label: getProjectLabel(path),
      sessions: sortedSessions,
      lastActivityAt: getSessionActivityTime(sortedSessions[0] ?? { updatedAt: '' } as SessionListItem),
    };
  });

  const labelCounts = baseGroups.reduce((counts, group) => {
    counts.set(group.label, (counts.get(group.label) ?? 0) + 1);
    return counts;
  }, new Map<string, number>());

  return baseGroups
    .map((group) => ({
      ...group,
      label:
        (labelCounts.get(group.label) ?? 0) > 1
          ? getDisambiguatedProjectLabel(group.path)
          : group.label,
    }))
    .sort(
      (a, b) => new Date(b.lastActivityAt).getTime() - new Date(a.lastActivityAt).getTime()
    );
}

function getDisambiguatedProjectLabel(workingDir: string): string {
  const withoutTrailingSeparators = normalizeProjectPath(workingDir);
  if (!withoutTrailingSeparators) {
    return UNKNOWN_PROJECT_LABEL;
  }
  const parts = withoutTrailingSeparators.split(/[\\/]+/).filter(Boolean);
  if (parts.length >= 2) {
    return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
  }

  return getProjectLabel(workingDir);
}

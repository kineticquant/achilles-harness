import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  assessmentIdForScanSession,
  destinationForHistorySession,
  forgetScanSession,
  isDesktopChatSessionId,
  isScanHistorySession,
  pickScanChatSession,
  rememberScanSession,
  resolveScanAssessmentId,
  SCAN_SESSION_NAME_PREFIX,
  scanSessionTitle,
} from './startScanSession';

vi.mock('../../acp/achilles', () => ({
  acpListAssessments: vi.fn(),
  acpStartAssessment: vi.fn(),
}));

import { acpListAssessments } from '../../acp/achilles';

const listAssessments = vi.mocked(acpListAssessments);

function assessment(id: string, sessionId: string, openFindingCount = 0) {
  return {
    id,
    engagementId: 'eng',
    workingDir: '/repo',
    sessionId,
    mode: 'quick',
    status: 'completed',
    startedAt: '',
    updatedAt: '',
    phases: {},
    stats: {},
    trigger: 'scan_cta',
    openFindingCount,
  };
}

describe('resolveScanAssessmentId', () => {
  beforeEach(() => {
    listAssessments.mockReset();
    for (const id of ['sess-1', 'sess-2', 'sess-orphan', 'sess-scan', 'sess-mapped']) {
      forgetScanSession(id);
    }
  });

  it('returns a remembered mapping without listing assessments', async () => {
    rememberScanSession('sess-1', 'assess-1');
    expect(assessmentIdForScanSession('sess-1')).toBe('assess-1');
    await expect(resolveScanAssessmentId('sess-1')).resolves.toBe('assess-1');
    expect(listAssessments).not.toHaveBeenCalled();
  });

  it('looks up the latest assessment for a session and remembers it', async () => {
    listAssessments.mockResolvedValue([assessment('assess-2', 'sess-2')]);
    await expect(resolveScanAssessmentId('sess-2', '/repo')).resolves.toBe('assess-2');
    expect(listAssessments).toHaveBeenCalledWith({
      sessionId: 'sess-2',
    });
    expect(assessmentIdForScanSession('sess-2')).toBe('assess-2');
  });

  it('does not bind a scan row to an unrelated latest assessment', async () => {
    listAssessments.mockResolvedValue([assessment('assess-other', 'sess-other')]);
    await expect(resolveScanAssessmentId('sess-orphan', '/repo')).resolves.toBeUndefined();
    expect(assessmentIdForScanSession('sess-orphan')).toBeUndefined();
  });

  it('falls back to the workspace assessment for a Scan History thread', async () => {
    listAssessments.mockImplementation(async (options) => {
      if (options?.sessionId) return [];
      if (options?.workingDir === '/repo') return [assessment('assess-dir', 'sess-other', 3)];
      return [];
    });
    await expect(
      resolveScanAssessmentId('sess-orphan', '/repo', { fallbackToWorkingDir: true })
    ).resolves.toBe('assess-dir');
    expect(assessmentIdForScanSession('sess-orphan')).toBe('assess-dir');
  });
});

describe('destinationForHistorySession', () => {
  beforeEach(() => {
    listAssessments.mockReset();
    forgetScanSession('sess-orphan');
  });

  it('opens findings for a Scan History title even without a stored assessment id', async () => {
    listAssessments.mockResolvedValue([]);
    await expect(
      destinationForHistorySession({
        id: 'sess-orphan',
        name: `${SCAN_SESSION_NAME_PREFIX}village-chat`,
        workingDir: '/repo',
      })
    ).resolves.toMatchObject({ view: 'findings' });
  });

  it('opens pair chat for a normal session with no assessment', async () => {
    listAssessments.mockResolvedValue([]);
    await expect(
      destinationForHistorySession({
        id: 'sess-orphan',
        name: 'Review PR',
        workingDir: '/repo',
      })
    ).resolves.toEqual({ view: 'pair' });
  });
});

describe('isDesktopChatSessionId', () => {
  it('accepts ACP session ids and rejects CLI date ids', () => {
    expect(isDesktopChatSessionId('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')).toBe(true);
    expect(isDesktopChatSessionId('sess-1')).toBe(true);
    expect(isDesktopChatSessionId('20260831_1')).toBe(false);
    expect(isDesktopChatSessionId(null)).toBe(false);
  });
});

describe('isScanHistorySession', () => {
  it('matches remembered scan sessions even after rename', () => {
    rememberScanSession('sess-scan', 'assess-scan');
    expect(isScanHistorySession({ id: 'sess-scan', name: 'Renamed' })).toBe(true);
    forgetScanSession('sess-scan');
    expect(isScanHistorySession({ id: 'sess-scan', name: 'Renamed' })).toBe(false);
  });

  it('matches the scan title prefix without a remembered mapping', () => {
    expect(isScanHistorySession({ id: 'unknown', name: `${SCAN_SESSION_NAME_PREFIX}repo` })).toBe(
      true
    );
    expect(isScanHistorySession({ id: 'chat', name: 'Review PR' })).toBe(false);
  });
});

describe('pickScanChatSession', () => {
  it('keeps the thread already open in Findings', () => {
    expect(
      pickScanChatSession({
        assessmentId: 'assess-pick',
        assessmentSessionId: 'sess-scan',
        sessionId: 'sess-local',
        urlSessionId: 'sess-url',
      })
    ).toBe('sess-local');
  });

  it('uses the assessment session when Findings has no thread yet', () => {
    expect(
      pickScanChatSession({
        assessmentId: 'assess-pick',
        assessmentSessionId: 'sess-scan',
        urlSessionId: 'sess-url',
      })
    ).toBe('sess-scan');
  });

  it('falls back to a mapped or URL session when the assessment has a CLI id', () => {
    rememberScanSession('sess-mapped', 'assess-cli');
    expect(
      pickScanChatSession({
        assessmentId: 'assess-cli',
        assessmentSessionId: '20260831_1',
        urlSessionId: 'sess-url-2',
      })
    ).toBe('sess-mapped');
  });
});

describe('scanSessionTitle', () => {
  it('uses the folder leaf even for Windows extended paths', () => {
    expect(scanSessionTitle('\\\\?\\H:\\village\\village-chat')).toBe(
      `${SCAN_SESSION_NAME_PREFIX}village-chat`
    );
  });
});

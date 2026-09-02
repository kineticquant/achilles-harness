import { describe, expect, it } from 'vitest';
import {
  buildScanTranscript,
  ENGINE_GROUPS,
  ENGINE_ORDER,
  isScanKickoffText,
  relativeTimeFrom,
  scanDepthOf,
  startupPathsOf,
} from './scanEvents';
import type { AchillesAssessment, AchillesFinding } from '../../acp/achilles';

describe('isScanKickoffText', () => {
  it('matches the Scan and Scan-changed kickoff lines', () => {
    expect(isScanKickoffText('Scan my repo')).toBe(true);
    expect(isScanKickoffText('  Scan changed files  ')).toBe(true);
    expect(isScanKickoffText('Perform a Fast Scan on my repo')).toBe(true);
    expect(isScanKickoffText('Perform an Investigative Scan on my repo')).toBe(true);
    expect(isScanKickoffText('Perform a Deep Scan on changed files')).toBe(true);
  });

  it('leaves real follow-up questions alone', () => {
    expect(isScanKickoffText('What is the worst finding?')).toBe(false);
    expect(isScanKickoffText('Scan my repo please')).toBe(false);
    expect(isScanKickoffText('Perform a Fast Scan on my repo please')).toBe(false);
  });
});

describe('scanDepthOf', () => {
  it('reads scanDepth from assessment stats', () => {
    expect(scanDepthOf({ stats: { scanDepth: 'investigate' } } as never)).toBe('investigate');
    expect(scanDepthOf({ stats: { scanDepth: 'deep' } } as never)).toBe('deep');
    expect(scanDepthOf({ stats: {} } as never)).toBe('fast');
  });
});

describe('relativeTimeFrom', () => {
  it('picks minutes for a scan that finished under an hour ago', () => {
    const now = Date.parse('2026-08-29T19:00:00.000Z');
    expect(relativeTimeFrom('2026-08-29T18:40:00.000Z', now)).toEqual({
      value: -20,
      unit: 'minute',
    });
  });
});

describe('buildScanTranscript', () => {
  function assessment(stats: Record<string, unknown>): AchillesAssessment {
    return {
      id: 'a1',
      engagementId: 'e1',
      workingDir: '/repo',
      mode: 'quick',
      status: 'completed',
      startedAt: '2026-08-31T16:00:00.000Z',
      updatedAt: '2026-08-31T16:01:00.000Z',
      phases: {
        fingerprint: 'done',
        secrets: 'done',
        sast: 'done',
        sca: 'done',
        intel: 'done',
      },
      stats,
      trigger: 'scan_cta',
      openFindingCount: 5,
    };
  }

  function finding(
    partial: Partial<AchillesFinding> & Pick<AchillesFinding, 'id' | 'state'>
  ): AchillesFinding {
    return {
      engagementId: 'e1',
      assessmentId: 'a1',
      lastSeenAssessmentId: 'a1',
      fingerprint: partial.id,
      severity: 'medium',
      confidence: 'high',
      category: 'sca',
      ruleId: 'GHSA-p67v-3w7g-wjg7',
      title: 'old nokogiri advisory',
      description: '',
      cwe: [],
      cve: [],
      evidence: { epss: 0.01 },
      firstSeenAt: '2026-08-31T12:00:00.000Z',
      lastSeenAt: '2026-08-31T16:01:00.000Z',
      ...partial,
    };
  }

  it('does not treat closed SCA hits from a prior scan as known-threat matches', () => {
    const lines = buildScanTranscript(
      assessment({ sca: 0, intel: 0 }),
      [
        finding({ id: 'old-1', state: 'verified_fixed' }),
        finding({ id: 'old-2', state: 'verified_fixed' }),
      ],
      'Scan my repo'
    );
    const intel = lines.find((line) => line.role === 'assistant' && line.engine === 'intel');
    expect(intel).toMatchObject({ status: 'done', detailCount: 0 });
  });

  it('surfaces each AI inspection as its own transcript line', () => {
    const lines = buildScanTranscript(
      {
        ...assessment({
          agentReviewed: 1,
          agentUnits: 0,
          agentLog: [
            {
              text: 'AI review · app.js:12 — confirmed: innerHTML takes message body',
            },
          ],
        }),
        phases: {
          fingerprint: 'done',
          agent: 'done',
        },
      },
      [],
      'Perform an Investigative Scan on my repo'
    );
    expect(lines.some((line) => line.role === 'assistant' && 'text' in line && line.text?.includes('innerHTML'))).toBe(
      true
    );
  });
});

describe('startupPathsOf', () => {
  it('reads start commands from assessment stats', () => {
    const assessment = {
      stats: {
        startupPaths: [
          {
            kind: 'npm-script',
            path: 'package.json',
            command: 'node server.js',
            note: 'scripts.start',
          },
        ],
      },
    };
    expect(startupPathsOf(assessment as never)).toEqual([
      {
        kind: 'npm-script',
        path: 'package.json',
        command: 'node server.js',
        note: 'scripts.start',
      },
    ]);
  });
});

describe('ENGINE_GROUPS', () => {
  it('lists every scan engine exactly once', () => {
    const grouped = ENGINE_GROUPS.flatMap((group) => group.engines);
    expect([...grouped].sort()).toEqual([...ENGINE_ORDER].sort());
  });
});

describe('ENGINE_GROUPS', () => {
  it('lists every scan engine exactly once', () => {
    const grouped = ENGINE_GROUPS.flatMap((group) => group.engines);
    expect([...grouped].sort()).toEqual([...ENGINE_ORDER].sort());
  });
});

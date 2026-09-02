import { describe, expect, it } from 'vitest';
import { collapseScanHistorySessions, getProjectLabel, groupSessionsByProject } from '../utils/projectSessions';
import type { SessionListItem } from '../acp/sessions';

function makeSession(overrides: Partial<SessionListItem> = {}): SessionListItem {
  return {
    id: 'session-1',
    name: 'Session',
    messageCount: 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    workingDir: '/tmp/goose',
    ...overrides,
  };
}

describe('groupSessionsByProject', () => {
  it('groups sessions by normalized working directory', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'a', workingDir: '/tmp/goose' }),
      makeSession({ id: 'b', workingDir: '/tmp/goose/' }),
      makeSession({ id: 'c', workingDir: '  /tmp/goose//  ' }),
      makeSession({ id: 'd', workingDir: '/tmp/other' }),
    ]);

    expect(groups).toHaveLength(2);
    expect(groups.find((group) => group.path === '/tmp/goose')?.sessions.map((s) => s.id)).toEqual([
      'a',
      'b',
      'c',
    ]);
    expect(groups.find((group) => group.path === '/tmp/other')?.sessions.map((s) => s.id)).toEqual([
      'd',
    ]);
  });

  it('sorts project groups and sessions by session activity', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'old', workingDir: '/tmp/old', updatedAt: '2026-01-01T00:00:00.000Z' }),
      makeSession({
        id: 'middle-old',
        workingDir: '/tmp/middle',
        updatedAt: '2026-01-02T00:00:00.000Z',
      }),
      makeSession({
        id: 'middle-new',
        workingDir: '/tmp/middle',
        updatedAt: '2026-01-03T00:00:00.000Z',
      }),
      makeSession({
        id: 'renamed',
        workingDir: '/tmp/new',
        updatedAt: '2026-01-04T00:00:00.000Z',
        lastMessageAt: '2026-01-01T00:00:00.000Z',
      }),
      makeSession({
        id: 'active',
        workingDir: '/tmp/new',
        updatedAt: '2026-01-02T00:00:00.000Z',
        lastMessageAt: '2026-01-05T00:00:00.000Z',
      }),
    ]);

    expect(groups.map((group) => group.path)).toEqual(['/tmp/new', '/tmp/middle', '/tmp/old']);
    expect(groups[0].sessions.map((session) => session.id)).toEqual(['active', 'renamed']);
    expect(groups[1].sessions.map((session) => session.id)).toEqual(['middle-new', 'middle-old']);
  });

  it('handles missing working directories', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'a', workingDir: '' }),
      makeSession({ id: 'b', workingDir: '   ' }),
    ]);

    expect(groups).toHaveLength(1);
    expect(groups[0].path).toBe('');
    expect(groups[0].label).toBe('Unknown');
    expect(groups[0].sessions.map((session) => session.id)).toEqual(['a', 'b']);
  });

  it('disambiguates projects with the same basename', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'a', workingDir: '/Users/me/work/goose' }),
      makeSession({ id: 'b', workingDir: '/Users/me/forks/goose' }),
    ]);

    expect(groups.map((group) => group.label).sort()).toEqual(['forks/goose', 'work/goose']);
  });

  it('treats Windows slash and drive-letter variants as one project', () => {
    const groups = groupSessionsByProject([
      makeSession({
        id: 'a',
        workingDir: 'H:\\Arrav\\village\\village-chat',
      }),
      makeSession({
        id: 'b',
        workingDir: 'H:/Arrav/village/village-chat/',
      }),
      makeSession({
        id: 'c',
        workingDir: 'h:\\arrav\\village\\village-chat',
      }),
    ]);

    expect(groups).toHaveLength(1);
    expect(groups[0].sessions.map((session) => session.id).sort()).toEqual(['a', 'b', 'c']);
  });

  it('treats Windows extended paths as the same folder', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'ext', workingDir: '\\\\?\\H:\\village\\village-chat' }),
      makeSession({ id: 'plain', workingDir: 'H:\\village\\village-chat' }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].sessions.map((session) => session.id).sort()).toEqual(['ext', 'plain']);
  });

  it('treats Git Bash and Windows paths as one project', () => {
    const groups = groupSessionsByProject([
      makeSession({ id: 'win', workingDir: 'H:\\Arrav\\village\\village-chat' }),
      makeSession({ id: 'bash', workingDir: '/h/Arrav/village/village-chat' }),
      makeSession({ id: 'cyg', workingDir: '/cygdrive/h/Arrav/village/village-chat' }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].sessions.map((session) => session.id).sort()).toEqual(['bash', 'cyg', 'win']);
  });
});

describe('collapseScanHistorySessions', () => {
  it('keeps the newest scan per workspace and drops same-titled leftovers', () => {
    const collapsed = collapseScanHistorySessions([
      makeSession({
        id: 'old',
        name: 'Scan · village-chat',
        workingDir: 'H:\\Arrav\\village\\village-chat',
        updatedAt: '2026-01-01T00:00:00.000Z',
      }),
      makeSession({
        id: 'new',
        name: 'Scan · village-chat',
        workingDir: '/h/Arrav/village/village-chat',
        updatedAt: '2026-01-03T00:00:00.000Z',
      }),
      makeSession({
        id: 'other-path',
        name: 'Scan · village-chat',
        workingDir: 'H:/Arrav/village/village-chat',
        updatedAt: '2026-01-02T00:00:00.000Z',
      }),
    ]);
    expect(collapsed.map((session) => session.id)).toEqual(['new']);
  });
});

describe('getProjectLabel', () => {
  it('extracts readable labels from paths', () => {
    expect(getProjectLabel('/Users/me/work/goose')).toBe('goose');
    expect(getProjectLabel('/')).toBe('/');
    expect(getProjectLabel('')).toBe('Unknown');
    expect(getProjectLabel('C:\\Users\\me\\goose')).toBe('goose');
  });
});

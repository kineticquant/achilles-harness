import { describe, expect, it } from 'vitest';
import { relativeToWorkspace, TOOL_GROUPS, TOOLS } from './toolsCatalog';

describe('relativeToWorkspace', () => {
  it('strips the workspace prefix', () => {
    expect(relativeToWorkspace('H:/repo', 'H:/repo/src/a.txt')).toBe('src/a.txt');
  });

  it('leaves paths outside the workspace alone', () => {
    expect(relativeToWorkspace('H:/repo', 'C:/other/a.txt')).toBe('C:/other/a.txt');
  });
});

describe('TOOLS', () => {
  it('lists every grouped action once', () => {
    const grouped = TOOL_GROUPS.flatMap((group) => group.tools);
    expect([...grouped].sort()).toEqual([...TOOLS.map((t) => t.action)].sort());
  });
});

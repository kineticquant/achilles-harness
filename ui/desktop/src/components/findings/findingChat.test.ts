import { describe, expect, it } from 'vitest';
import type { AchillesFinding } from '../../acp/achilles';
import {
  attachFinding,
  composeFindingChatPayload,
  findingAsChatContext,
  findingAsEditorBrief,
  findingContextTitle,
  splitFindingChatPayload,
  ACHILLES_REPO,
  ACHILLES_SITE,
  EDITOR_BRIEF_LEAD,
} from './findingChat';

function finding(overrides: Partial<AchillesFinding> = {}): AchillesFinding {
  return {
    id: 'f-1',
    engagementId: 'e-1',
    assessmentId: 'a-1',
    lastSeenAssessmentId: 'a-1',
    fingerprint: 'fp',
    state: 'open',
    severity: 'high',
    confidence: 'high',
    category: 'secrets',
    ruleId: 'mongodb-url',
    title: 'MongoDB connection string with password',
    description: 'A connection string includes credentials.',
    path: 'leak.env',
    lineStart: 23,
    lineEnd: 23,
    cwe: ['CWE-798'],
    cve: null,
    evidence: { engine: 'achilles-secrets-v0' },
    firstSeenAt: '',
    lastSeenAt: '',
    ...overrides,
  };
}

describe('findingAsChatContext', () => {
  it('includes title, location, and description', () => {
    const context = findingAsChatContext(finding());
    expect(context).toContain('id=f-1');
    expect(context).toContain('title=MongoDB connection string with password');
    expect(context).toContain('location=leak.env:23');
    expect(context).toContain('A connection string includes credentials.');
    expect(context).toContain('Prefer they apply a patch in their usual editor');
    expect(context).toContain('Do not call appsec_scan');
  });

  it('includes a stored snippet when present', () => {
    const context = findingAsChatContext(
      finding({
        evidence: { preview: 'MONGO_URL=mongodb://user:pass@host' },
      })
    );
    expect(context).toContain('snippet:');
    expect(context).toContain('MONGO_URL=mongodb://user:pass@host');
  });
});

describe('attachFinding', () => {
  it('keeps the finding title for the composer chip', () => {
    const attached = attachFinding(finding());
    expect(attached.id).toBe('f-1');
    expect(attached.title).toBe('MongoDB connection string with password');
    expect(attached.context).toContain('rule=mongodb-url');
  });
});

describe('findingAsEditorBrief', () => {
  it('introduces Achilles and includes a thorough finding plus MCP close steps', () => {
    const text = findingAsEditorBrief(finding());
    expect(text.startsWith(EDITOR_BRIEF_LEAD)).toBe(true);
    expect(text).toContain(ACHILLES_SITE);
    expect(text).toContain(ACHILLES_REPO);
    expect(text).not.toContain('Paste this into your coding editor');
    expect(text).toContain('leak.env:23');
    expect(text).toContain('Rule: mongodb-url');
    expect(text).toContain('Confidence: high');
    expect(text).toContain('CWE: CWE-798');
    expect(text).toContain('engine: achilles-secrets-v0');
    expect(text).toContain('appsec_triage');
    expect(text).toContain('state=verified_fixed');
    expect(text).toContain('state=dismissed');
  });
});

describe('splitFindingChatPayload', () => {
  it('round-trips compose and extracts the title', () => {
    const context = findingAsChatContext(finding());
    const payload = composeFindingChatPayload(context, 'what does this mean');
    const split = splitFindingChatPayload(payload);
    expect(split).toEqual({ context, question: 'what does this mean' });
    expect(findingContextTitle(context)).toBe('MongoDB connection string with password');
  });

  it('leaves ordinary chat messages alone', () => {
    expect(splitFindingChatPayload('what does this mean')).toBeNull();
    expect(splitFindingChatPayload('User question:\nhello')).toBeNull();
  });
});

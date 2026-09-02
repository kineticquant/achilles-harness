import { describe, expect, it } from 'vitest';
import { composeScanFollowUp, scanAllowsFollowUpChat, scanIsBusy, visibleScanFollowUpText } from './scanChat';
import { isDesktopChatSessionId } from './startScanSession';

describe('scanAllowsFollowUpChat', () => {
  it.each(['fast', 'investigate', 'deep'] as const)(
    'allows follow-up chat after a completed %s scan',
    () => {
      expect(
        scanAllowsFollowUpChat({
          hasAssessment: true,
          scanning: false,
          status: 'completed',
        })
      ).toBe(true);
    }
  );

  it('allows chat after cancelled, failed, or partial scans', () => {
    for (const status of ['cancelled', 'failed', 'partial']) {
      expect(scanAllowsFollowUpChat({ hasAssessment: true, status })).toBe(true);
    }
  });

  it('allows chat even when the assessment still points at a CLI session id', () => {
    expect(isDesktopChatSessionId('20260831_1')).toBe(false);
    expect(
      scanAllowsFollowUpChat({
        hasAssessment: true,
        status: 'completed',
      })
    ).toBe(true);
  });

  it('hides follow-up chat while a scan is in flight', () => {
    expect(scanIsBusy({ scanning: true, status: 'completed' })).toBe(true);
    expect(scanAllowsFollowUpChat({ hasAssessment: true, scanning: true, status: 'completed' })).toBe(
      false
    );
    expect(scanAllowsFollowUpChat({ hasAssessment: true, status: 'running' })).toBe(false);
    expect(scanAllowsFollowUpChat({ hasAssessment: true, status: 'queued' })).toBe(false);
    expect(scanAllowsFollowUpChat({ hasAssessment: true, status: 'paused' })).toBe(false);
  });

  it('hides follow-up chat before any scan exists', () => {
    expect(scanAllowsFollowUpChat({ hasAssessment: false, status: 'completed' })).toBe(false);
  });
});

describe('composeScanFollowUp', () => {
  it('marks ordinary follow-ups so the model does not start a new scan', () => {
    const payload = composeScanFollowUp('what is worst');
    expect(payload).toContain('Do not call appsec_scan');
    expect(visibleScanFollowUpText(payload)).toBe('what is worst');
  });

  it('leaves finding payloads unchanged', () => {
    const finding = 'Achilles finding (id=f-1).\n\nUser question:\nexplain';
    expect(composeScanFollowUp(finding)).toBe(finding);
  });
});

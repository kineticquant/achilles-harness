/** Follow-up chat is available after any finished scan, including Fast. */

export function scanIsBusy(options: {
  scanning?: boolean;
  status?: string | null;
}): boolean {
  const status = options.status ?? '';
  return (
    Boolean(options.scanning) ||
    status === 'paused' ||
    status === 'running' ||
    status === 'queued'
  );
}

export function scanAllowsFollowUpChat(options: {
  hasAssessment: boolean;
  scanning?: boolean;
  status?: string | null;
}): boolean {
  return options.hasAssessment && !scanIsBusy(options);
}

export const SCAN_FOLLOWUP_LEAD =
  'Follow-up on the current Achilles scan. Do not call appsec_scan unless they explicitly ask to scan or rescan.\n\n';

export function composeScanFollowUp(text: string): string {
  if (text.startsWith(SCAN_FOLLOWUP_LEAD) || text.startsWith('Achilles finding (id=')) {
    return text;
  }
  return `${SCAN_FOLLOWUP_LEAD}${text}`;
}

export function visibleScanFollowUpText(text: string): string {
  if (text.startsWith(SCAN_FOLLOWUP_LEAD)) {
    return text.slice(SCAN_FOLLOWUP_LEAD.length);
  }
  return text;
}

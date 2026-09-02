import { useEffect, useMemo, useRef } from 'react';
import { Loader2 } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { ScrollArea, type ScrollAreaHandle } from '../ui/scroll-area';
import { formatMessageTimestamp } from '../../utils/timeUtils';
import { cn } from '../../utils';
import { type ScanLine } from './scanEvents';
import GooseMessage from '../GooseMessage';
import UserMessage from '../UserMessage';
import LoadingGoose from '../LoadingGoose';
import { ChatState } from '../../types/chatState';
import type { Message, NotificationEvent } from '../../types/message';
import { identifyConsecutiveToolCalls, isInChain } from '../../utils/toolCallChaining';

const i18n = defineMessages({
  empty: {
    id: 'findingsView.emptyTranscript',
    defaultMessage: 'Pick a workspace, then Scan.',
  },
  scanningFingerprint: {
    id: 'findingsView.scanningFingerprint',
    defaultMessage: 'Achilles is indexing the codebase…',
  },
  scanningSecrets: {
    id: 'findingsView.scanningSecrets',
    defaultMessage: 'Achilles is looking for potential secrets leaked or accidentally exposed in the code…',
  },
  scanningHistory: {
    id: 'findingsView.scanningHistory',
    defaultMessage: 'Achilles is checking git history for secrets that left the working tree…',
  },
  scanningSast: {
    id: 'findingsView.scanningSast',
    defaultMessage: 'Achilles is checking the code for known insecure patterns…',
  },
  scanningDelta: {
    id: 'findingsView.scanningDelta',
    defaultMessage:
      'Achilles is compacting local git changes and checking the logic they introduce against the rest of the tree…',
  },
  scanningLiterals: {
    id: 'findingsView.scanningLiterals',
    defaultMessage:
      'Achilles is checking source for hardcoded values (not a security scan — stability / config hygiene)…',
  },
  scanningInvestigate: {
    id: 'findingsView.scanningInvestigate',
    defaultMessage: 'Achilles is reviewing findings that need a closer look…',
  },
  scanningSurfaces: {
    id: 'findingsView.scanningSurfaces',
    defaultMessage: 'Achilles is mapping exposed attack surfaces…',
  },
  scanningHarden: {
    id: 'findingsView.scanningHarden',
    defaultMessage: 'Achilles is checking cookie, CORS, and CSP defaults in source…',
  },
  scanningSca: {
    id: 'findingsView.scanningSca',
    defaultMessage: 'Achilles is checking dependencies for known vulnerabilities…',
  },
    scanningIntel: {
    id: 'findingsView.scanningIntel',
    defaultMessage: 'Achilles is matching findings against known threats…',
  },
  scanningAgent: {
    id: 'findingsView.scanningAgent',
    defaultMessage:
      'Achilles is inspecting findings with the model (investigator + validator). Deep also walks functions…',
  },
  scanningWorkspace: {
    id: 'findingsView.scanningWorkspace',
    defaultMessage: 'Achilles is scanning the workspace…',
  },
  doneFingerprint: {
    id: 'findingsView.doneFingerprint',
    defaultMessage: 'Indexed {count} files',
  },
  doneFingerprintPlain: {
    id: 'findingsView.doneFingerprintPlain',
    defaultMessage: 'Finished indexing the codebase',
  },
  doneSecrets: {
    id: 'findingsView.doneSecrets',
    defaultMessage:
      '{count, plural, =0 {No potential leaked or exposed secrets found} one {Found 1 potential leaked or exposed secret} other {Found # potential leaked or exposed secrets}}',
  },
  doneSecretsPlain: {
    id: 'findingsView.doneSecretsPlain',
    defaultMessage: 'Finished looking for potential leaked secrets',
  },
  doneHistory: {
    id: 'findingsView.doneHistory',
    defaultMessage:
      '{count, plural, =0 {No secrets left in git history} one {Found 1 secret still in git history} other {Found # secrets still in git history}}',
  },
  doneHistoryPlain: {
    id: 'findingsView.doneHistoryPlain',
    defaultMessage: 'Finished checking git history for deleted secrets',
  },
  doneSast: {
    id: 'findingsView.doneSast',
    defaultMessage:
      '{count, plural, =0 {No insecure coding patterns found} one {Found 1 insecure coding pattern} other {Found # insecure coding patterns}}',
  },
  doneSastPlain: {
    id: 'findingsView.doneSastPlain',
    defaultMessage: 'Finished checking for insecure coding patterns',
  },
  doneDelta: {
    id: 'findingsView.doneDelta',
    defaultMessage:
      '{count, plural, =0 {No issues introduced by local changes} one {Found 1 issue introduced by local changes} other {Found # issues introduced by local changes}}',
  },
  doneDeltaPlain: {
    id: 'findingsView.doneDeltaPlain',
    defaultMessage: 'Finished comparing local changes to the rest of the tree',
  },
  doneLiterals: {
    id: 'findingsView.doneLiterals',
    defaultMessage:
      '{count, plural, =0 {No hardcoded values flagged (not a security check)} one {Flagged 1 hardcoded value (not a security finding)} other {Flagged # hardcoded values (not security findings)}}',
  },
  doneLiteralsPlain: {
    id: 'findingsView.doneLiteralsPlain',
    defaultMessage: 'Finished checking for hardcoded values (not a security scan)',
  },
  doneInvestigate: {
    id: 'findingsView.doneInvestigate',
    defaultMessage:
      '{count, plural, =0 {Investigation complete} one {Investigation complete · 1 finding still needs a closer look} other {Investigation complete · # findings still need a closer look}}',
  },
  doneInvestigatePlain: {
    id: 'findingsView.doneInvestigatePlain',
    defaultMessage: 'Investigation complete',
  },
  doneSurfaces: {
    id: 'findingsView.doneSurfaces',
    defaultMessage:
      '{count, plural, =0 {No exposed attack surfaces found} one {Found 1 exposed attack surface} other {Found # exposed attack surfaces}}',
  },
  doneSurfacesPlain: {
    id: 'findingsView.doneSurfacesPlain',
    defaultMessage: 'Finished mapping attack surfaces',
  },
  doneHarden: {
    id: 'findingsView.doneHarden',
    defaultMessage:
      '{count, plural, =0 {No cookie/CORS/CSP issues found} one {Found 1 cookie/CORS/CSP issue} other {Found # cookie/CORS/CSP issues}}',
  },
  doneHardenPlain: {
    id: 'findingsView.doneHardenPlain',
    defaultMessage: 'Finished checking cookie, CORS, and CSP defaults',
  },
  doneSca: {
    id: 'findingsView.doneSca',
    defaultMessage:
      '{count, plural, =0 {No known vulnerable dependencies found} one {Found 1 known vulnerable dependency} other {Found # known vulnerable dependencies}}',
  },
  doneScaPlain: {
    id: 'findingsView.doneScaPlain',
    defaultMessage: 'Finished checking dependencies',
  },
  doneIntel: {
    id: 'findingsView.doneIntel',
    defaultMessage:
      '{count, plural, =0 {No findings matched known threats} one {Matched 1 finding to known threats} other {Matched # findings to known threats}}',
  },
  doneIntelPlain: {
    id: 'findingsView.doneIntelPlain',
    defaultMessage: 'Finished matching threat intelligence',
  },
  doneAgent: {
    id: 'findingsView.doneAgent',
    defaultMessage:
      '{count, plural, =0 {AI inspection finished} one {AI inspected 1 item} other {AI inspected # items}}',
  },
  doneAgentPlain: {
    id: 'findingsView.doneAgentPlain',
    defaultMessage: 'Finished AI review',
  },
  skippedFingerprint: {
    id: 'findingsView.skippedFingerprint',
    defaultMessage: 'Indexing skipped',
  },
  skippedSecrets: {
    id: 'findingsView.skippedSecrets',
    defaultMessage: 'Secret scan skipped',
  },
  skippedHistory: {
    id: 'findingsView.skippedHistory',
    defaultMessage: 'Git-history secret scan skipped',
  },
  skippedSast: {
    id: 'findingsView.skippedSast',
    defaultMessage: 'Insecure-pattern scan skipped',
  },
  skippedDelta: {
    id: 'findingsView.skippedDelta',
    defaultMessage: 'Local-change comparison skipped',
  },
  skippedLiterals: {
    id: 'findingsView.skippedLiterals',
    defaultMessage: 'Hardcoded-value scan skipped',
  },
  skippedInvestigate: {
    id: 'findingsView.skippedInvestigate',
    defaultMessage: 'Investigation skipped',
  },
  skippedSurfaces: {
    id: 'findingsView.skippedSurfaces',
    defaultMessage: 'Attack-surface scan skipped',
  },
  skippedHarden: {
    id: 'findingsView.skippedHarden',
    defaultMessage: 'App-config hardening scan skipped',
  },
  skippedSca: {
    id: 'findingsView.skippedSca',
    defaultMessage: 'Dependency scan skipped',
  },
  skippedIntel: {
    id: 'findingsView.skippedIntel',
    defaultMessage: 'Threat-intel scan skipped',
  },
  skippedAgent: {
    id: 'findingsView.skippedAgent',
    defaultMessage: 'AI review skipped (no model, or Fast scan)',
  },
  scanComplete: {
    id: 'findingsView.scanCompleteLine',
    defaultMessage:
      '{count, plural, =0 {Scan complete · no open findings} one {Scan complete · 1 open finding} other {Scan complete · # open findings}}',
  },
  scanStopped: {
    id: 'findingsView.scanStoppedLine',
    defaultMessage: 'Scan stopped.',
  },
  scanPaused: {
    id: 'findingsView.scanPausedLine',
    defaultMessage: 'Scan paused.',
  },
  chatHint: {
    id: 'findingsView.chatHint',
    defaultMessage: 'Ask about these findings below.',
  },
});

function scanningText(intl: ReturnType<typeof useIntl>, engine?: string): string {
  switch (engine) {
    case 'fingerprint':
      return intl.formatMessage(i18n.scanningFingerprint);
    case 'secrets':
      return intl.formatMessage(i18n.scanningSecrets);
    case 'history':
      return intl.formatMessage(i18n.scanningHistory);
    case 'sast':
      return intl.formatMessage(i18n.scanningSast);
    case 'delta':
      return intl.formatMessage(i18n.scanningDelta);
    case 'literals':
      return intl.formatMessage(i18n.scanningLiterals);
    case 'investigate':
      return intl.formatMessage(i18n.scanningInvestigate);
    case 'surfaces':
      return intl.formatMessage(i18n.scanningSurfaces);
    case 'harden':
      return intl.formatMessage(i18n.scanningHarden);
    case 'sca':
      return intl.formatMessage(i18n.scanningSca);
    case 'intel':
      return intl.formatMessage(i18n.scanningIntel);
    case 'agent':
      return intl.formatMessage(i18n.scanningAgent);
    default:
      return intl.formatMessage(i18n.scanningWorkspace);
  }
}

function skippedText(intl: ReturnType<typeof useIntl>, engine?: string): string {
  switch (engine) {
    case 'fingerprint':
      return intl.formatMessage(i18n.skippedFingerprint);
    case 'secrets':
      return intl.formatMessage(i18n.skippedSecrets);
    case 'history':
      return intl.formatMessage(i18n.skippedHistory);
    case 'sast':
      return intl.formatMessage(i18n.skippedSast);
    case 'delta':
      return intl.formatMessage(i18n.skippedDelta);
    case 'literals':
      return intl.formatMessage(i18n.skippedLiterals);
    case 'investigate':
      return intl.formatMessage(i18n.skippedInvestigate);
    case 'surfaces':
      return intl.formatMessage(i18n.skippedSurfaces);
    case 'harden':
      return intl.formatMessage(i18n.skippedHarden);
    case 'sca':
      return intl.formatMessage(i18n.skippedSca);
    case 'intel':
      return intl.formatMessage(i18n.skippedIntel);
    case 'agent':
      return intl.formatMessage(i18n.skippedAgent);
    default:
      return intl.formatMessage(i18n.scanningWorkspace);
  }
}

function doneText(
  intl: ReturnType<typeof useIntl>,
  engine?: string,
  count?: number
): string {
  const counted = count != null;
  switch (engine) {
    case 'fingerprint':
      return counted
        ? intl.formatMessage(i18n.doneFingerprint, { count })
        : intl.formatMessage(i18n.doneFingerprintPlain);
    case 'secrets':
      return counted
        ? intl.formatMessage(i18n.doneSecrets, { count })
        : intl.formatMessage(i18n.doneSecretsPlain);
    case 'history':
      return counted
        ? intl.formatMessage(i18n.doneHistory, { count })
        : intl.formatMessage(i18n.doneHistoryPlain);
    case 'sast':
      return counted
        ? intl.formatMessage(i18n.doneSast, { count })
        : intl.formatMessage(i18n.doneSastPlain);
    case 'delta':
      return counted
        ? intl.formatMessage(i18n.doneDelta, { count })
        : intl.formatMessage(i18n.doneDeltaPlain);
    case 'literals':
      return counted
        ? intl.formatMessage(i18n.doneLiterals, { count })
        : intl.formatMessage(i18n.doneLiteralsPlain);
    case 'investigate':
      return counted
        ? intl.formatMessage(i18n.doneInvestigate, { count })
        : intl.formatMessage(i18n.doneInvestigatePlain);
    case 'surfaces':
      return counted
        ? intl.formatMessage(i18n.doneSurfaces, { count })
        : intl.formatMessage(i18n.doneSurfacesPlain);
    case 'harden':
      return counted
        ? intl.formatMessage(i18n.doneHarden, { count })
        : intl.formatMessage(i18n.doneHardenPlain);
    case 'sca':
      return counted
        ? intl.formatMessage(i18n.doneSca, { count })
        : intl.formatMessage(i18n.doneScaPlain);
    case 'intel':
      return counted
        ? intl.formatMessage(i18n.doneIntel, { count })
        : intl.formatMessage(i18n.doneIntelPlain);
    case 'agent':
      return counted
        ? intl.formatMessage(i18n.doneAgent, { count })
        : intl.formatMessage(i18n.doneAgentPlain);
    default:
      return intl.formatMessage(i18n.scanningWorkspace);
  }
}

function lineText(
  intl: ReturnType<typeof useIntl>,
  line: ScanLine,
  liveEngine?: string | null
): string {
  if (line.role === 'user') return line.text;
  if (line.role === 'assistant' && line.text) return line.text;
  if (line.status === 'running' && line.engine && line.engine === liveEngine) {
    return '';
  }
  if (line.status === 'running') {
    return scanningText(intl, line.engine);
  }
  if (line.status === 'skipped') {
    return skippedText(intl, line.engine);
  }
  if (line.status === 'done') {
    return doneText(intl, line.engine, line.detailCount);
  }
  if (line.status === 'paused') {
    return intl.formatMessage(i18n.scanPaused);
  }
  if (line.status === 'error') {
    return intl.formatMessage(i18n.scanStopped);
  }
  if (line.status === 'summary' && line.detailCount != null) {
    return intl.formatMessage(i18n.scanComplete, { count: line.detailCount });
  }
  if (line.status === 'summary') {
    return intl.formatMessage(i18n.scanStopped);
  }
  return '';
}

function startedTimestamp(startedAt?: string | null): number | undefined {
  if (!startedAt) return undefined;
  const parsed = Date.parse(startedAt);
  return Number.isNaN(parsed) ? undefined : parsed / 1000;
}

export default function ScanTranscript({
  lines,
  errorMessage,
  liveEngine,
  empty,
  startedAt,
  sessionId,
  chatMessages,
  toolCallNotifications,
  chatting,
  chatState,
  progressMessage,
  canChat,
  onMessageUpdate,
  onMessageDelete,
  submitElicitationResponse,
}: {
  lines: ScanLine[];
  errorMessage?: string | null;
  liveEngine?: string | null;
  empty?: boolean;
  startedAt?: string | null;
  sessionId?: string | null;
  chatMessages?: Message[];
  toolCallNotifications?: Map<string, NotificationEvent[]>;
  chatting?: boolean;
  chatState?: ChatState;
  progressMessage?: string;
  canChat?: boolean;
  onMessageUpdate?: (
    messageId: string,
    newContent: string,
    editType: 'fork' | 'edit',
    retainedImages: import('../../types/message').ImageData[]
  ) => void;
  onMessageDelete?: (messageId: string) => void;
  submitElicitationResponse?: (
    elicitationId: string,
    userData: Record<string, unknown>
  ) => Promise<boolean>;
}) {
  const intl = useIntl();
  const scrollRef = useRef<ScrollAreaHandle>(null);
  const toolCallChains = useMemo(
    () => identifyConsecutiveToolCalls(chatMessages ?? []),
    [chatMessages]
  );

  useEffect(() => {
    scrollRef.current?.scrollToBottom();
  }, [lines.length, liveEngine, errorMessage, chatMessages?.length, chatting]);

  return (
    <ScrollArea
      ref={scrollRef}
      className="flex-1 min-h-0"
      autoScroll
      paddingX={6}
      paddingY={4}
    >
      {empty ? (
        <p className="text-sm text-text-secondary py-8">{intl.formatMessage(i18n.empty)}</p>
      ) : (
        <div className="flex flex-col gap-4 pb-8">
          {lines.map((line) => {
            const text = lineText(intl, line, liveEngine);
            if (!text) return null;
            if (line.role === 'user') {
              return (
                <div
                  key={line.id}
                  className="w-full opacity-0 animate-[appear_150ms_ease-in_forwards] flex justify-end"
                >
                  <div className="flex-col max-w-[85%] w-fit">
                    <div className="user-message-bubble flex bg-text-primary text-background-primary rounded-xl py-2.5 px-4">
                      <p className="text-sm leading-relaxed">{text}</p>
                    </div>
                    <p className="text-xs font-mono text-text-secondary pt-1 text-right">
                      {formatMessageTimestamp(startedTimestamp(startedAt))}
                    </p>
                  </div>
                </div>
              );
            }
            return (
              <div
                key={line.id}
                className={cn(
                  'w-full opacity-0 animate-[appear_150ms_ease-in_forwards]',
                  line.live && 'text-text-secondary'
                )}
              >
                <div className="agent-message-bubble w-full">
                  <p className="text-sm text-text-primary leading-relaxed">{text}</p>
                </div>
              </div>
            );
          })}
          {errorMessage && (
            <p className="text-sm text-red-600 dark:text-red-400">{errorMessage}</p>
          )}
          {liveEngine && (
            <div className="flex items-start gap-2 text-sm text-text-primary py-2 min-w-0">
              <Loader2 className="size-4 shrink-0 animate-spin mt-0.5" aria-hidden="true" />
              <span className="min-w-0 break-words">{scanningText(intl, liveEngine)}</span>
            </div>
          )}
          {canChat && !liveEngine && (chatMessages?.length ?? 0) === 0 && !chatting && (
            <p className="text-sm text-text-secondary">{intl.formatMessage(i18n.chatHint)}</p>
          )}
          {(Boolean(sessionId) || (chatMessages?.length ?? 0) > 0) &&
            chatMessages?.map((message, index) =>
              message.role === 'user' ? (
                <UserMessage
                  key={message.id ?? `${message.created}-user`}
                  message={message}
                  {...(onMessageUpdate ? { onMessageUpdate } : {})}
                  {...(onMessageDelete ? { onMessageDelete } : {})}
                />
              ) : (
                <div
                  key={message.id ?? `${message.created}-assistant`}
                  className={cn(
                    isInChain(index, toolCallChains) &&
                      index > 0 &&
                      chatMessages[index - 1]?.role === 'assistant' &&
                      '-mt-2'
                  )}
                >
                  <GooseMessage
                    sessionId={sessionId ?? ''}
                    message={message}
                    messages={chatMessages}
                    toolCallNotifications={toolCallNotifications ?? new Map()}
                    append={() => {}}
                    isStreaming={
                      Boolean(chatting) &&
                      index === chatMessages.length - 1 &&
                      message.role === 'assistant'
                    }
                    submitElicitationResponse={submitElicitationResponse}
                  />
                </div>
              )
            )}
          {chatting && chatState && chatState !== ChatState.Idle && (
            <LoadingGoose chatState={chatState} message={progressMessage} />
          )}
        </div>
      )}
    </ScrollArea>
  );
}

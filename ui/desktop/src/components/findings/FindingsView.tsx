/*
  THESIS: Scan status is a conversation docked like Chat, not a dashboard of phase chips; the ledger stays a list beside it.
  OWN-WORLD: Incumbent Achilles desktop chrome — Cash Sans, #111 canvas, ChatInputCard, DirSwitcher, ModelsBottomBar, near-black bubbles.
  STORY: Start a scan, watch engines land as assistant lines, triage findings on the right, change folder/model without leaving. The session appears under CHATS and opens this view.
  FIRST VIEWPORT: Split workbench — transcript left, findings rail right, native composer spanning the bottom with Scan where Send sits.
  FORM: Composer-docked split, seed 9e4cf1e1 candidate 5, approved comp findings-comp-b-split-rail.
  FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, and DESIGN.md
*/
import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { toast } from 'react-toastify';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { defineMessages, useIntl } from '../../i18n';
import { getInitialWorkingDir } from '../../utils/workingDir';
import { SOCKET_TOKEN_KEY, socketSecretIsSet } from '../../utils/socketConfig';
import { useConfig } from '../ConfigContext';
import { useIsMobile } from '../../hooks/use-mobile';
import { useChatSession } from '../../hooks/useChatSession';
import { ChatState } from '../../types/chatState';
import { createUserMessage, getTextAndImageContent } from '../../types/message';
import { Button } from '../ui/button';
import {
  acpGetAssessment,
  acpListAssessments,
  acpListFindings,
  acpSetFindingState,
  acpCancelAssessment,
  acpPauseAssessment,
  type AchillesAssessment,
  type AchillesFinding,
} from '../../acp/achilles';
import ScanTranscript from './ScanTranscript';
import FindingsRail from './FindingsRail';
import ScanComposer from './ScanComposer';
import FindingPreview from './FindingPreview';
import { attachFinding, splitFindingChatPayload, type AttachedFinding } from './findingChat';
import {
  buildScanTranscript,
  isScanKickoffText,
  runningEngine,
  scanDepthOf,
  type ScanDepth,
} from './scanEvents';
import { acpChatSessionController } from '../../acp/chatSessionController';
import { acpChatSessionActions, acpChatSessionStore } from '../../acp/chatSessionStore';
import { acpGetSessionListItem, isAcpSessionLoadInFlight } from '../../acp/sessions';
import {
  rememberScanSession,
  startScanSession,
  assessmentIdForScanSession,
  isDesktopChatSessionId,
  pickScanChatSession,
  ensureScanChatSession,
  findExistingScanSessionForDir,
  resolveScanAssessmentId,
} from './startScanSession';
import { scanAllowsFollowUpChat, scanIsBusy, visibleScanFollowUpText } from './scanChat';

type StateFilter = 'active' | 'dismissed' | 'verified_fixed' | 'all';

const RAIL_MIN = 280;
const RAIL_DEFAULT = 448;
const TRANSCRIPT_MIN = 240;

const i18n = defineMessages({
  noDir: {
    id: 'findingsView.noDir',
    defaultMessage: 'Pick a workspace folder first.',
  },
  scanFailed: {
    id: 'findingsView.scanFailed',
    defaultMessage: 'Scan failed: {error}',
  },
  cancelFailed: {
    id: 'findingsView.cancelFailed',
    defaultMessage: 'Could not stop scan: {error}',
  },
  pauseFailed: {
    id: 'findingsView.pauseFailed',
    defaultMessage: 'Could not pause scan: {error}',
  },
  triageFailed: {
    id: 'findingsView.triageFailed',
    defaultMessage: 'Could not update finding: {error}',
  },
  scanPrompt: {
    id: 'findingsView.scanPromptDefault',
    defaultMessage:
      'Perform {depth, select, investigate {an Investigative} deep {a Deep} other {a Fast}} Scan on my repo',
  },
  scanPromptDiff: {
    id: 'findingsView.scanPromptDiff',
    defaultMessage:
      'Perform {depth, select, investigate {an Investigative} deep {a Deep} other {a Fast}} Scan on changed files',
  },
  queuedForAgent: {
    id: 'findingsView.queuedForAgent',
    defaultMessage: '{count} finding(s) still open after AI review — you can continue in chat.',
  },
  investigateInChat: {
    id: 'findingsView.investigateInChat',
    defaultMessage: 'Investigate in chat',
  },
  resizeRail: {
    id: 'findingsView.resizeRail',
    defaultMessage: 'Resize findings panel',
  },
  askAiWait: {
    id: 'findingsView.askAiWait',
    defaultMessage: 'Wait for the scan to finish, then type your question about this finding.',
  },
  chatFailed: {
    id: 'findingsView.chatFailed',
    defaultMessage: 'Could not send: {error}',
  },
});

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function findingNeedsAgent(finding: AchillesFinding): boolean {
  return asRecord(finding.evidence.investigation).needsAgent === true;
}

async function waitForScanChatReady(sessionId: string): Promise<void> {
  const deadline = Date.now() + 15000;
  let askedRestore = false;
  while (Date.now() < deadline) {
    const snap = acpChatSessionStore.getSnapshot(sessionId);
    if (snap?.sessionLoadError) {
      throw new Error(snap.sessionLoadError);
    }
    if (snap?.session && snap.chatState !== ChatState.LoadingConversation) {
      return;
    }
    if (!askedRestore && !isAcpSessionLoadInFlight(sessionId) && !snap?.session) {
      askedRestore = true;
      await acpChatSessionController.restoreSession(sessionId);
      continue;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  }
  if (!acpChatSessionStore.getSnapshot(sessionId)?.session) {
    throw new Error('Chat session did not load');
  }
}

function userPromptFor(
  mode: string,
  depth: ScanDepth,
  intl: ReturnType<typeof useIntl>
): string {
  const values = { depth };
  return mode === 'diff'
    ? intl.formatMessage(i18n.scanPromptDiff, values)
    : intl.formatMessage(i18n.scanPrompt, values);
}

function mergeAssessments(groups: AchillesAssessment[][]): AchillesAssessment[] {
  const byId = new Map<string, AchillesAssessment>();
  for (const group of groups) {
    for (const row of group) {
      byId.set(row.id, row);
    }
  }
  return [...byId.values()].sort((a, b) => {
    const delta = Date.parse(b.startedAt) - Date.parse(a.startedAt);
    return Number.isFinite(delta) ? delta : 0;
  });
}

export default function FindingsView() {
  const intl = useIntl();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isMobile = useIsMobile();
  const { extensionsList, read } = useConfig();
  const [workingDir, setWorkingDir] = useState(() => getInitialWorkingDir());
  const urlAssessmentId = searchParams.get('assessmentId');
  const urlSessionId = searchParams.get('resumeSessionId');
  const [sessionId, setSessionId] = useState<string | null>(() => urlSessionId);
  const [assessment, setAssessment] = useState<AchillesAssessment | null>(null);
  const [scanRuns, setScanRuns] = useState<AchillesAssessment[]>([]);
  const [findings, setFindings] = useState<AchillesFinding[]>([]);
  const [scanning, setScanning] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [filter, setFilter] = useState<StateFilter>('active');
  const [includeVendor, setIncludeVendor] = useState(false);
  const [scanLiterals, setScanLiterals] = useState(false);
  const [scanDelta, setScanDelta] = useState(false);
  const [scanDepth, setScanDepth] = useState<ScanDepth>('fast');
  const [socketConfigured, setSocketConfigured] = useState<boolean | null>(null);
  const [railWidth, setRailWidth] = useState(RAIL_DEFAULT);
  const [railDragging, setRailDragging] = useState(false);
  const [attachedFinding, setAttachedFinding] = useState<AttachedFinding | null>(null);
  const [previewFinding, setPreviewFinding] = useState<AchillesFinding | null>(null);

  useEffect(() => {
    setPreviewFinding(null);
  }, [workingDir]);
  const splitRef = useRef<HTMLDivElement>(null);
  const resizing = useRef(false);
  const resizeStartX = useRef(0);
  const resizeStartWidth = useRef(RAIL_DEFAULT);
  const assessmentIdRef = useRef<string | null>(null);
  const restoredSessionRef = useRef<string | null>(null);
  const sessionIdRef = useRef<string | null>(null);
  assessmentIdRef.current = assessment?.id ?? null;
  sessionIdRef.current = sessionId;

  useEffect(() => {
    let cancelled = false;
    void read(SOCKET_TOKEN_KEY, true)
      .then((value) => {
        if (!cancelled) setSocketConfigured(socketSecretIsSet(value));
      })
      .catch(() => {
        if (!cancelled) setSocketConfigured(false);
      });
    return () => {
      cancelled = true;
    };
  }, [read]);

  const openSocketSettings = useCallback(() => {
    navigate('/settings', { state: { section: 'socket' } });
  }, [navigate]);

  const syncUrl = useCallback(
    (next: { assessmentId?: string | null; sessionId?: string | null }) => {
      const params = new URLSearchParams();
      if (next.assessmentId) params.set('assessmentId', next.assessmentId);
      if (next.sessionId) params.set('resumeSessionId', next.sessionId);
      if (
        urlAssessmentId === params.get('assessmentId') &&
        urlSessionId === params.get('resumeSessionId')
      ) {
        return;
      }
      const query = params.toString();
      navigate(query ? `/findings?${query}` : '/findings', { replace: true });
    },
    [navigate, urlAssessmentId, urlSessionId]
  );

  const loadForAssessment = useCallback(async (id: string) => {
    const [nextAssessment, nextFindings] = await Promise.all([
      acpGetAssessment(id),
      acpListFindings({ assessmentId: id }),
    ]);
    setAssessment(nextAssessment);
    setFindings(nextFindings);
    if (nextAssessment.workingDir) {
      setWorkingDir(nextAssessment.workingDir);
    }
    const boundSessionId = pickScanChatSession({
      assessmentId: nextAssessment.id,
      assessmentSessionId: nextAssessment.sessionId,
      sessionId: sessionIdRef.current,
    });
    if (boundSessionId) {
      setSessionId((prev) => (isDesktopChatSessionId(prev) ? prev : boundSessionId));
    }
    const sessionKey = boundSessionId ?? nextAssessment.sessionId ?? sessionIdRef.current;
    const [bySession, byDir] = await Promise.all([
      isDesktopChatSessionId(sessionKey)
        ? acpListAssessments({ sessionId: sessionKey }).catch(() => [])
        : Promise.resolve([]),
      nextAssessment.workingDir
        ? acpListAssessments({ workingDir: nextAssessment.workingDir }).catch(() => [])
        : Promise.resolve([]),
    ]);
    setScanRuns(mergeAssessments([bySession, byDir]));
    return nextAssessment;
  }, []);

  const {
    messages,
    session,
    chatState,
    stopStreaming,
    onMessageUpdate,
    onMessageDelete,
    submitElicitationResponse,
    notifications: toolCallNotifications,
    progressMessage,
  } = useChatSession({
    sessionId: isDesktopChatSessionId(sessionId) ? sessionId : '',
    onStreamFinish: () => {
      const id = assessmentIdRef.current;
      if (id) {
        void loadForAssessment(id).catch((error) => console.error(error));
      }
    },
  });

  const refreshLatest = useCallback(async () => {
    if (!workingDir) return;
    const listed = await acpListAssessments({ workingDir });
    const latest = listed[0];
    if (!latest) {
      setAssessment(null);
      setScanRuns([]);
      setFindings([]);
      return;
    }
    await loadForAssessment(latest.id);
  }, [loadForAssessment, workingDir]);

  useEffect(() => {
    if (urlAssessmentId) {
      void loadForAssessment(urlAssessmentId).catch((error) => {
        console.error(error);
      });
      return;
    }
    if (urlSessionId) {
      const cached = assessmentIdForScanSession(urlSessionId);
      if (cached) {
        void loadForAssessment(cached).catch((error) => console.error(error));
        return;
      }
      void (async () => {
        const item = await acpGetSessionListItem(urlSessionId).catch(() => null);
        const dir = item?.workingDir || workingDir || undefined;
        const id = await resolveScanAssessmentId(urlSessionId, dir, {
          fallbackToWorkingDir: true,
        });
        if (id) {
          await loadForAssessment(id);
        }
      })().catch((error) => console.error(error));
      return;
    }
    void refreshLatest().catch((error) => console.error(error));
  }, [loadForAssessment, refreshLatest, urlAssessmentId, urlSessionId, workingDir]);

  const liveAssessmentId = assessment?.id;
  const liveAssessmentStatus = assessment?.status;
  useEffect(() => {
    if (!liveAssessmentId || (liveAssessmentStatus !== 'running' && liveAssessmentStatus !== 'queued')) {
      return;
    }
    const timer = window.setInterval(() => {
      void loadForAssessment(liveAssessmentId).catch((error) => console.error(error));
    }, 1200);
    return () => window.clearInterval(timer);
  }, [liveAssessmentId, liveAssessmentStatus, loadForAssessment]);

  const handleWorkingDirChange = async (next: string) => {
    setWorkingDir(next);
    setSessionId(null);
    setAssessment(null);
    setScanRuns([]);
    setFindings([]);
    setAttachedFinding(null);
    syncUrl({ sessionId: null, assessmentId: null });
  };

  const handleScan = async (mode: 'quick' | 'diff' = 'quick') => {
    if (!workingDir) {
      toast.error(intl.formatMessage(i18n.noDir));
      return;
    }
    setScanning(true);
    try {
      const resumable =
        assessment &&
        (assessment.status === 'cancelled' ||
          assessment.status === 'partial' ||
          assessment.status === 'failed');
      const started = await startScanSession({
        workingDir,
        mode,
        includeVendor,
        scanLiterals,
        scanDelta,
        depth: scanDepth,
        parentAssessmentId: resumable ? undefined : assessment?.id,
        resumeAssessmentId: resumable ? assessment.id : undefined,
        existingSessionId: assessment
          ? pickScanChatSession({
              assessmentId: assessment.id,
              assessmentSessionId: assessment.sessionId,
              sessionId,
              urlSessionId,
            })
          : sessionId,
        extensionsList,
      });
      setAssessment(started.assessment);
      setScanRuns([started.assessment]);
      setFindings([]);
      setAttachedFinding(null);
      setSessionId(started.sessionId);
      syncUrl({ assessmentId: started.assessment.id, sessionId: started.sessionId });
    } catch (error) {
      toast.error(
        intl.formatMessage(i18n.scanFailed, {
          error: error instanceof Error ? error.message : String(error),
        })
      );
    } finally {
      setScanning(false);
    }
  };

  const handlePause = async (paused: boolean) => {
    if (!assessment) return;
    setPausing(true);
    try {
      const next = await acpPauseAssessment(assessment.id, paused);
      setAssessment(next);
    } catch (error) {
      toast.error(
        intl.formatMessage(i18n.pauseFailed, {
          error: error instanceof Error ? error.message : String(error),
        })
      );
    } finally {
      setPausing(false);
    }
  };

  const handleStop = async () => {
    if (!assessment) return;
    setCancelling(true);
    try {
      const stopped = await acpCancelAssessment(assessment.id);
      await loadForAssessment(stopped.id);
    } catch (error) {
      toast.error(
        intl.formatMessage(i18n.cancelFailed, {
          error: error instanceof Error ? error.message : String(error),
        })
      );
    } finally {
      setCancelling(false);
    }
  };

  const handleSelectScanRun = useCallback(
    (id: string) => {
      if (!id || id === assessmentIdRef.current) return;
      void loadForAssessment(id)
        .then((next) => {
          const session =
            pickScanChatSession({
              assessmentId: next.id,
              assessmentSessionId: next.sessionId,
              sessionId: sessionIdRef.current,
              urlSessionId,
            }) ?? sessionIdRef.current;
          syncUrl({
            assessmentId: next.id,
            sessionId: isDesktopChatSessionId(session) ? session : null,
          });
        })
        .catch((error) => console.error(error));
    },
    [loadForAssessment, syncUrl, urlSessionId]
  );

  const handleTriage = async (finding: AchillesFinding, state: string, reason?: string) => {
    try {
      const updated = await acpSetFindingState(finding.id, state, reason);
      setFindings((prev) => prev.map((row) => (row.id === updated.id ? updated : row)));
      if (assessment) {
        const next = await acpGetAssessment(assessment.id);
        setAssessment(next);
      }
    } catch (error) {
      toast.error(
        intl.formatMessage(i18n.triageFailed, {
          error: error instanceof Error ? error.message : String(error),
        })
      );
    }
  };

  const queuedForAgent = useMemo(() => {
    return findings
      .filter((f) => (f.state === 'open' || f.state === 'confirmed') && findingNeedsAgent(f))
      .slice(0, 8);
  }, [findings]);

  const paused = assessment?.status === 'paused';
  const busy = scanIsBusy({ scanning, status: assessment?.status });

  const chatting =
    chatState === ChatState.Thinking ||
    chatState === ChatState.Streaming ||
    chatState === ChatState.Compacting ||
    chatState === ChatState.WaitingForUserInput;

  const canChat = scanAllowsFollowUpChat({
    hasAssessment: Boolean(assessment),
    scanning,
    status: assessment?.status,
  });

  useEffect(() => {
    if (!assessment || busy || !workingDir) return;

    if (isDesktopChatSessionId(sessionId)) {
      if (urlSessionId !== sessionId || urlAssessmentId !== assessment.id) {
        syncUrl({ assessmentId: assessment.id, sessionId });
      }
      return;
    }

    let cancelled = false;
    void (async () => {
      const existing =
        (isDesktopChatSessionId(urlSessionId) ? urlSessionId : null) ||
        (isDesktopChatSessionId(assessment.sessionId) ? assessment.sessionId : null) ||
        (await findExistingScanSessionForDir(workingDir));
      if (cancelled || !isDesktopChatSessionId(existing)) return;
      rememberScanSession(existing, assessment.id);
      setSessionId(existing);
      syncUrl({ assessmentId: assessment.id, sessionId: existing });
    })().catch((error) => console.error('Failed to bind scan chat session:', error));

    return () => {
      cancelled = true;
    };
  }, [assessment, busy, sessionId, syncUrl, urlAssessmentId, urlSessionId, workingDir]);

  useEffect(() => {
    if (!isDesktopChatSessionId(sessionId) || busy) return;
    const snap = acpChatSessionStore.getSnapshot(sessionId);
    if (snap?.session || snap?.messages.length) return;
    if (restoredSessionRef.current === sessionId) return;
    restoredSessionRef.current = sessionId;
    void acpChatSessionController.loadSession(sessionId).catch((error) => {
      console.error('Failed to open scan chat session:', error);
    });
  }, [busy, session, sessionId]);

  const submitScanChat = useCallback(
    async (text: string) => {
      if (!assessment) return;
      let id = isDesktopChatSessionId(sessionId)
        ? sessionId
        : isDesktopChatSessionId(urlSessionId)
          ? urlSessionId
          : null;
      if (!isDesktopChatSessionId(id)) {
        try {
          id = await ensureScanChatSession({
            workingDir,
            assessmentId: assessment.id,
            extensionsList,
          });
        } catch (error) {
          toast.error(
            intl.formatMessage(i18n.chatFailed, {
              error: error instanceof Error ? error.message : String(error),
            })
          );
          return;
        }
      }
      rememberScanSession(id, assessment.id);
      setSessionId(id);
      syncUrl({ assessmentId: assessment.id, sessionId: id });
      try {
        await waitForScanChatReady(id);
        const snapshot = acpChatSessionStore.getSnapshot(id);
        if (!snapshot?.session) {
          throw new Error('Chat session did not load');
        }
        const userMessage = createUserMessage(text, []);
        acpChatSessionActions.setMessages(id, [...(snapshot.messages ?? []), userMessage]);
        await acpChatSessionController.submitMessage(id, userMessage, {
          getCurrentSnapshot: () => acpChatSessionStore.getSnapshot(id),
          onFinish: () => {
            const assessmentId = assessmentIdRef.current;
            if (assessmentId) {
              void loadForAssessment(assessmentId).catch((error) => console.error(error));
            }
          },
        });
      } catch (error) {
        toast.error(
          intl.formatMessage(i18n.chatFailed, {
            error: error instanceof Error ? error.message : String(error),
          })
        );
      }
    },
    [
      assessment,
      extensionsList,
      intl,
      loadForAssessment,
      sessionId,
      syncUrl,
      urlSessionId,
      workingDir,
    ]
  );

  const handleAskAi = useCallback(
    (finding: AchillesFinding) => {
      setAttachedFinding(attachFinding(finding));
      if (!canChat) {
        toast.info(intl.formatMessage(i18n.askAiWait));
      }
    },
    [canChat, intl]
  );

  const handleInvestigateInChat = () => {
    if (queuedForAgent.length === 0 || chatting) return;
    const ids = queuedForAgent.map((f) => f.id).join(', ');
    void submitScanChat(
      `Investigate these Achilles findings only. Do not invent other issues or exploits. For each finding_id: appsec_investigate, then appsec_verdict role=investigator, then appsec_investigate again, then appsec_verdict role=validator, then appsec_triage when both passes agree (confirmed or dismissed). finding_ids: ${ids}`
    );
  };

  const followUpMessages = useMemo(
    () =>
      messages
        .filter((message) => {
          if (!message.metadata?.userVisible) return false;
          if (message.role !== 'user') return true;
          const { textContent } = getTextAndImageContent(message);
          return !isScanKickoffText(textContent);
        })
        .map((message) => {
          if (message.role !== 'user') return message;
          const { textContent } = getTextAndImageContent(message);
          const split = splitFindingChatPayload(textContent);
          const visible = split?.question ?? visibleScanFollowUpText(textContent);
          if (visible === textContent) return message;
          return {
            ...message,
            content: message.content.map((block) =>
              block.type === 'text' ? { ...block, text: visible } : block
            ),
          };
        }),
    [messages]
  );

  const lines = useMemo(
    () =>
      buildScanTranscript(
        assessment,
        findings,
        assessment ? userPromptFor(assessment.mode, scanDepthOf(assessment), intl) : null
      ),
    [assessment, findings, intl]
  );

  const live = runningEngine(assessment);

  const investigateAction =
    queuedForAgent.length > 0 ? (
      <Button
        size="xs"
        variant="outline"
        onClick={handleInvestigateInChat}
        disabled={busy || chatting || !canChat}
      >
        {intl.formatMessage(i18n.investigateInChat)}
      </Button>
    ) : null;

  const handleRailResizeStart = useCallback(
    (event: MouseEvent) => {
      resizing.current = true;
      resizeStartX.current = event.clientX;
      resizeStartWidth.current = railWidth;
      setRailDragging(true);
      event.preventDefault();
    },
    [railWidth]
  );

  useEffect(() => {
    const onMove = (event: globalThis.MouseEvent) => {
      if (!resizing.current) return;
      const container = splitRef.current?.getBoundingClientRect().width ?? window.innerWidth;
      const max = Math.max(RAIL_MIN, container - TRANSCRIPT_MIN);
      const next = resizeStartWidth.current + (resizeStartX.current - event.clientX);
      setRailWidth(Math.min(max, Math.max(RAIL_MIN, next)));
    };
    const onUp = () => {
      if (!resizing.current) return;
      resizing.current = false;
      setRailDragging(false);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, []);

  return (
    <MainPanelLayout removeTopPadding>
      <div className="h-full flex flex-col min-h-0">
        <div
          ref={splitRef}
          className={`flex flex-col md:flex-row flex-1 min-h-0${railDragging ? ' select-none' : ''}`}
        >
          <div className="flex-1 min-h-0 min-w-0 flex flex-col">
            {previewFinding && workingDir ? (
              <FindingPreview
                path={previewFinding.path ?? ''}
                workingDir={workingDir}
                lineStart={previewFinding.lineStart}
                lineEnd={previewFinding.lineEnd}
                onClose={() => setPreviewFinding(null)}
              />
            ) : (
              <ScanTranscript
                lines={lines}
                errorMessage={assessment?.errorMessage}
                liveEngine={busy && !paused ? live : null}
                empty={!assessment}
                startedAt={assessment?.startedAt}
                sessionId={isDesktopChatSessionId(sessionId) ? sessionId : null}
                chatMessages={busy ? [] : followUpMessages}
                toolCallNotifications={toolCallNotifications}
                chatting={canChat && chatting}
                chatState={chatState}
                progressMessage={progressMessage}
                canChat={canChat}
                onMessageUpdate={onMessageUpdate}
                onMessageDelete={onMessageDelete}
                submitElicitationResponse={submitElicitationResponse}
              />
            )}
          </div>
          {!isMobile && (
            <>
              <div
                role="separator"
                aria-orientation="vertical"
                aria-label={intl.formatMessage(i18n.resizeRail)}
                aria-valuemin={RAIL_MIN}
                aria-valuenow={Math.round(railWidth)}
                tabIndex={0}
                className="hidden md:block w-1.5 shrink-0 cursor-col-resize bg-border-primary hover:bg-text-muted/40 active:bg-text-muted/60"
                onMouseDown={handleRailResizeStart}
                onKeyDown={(event) => {
                  const container =
                    splitRef.current?.getBoundingClientRect().width ?? window.innerWidth;
                  const max = Math.max(RAIL_MIN, container - TRANSCRIPT_MIN);
                  if (event.key === 'ArrowLeft') {
                    event.preventDefault();
                    setRailWidth((width) => Math.min(max, width + 24));
                  }
                  if (event.key === 'ArrowRight') {
                    event.preventDefault();
                    setRailWidth((width) => Math.max(RAIL_MIN, width - 24));
                  }
                }}
              />
              <div
                className="hidden min-h-0 min-w-0 shrink-0 flex-col overflow-hidden md:flex"
                style={{ width: railWidth }}
              >
                <FindingsRail
                  findings={findings}
                  workingDir={workingDir}
                  filter={filter}
                  onFilter={setFilter}
                  onTriage={(finding, state, reason) => void handleTriage(finding, state, reason)}
                  assessment={assessment}
                  scanRuns={scanRuns}
                  onSelectScanRun={handleSelectScanRun}
                  headerAction={investigateAction}
                  onAskAi={handleAskAi}
                  previewFindingId={previewFinding?.id ?? null}
                  onOpenFile={(finding) =>
                    setPreviewFinding((current) =>
                      current?.id === finding.id ? null : finding
                    )
                  }
                />
              </div>
            </>
          )}
        </div>

        {isMobile && (
          <div className="max-h-[40%] min-h-[10rem] border-t border-border-primary">
            <FindingsRail
              findings={findings}
              workingDir={workingDir}
              filter={filter}
              onFilter={setFilter}
              onTriage={(finding, state, reason) => void handleTriage(finding, state, reason)}
              assessment={assessment}
              scanRuns={scanRuns}
              onSelectScanRun={handleSelectScanRun}
              headerAction={investigateAction}
              onAskAi={handleAskAi}
              previewFindingId={previewFinding?.id ?? null}
              onOpenFile={(finding) =>
                setPreviewFinding((current) => (current?.id === finding.id ? null : finding))
              }
            />
          </div>
        )}

        <ScanComposer
          sessionId={sessionId}
          workingDir={workingDir}
          onWorkingDirChange={handleWorkingDirChange}
          scanDepth={scanDepth}
          onScanDepth={(id) => {
            setScanDepth(id);
            if (id === 'deep') setIncludeVendor(true);
          }}
          includeVendor={includeVendor}
          onIncludeVendor={setIncludeVendor}
          scanLiterals={scanLiterals}
          onScanLiterals={setScanLiterals}
          scanDelta={scanDelta}
          onScanDelta={setScanDelta}
          busy={busy}
          paused={paused}
          hasAssessment={Boolean(assessment)}
          cancelling={cancelling}
          pausing={pausing}
          onScan={(mode) => void handleScan(mode)}
          onPause={(next) => void handlePause(next)}
          onStop={() => void handleStop()}
          canChat={canChat}
          chatting={chatting}
          onChatSubmit={(text) => {
            void submitScanChat(text);
          }}
          onStopChat={() => stopStreaming()}
          socketConfigured={socketConfigured}
          onOpenSocketSettings={openSocketSettings}
          attachedFinding={attachedFinding}
          onClearAttachedFinding={() => setAttachedFinding(null)}
        />
      </div>
    </MainPanelLayout>
  );
}

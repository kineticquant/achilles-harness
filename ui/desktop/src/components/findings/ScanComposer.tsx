import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import {
  ArrowUp,
  CircleHelp,
  Maximize2,
  Minimize2,
  Pause,
  Play,
  ShieldAlert,
  Sparkles,
  X,
} from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { Button } from '../ui/button';
import { ChatInputCard } from '../ChatInputCard';
import { DirSwitcher } from '../bottom_menu/DirSwitcher';
import ModelsBottomBar from '../settings/models/bottom_bar/ModelsBottomBar';
import Stop from '../ui/Stop';
import { useModelAndProvider } from '../ModelAndProviderContext';
import { useNavigation } from '../../hooks/useNavigation';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/Tooltip';
import { cn } from '../../utils';
import type { ScanDepth } from './scanEvents';
import { composeFindingChatPayload, type AttachedFinding } from './findingChat';

const i18n = defineMessages({
  placeholder: {
    id: 'findingsView.scanPromptPlaceholder',
    defaultMessage: 'Scan this workspace…',
  },
  chatPlaceholder: {
    id: 'findingsView.chatPlaceholder',
    defaultMessage: 'Ask Achilles for security guidance to take to your coding app',
  },
  send: {
    id: 'findingsView.sendChat',
    defaultMessage: 'Send',
  },
  stopChat: {
    id: 'findingsView.stopChat',
    defaultMessage: 'Stop reply',
  },
  depthFastHelp: {
    id: 'findingsView.depthFastHelp',
    defaultMessage:
      'Quick pass over secrets, known code patterns, dependencies, and deploy config. Typical run is seconds.',
  },
  depthInvestigateHelp: {
    id: 'findingsView.depthInvestigateHelp',
    defaultMessage:
      'Same coverage as Fast, then the configured model confirms or rejects code-pattern hits. It can read more source and look up existing findings.',
  },
  depthDeepHelp: {
    id: 'findingsView.depthDeepHelp',
    defaultMessage:
      'Wider file walk than Fast or Investigate. The model reviews hits and functions, and may read callers or search for the same sink. New findings need a quote from source it was shown.',
  },
  depthGroupHelpFast: {
    id: 'findingsView.depthGroupHelpFast',
    defaultMessage:
      'Fast: secrets, code patterns, dependencies, and deploy config. Usually seconds.',
  },
  depthGroupHelpInvestigate: {
    id: 'findingsView.depthGroupHelpInvestigate',
    defaultMessage:
      'Investigate: the configured model confirms or rejects code-pattern hits.',
  },
  depthGroupHelpDeep: {
    id: 'findingsView.depthGroupHelpDeep',
    defaultMessage: 'Deep: walks more of the tree. The model reviews hits and functions.',
  },
  depthGroupHelpAria: {
    id: 'findingsView.depthGroupHelpAria',
    defaultMessage: 'What Fast, Investigate, and Deep mean',
  },
  scanAction: {
    id: 'findingsView.scanAction',
    defaultMessage: 'Scan',
  },
  rescan: {
    id: 'findingsView.rescan',
    defaultMessage: 'Rescan',
  },
  scanChanged: {
    id: 'findingsView.scanChanged',
    defaultMessage: 'Scan changed files',
  },
  includeVendor: {
    id: 'findingsView.includeVendorShort',
    defaultMessage: 'Include vendor',
  },
  includeVendorHelp: {
    id: 'findingsView.includeVendorHelp',
    defaultMessage:
      'Also walk node_modules, vendor, and target. Off by default — those trees are large and usually not your code.',
  },
  includeVendorHelpAria: {
    id: 'findingsView.includeVendorHelpAria',
    defaultMessage: 'What include vendor means',
  },
  scanLiterals: {
    id: 'findingsView.scanLiteralsShort',
    defaultMessage: 'Hardcoded values',
  },
  scanLiteralsHelp: {
    id: 'findingsView.scanLiteralsHelp',
    defaultMessage:
      'Optional. Not a security scan. Limits, timeouts, and magic numbers rank higher than URLs (URLs in source are often fine). IPs, paths, and connection strings are called out because they usually belong in config.',
  },
  scanLiteralsHelpAria: {
    id: 'findingsView.scanLiteralsHelpAria',
    defaultMessage: 'What hardcoded values means',
  },
  scanDelta: {
    id: 'findingsView.scanDeltaShort',
    defaultMessage: 'Local changes',
  },
  scanDeltaHelp: {
    id: 'findingsView.scanDeltaHelp',
    defaultMessage:
      'Optional. Read staged, unstaged, and untracked edits, compact the functions they touch, and check that new logic against the rest of the tree. Flags sinks this change introduces — especially when the repo already uses a safer pattern.',
  },
  scanDeltaHelpAria: {
    id: 'findingsView.scanDeltaHelpAria',
    defaultMessage: 'What local changes means',
  },
  depthGroup: {
    id: 'findingsView.depthGroup',
    defaultMessage: 'Scan depth',
  },
  depthFast: { id: 'findingsView.depthFast', defaultMessage: 'Fast' },
  depthInvestigate: { id: 'findingsView.depthInvestigate', defaultMessage: 'Investigate' },
  depthDeep: { id: 'findingsView.depthDeep', defaultMessage: 'Deep' },
  stopScan: { id: 'findingsView.stopScan', defaultMessage: 'Stop scan' },
  stopping: { id: 'findingsView.stopping', defaultMessage: 'Stopping…' },
  pauseScan: { id: 'findingsView.pauseScan', defaultMessage: 'Pause' },
  resumeScan: { id: 'findingsView.resumeScan', defaultMessage: 'Resume' },
  socketOff: {
    id: 'findingsView.socketOff',
    defaultMessage: 'Socket off',
  },
  socketOffHint: {
    id: 'findingsView.socketOffHint',
    defaultMessage:
      'Optional extra package alerts. Add your own free Socket token in Settings — not required. Scans still use OSV.',
  },
  attachedFinding: {
    id: 'findingsView.attachedFinding',
    defaultMessage: 'Asking about this finding',
  },
  clearAttached: {
    id: 'findingsView.clearAttachedFinding',
    defaultMessage: 'Remove finding from chat',
  },
  expandComposer: {
    id: 'findingsView.expandComposer',
    defaultMessage: 'Expand input',
  },
  collapseComposer: {
    id: 'findingsView.collapseComposer',
    defaultMessage: 'Collapse input',
  },
  resizeComposer: {
    id: 'findingsView.resizeComposer',
    defaultMessage: 'Resize input',
  },
});

const TEXTAREA_MIN = 56;
const TEXTAREA_COMPACT_MAX = 240;
const TEXTAREA_STEP = 24;

function expandedDefaultHeight(): number {
  if (typeof window === 'undefined') return 320;
  return Math.round(window.innerHeight * 0.48);
}

function maxComposerHeight(): number {
  if (typeof window === 'undefined') return 640;
  return Math.round(window.innerHeight * 0.72);
}

function clampComposerHeight(height: number): number {
  return Math.min(maxComposerHeight(), Math.max(TEXTAREA_MIN, height));
}

const hintContentClass =
  'max-w-xs text-left whitespace-normal text-pretty bg-background-secondary text-text-primary border border-border-primary';
const hintArrowClass = 'bg-background-secondary fill-background-secondary';

function ComposerHint({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn(
            'inline-flex size-5 shrink-0 items-center justify-center rounded-sm text-text-muted hover:text-text-primary focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
            className
          )}
          aria-label={label}
        >
          <CircleHelp className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className={hintContentClass} arrowClassName={hintArrowClass}>
        {children}
      </TooltipContent>
    </Tooltip>
  );
}

export default function ScanComposer({
  sessionId,
  workingDir,
  onWorkingDirChange,
  scanDepth,
  onScanDepth,
  includeVendor,
  onIncludeVendor,
  scanLiterals,
  onScanLiterals,
  scanDelta,
  onScanDelta,
  busy,
  paused,
  hasAssessment,
  cancelling,
  pausing,
  onScan,
  onPause,
  onStop,
  canChat,
  chatting,
  onChatSubmit,
  onStopChat,
  socketConfigured,
  onOpenSocketSettings,
  attachedFinding,
  onClearAttachedFinding,
}: {
  sessionId: string | null;
  workingDir: string;
  onWorkingDirChange: (dir: string) => Promise<void> | void;
  scanDepth: ScanDepth;
  onScanDepth: (depth: ScanDepth) => void;
  includeVendor: boolean;
  onIncludeVendor: (value: boolean) => void;
  scanLiterals: boolean;
  onScanLiterals: (value: boolean) => void;
  scanDelta: boolean;
  onScanDelta: (value: boolean) => void;
  busy: boolean;
  paused: boolean;
  hasAssessment: boolean;
  cancelling: boolean;
  pausing: boolean;
  onScan: (mode: 'quick' | 'diff') => void;
  onPause: (paused: boolean) => void;
  onStop: () => void;
  canChat: boolean;
  chatting: boolean;
  onChatSubmit: (text: string) => void;
  onStopChat: () => void;
  socketConfigured?: boolean | null;
  onOpenSocketSettings?: () => void;
  attachedFinding?: AttachedFinding | null;
  onClearAttachedFinding?: () => void;
}) {
  const intl = useIntl();
  const setView = useNavigation();
  const { currentModel, currentProvider } = useModelAndProvider();
  const dropdownRef = useRef<HTMLDivElement>(null) as RefObject<HTMLDivElement>;
  const [modelOverride, setModelOverride] = useState<{ model: string; provider: string } | null>(
    null
  );
  const [draft, setDraft] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [manualHeight, setManualHeight] = useState<number | null>(null);
  const [resizing, setResizing] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const resizeRef = useRef({ active: false, startY: 0, startHeight: TEXTAREA_MIN });
  const effectiveModel = modelOverride?.model ?? currentModel;
  const effectiveProvider = modelOverride?.provider ?? currentProvider;

  const textareaHeight = expanded
    ? clampComposerHeight(manualHeight ?? expandedDefaultHeight())
    : manualHeight;

  useEffect(() => {
    if (!attachedFinding || !canChat) return;
    const el = inputRef.current;
    if (!el) return;
    const focus = () => {
      el.focus();
      const end = el.value.length;
      el.setSelectionRange(end, end);
    };
    focus();
    const frame = window.requestAnimationFrame(focus);
    return () => window.cancelAnimationFrame(frame);
  }, [attachedFinding, canChat]);

  useEffect(() => {
    const el = inputRef.current;
    if (!el || !canChat) return;
    if (expanded || manualHeight != null) {
      el.style.height = `${textareaHeight ?? TEXTAREA_MIN}px`;
      return;
    }
    el.style.height = 'auto';
    const next = Math.min(Math.max(el.scrollHeight, TEXTAREA_MIN), TEXTAREA_COMPACT_MAX);
    el.style.height = `${next}px`;
  }, [canChat, draft, expanded, manualHeight, textareaHeight]);

  const collapseComposer = useCallback(() => {
    setExpanded(false);
    setManualHeight(null);
  }, []);

  const toggleExpanded = useCallback(() => {
    setExpanded((open) => {
      if (open) {
        setManualHeight(null);
        return false;
      }
      setManualHeight(expandedDefaultHeight());
      return true;
    });
    window.requestAnimationFrame(() => inputRef.current?.focus());
  }, []);

  const handleResizeStart = useCallback(
    (event: ReactMouseEvent) => {
      const current =
        inputRef.current?.offsetHeight ??
        (expanded ? expandedDefaultHeight() : TEXTAREA_MIN);
      resizeRef.current = {
        active: true,
        startY: event.clientY,
        startHeight: current,
      };
      setResizing(true);
      event.preventDefault();
    },
    [expanded]
  );

  useEffect(() => {
    const onMove = (event: globalThis.MouseEvent) => {
      if (!resizeRef.current.active) return;
      const next = clampComposerHeight(
        resizeRef.current.startHeight + (resizeRef.current.startY - event.clientY)
      );
      setManualHeight(next);
      setExpanded(next > TEXTAREA_COMPACT_MAX);
    };
    const onUp = () => {
      if (!resizeRef.current.active) return;
      resizeRef.current.active = false;
      setResizing(false);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, []);

  const depthLabel = (id: ScanDepth) => {
    if (id === 'fast') return intl.formatMessage(i18n.depthFast);
    if (id === 'investigate') return intl.formatMessage(i18n.depthInvestigate);
    return intl.formatMessage(i18n.depthDeep);
  };

  const depthHelp = (id: ScanDepth) => {
    if (id === 'fast') return intl.formatMessage(i18n.depthFastHelp);
    if (id === 'investigate') return intl.formatMessage(i18n.depthInvestigateHelp);
    return intl.formatMessage(i18n.depthDeepHelp);
  };

  const sendDraft = () => {
    const text = draft.trim();
    if (!text || chatting) return;
    const payload = attachedFinding
      ? composeFindingChatPayload(attachedFinding.context, text)
      : text;
    onChatSubmit(payload);
    setDraft('');
    collapseComposer();
    onClearAttachedFinding?.();
  };

  const onChatKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Escape' && (expanded || manualHeight != null)) {
      event.preventDefault();
      collapseComposer();
      return;
    }
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendDraft();
    }
  };

  const onResizeKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
    event.preventDefault();
    const current =
      inputRef.current?.offsetHeight ??
      (expanded ? expandedDefaultHeight() : TEXTAREA_MIN);
    const delta = event.key === 'ArrowUp' ? TEXTAREA_STEP : -TEXTAREA_STEP;
    const next = clampComposerHeight(current + delta);
    setManualHeight(next);
    setExpanded(next > TEXTAREA_COMPACT_MAX);
  };

  return (
    <ChatInputCard className={`relative z-10 mx-4 mb-4${resizing ? ' select-none' : ''}`}>
      {canChat && (
        <div
          role="separator"
          aria-orientation="horizontal"
          aria-label={intl.formatMessage(i18n.resizeComposer)}
          aria-valuemin={TEXTAREA_MIN}
          aria-valuemax={maxComposerHeight()}
          aria-valuenow={Math.round(inputRef.current?.offsetHeight ?? TEXTAREA_MIN)}
          tabIndex={0}
          data-testid="findings-composer-resize"
          className="flex h-3 cursor-row-resize items-center justify-center text-text-muted/60 hover:text-text-muted active:text-text-secondary"
          onMouseDown={handleResizeStart}
          onKeyDown={onResizeKeyDown}
        >
          <span className="block h-0.5 w-8 rounded-full bg-current" aria-hidden="true" />
        </div>
      )}
      {attachedFinding && (
        <div className="flex items-center gap-2 px-3 pt-2.5 min-w-0">
          <Sparkles className="size-3.5 shrink-0 text-text-muted" />
          <span className="text-xs text-text-secondary truncate min-w-0">
            {intl.formatMessage(i18n.attachedFinding)}
            {': '}
            {attachedFinding.title}
          </span>
          <button
            type="button"
            onClick={() => onClearAttachedFinding?.()}
            aria-label={intl.formatMessage(i18n.clearAttached)}
            className="ml-auto inline-flex size-6 shrink-0 items-center justify-center rounded-md text-text-muted hover:text-text-primary"
          >
            <X className="size-3.5" />
          </button>
        </div>
      )}
      {canChat ? (
        <textarea
          ref={inputRef}
          data-testid="findings-chat-input"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={onChatKeyDown}
          disabled={chatting}
          rows={2}
          placeholder={intl.formatMessage(i18n.chatPlaceholder)}
          className={cn(
            'w-full outline-none border-none focus:ring-0 bg-transparent px-3 pb-1.5 text-sm resize-none overflow-y-auto text-text-primary placeholder:text-text-secondary',
            attachedFinding ? 'pt-1.5' : 'pt-3'
          )}
        />
      ) : (
        <div className="px-3 pt-3 pb-1.5">
          <p className="text-sm text-text-secondary">{intl.formatMessage(i18n.placeholder)}</p>
        </div>
      )}
      <div className="flex flex-row items-center gap-2 px-3 py-2 border-t border-border-primary bg-background-secondary/40 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <ModelsBottomBar
            sessionId={sessionId}
            dropdownRef={dropdownRef}
            setView={setView}
            sessionModel={effectiveModel}
            sessionProvider={effectiveProvider}
            latestInference={null}
            onModelChanged={setModelOverride}
            sessionLoaded
          />
          <span className="h-4 w-px shrink-0 bg-border-primary" aria-hidden="true" />
          <DirSwitcher
            className=""
            sessionId={undefined}
            workingDir={workingDir}
            onWorkingDirChange={onWorkingDirChange}
          />
        </div>

        <div className="inline-flex h-7 items-stretch rounded-md border border-border-primary bg-background-primary overflow-hidden">
          <div
            role="radiogroup"
            aria-label={intl.formatMessage(i18n.depthGroup)}
            className="inline-flex h-full items-stretch"
          >
            {(['fast', 'investigate', 'deep'] as const).map((id, index) => (
              <Tooltip key={id}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={scanDepth === id}
                    aria-description={depthHelp(id)}
                    disabled={busy || chatting}
                    onClick={() => onScanDepth(id)}
                    className={cn(
                      'h-full px-2.5 text-[11px] text-text-muted hover:text-text-primary disabled:opacity-50',
                      index > 0 && 'border-l border-border-primary',
                      scanDepth === id && 'bg-background-tertiary text-text-primary'
                    )}
                  >
                    {depthLabel(id)}
                  </button>
                </TooltipTrigger>
                <TooltipContent
                  side="top"
                  className={hintContentClass}
                  arrowClassName={hintArrowClass}
                >
                  {depthHelp(id)}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
          <ComposerHint
            label={intl.formatMessage(i18n.depthGroupHelpAria)}
            className="h-full w-7 rounded-none border-l border-border-primary text-text-muted hover:bg-background-tertiary hover:text-text-primary"
          >
            <div className="flex flex-col gap-1.5">
              <p>{intl.formatMessage(i18n.depthGroupHelpFast)}</p>
              <p>{intl.formatMessage(i18n.depthGroupHelpInvestigate)}</p>
              <p>{intl.formatMessage(i18n.depthGroupHelpDeep)}</p>
            </div>
          </ComposerHint>
        </div>

        <div className="inline-flex h-7 items-center rounded-md border border-border-primary bg-background-primary pl-2 pr-0.5">
          <label className="flex items-center gap-1.5 text-[11px] text-text-muted cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeVendor}
              disabled={busy || chatting}
              onChange={(event) => onIncludeVendor(event.target.checked)}
            />
            {intl.formatMessage(i18n.includeVendor)}
          </label>
          <ComposerHint label={intl.formatMessage(i18n.includeVendorHelpAria)}>
            {intl.formatMessage(i18n.includeVendorHelp)}
          </ComposerHint>
        </div>

        <div className="inline-flex h-7 items-center rounded-md border border-border-primary bg-background-primary pl-2 pr-0.5">
          <label className="flex items-center gap-1.5 text-[11px] text-text-muted cursor-pointer select-none">
            <input
              type="checkbox"
              checked={scanLiterals}
              disabled={busy || chatting}
              onChange={(event) => onScanLiterals(event.target.checked)}
            />
            {intl.formatMessage(i18n.scanLiterals)}
          </label>
          <ComposerHint label={intl.formatMessage(i18n.scanLiteralsHelpAria)}>
            {intl.formatMessage(i18n.scanLiteralsHelp)}
          </ComposerHint>
        </div>

        <div className="inline-flex h-7 items-center rounded-md border border-border-primary bg-background-primary pl-2 pr-0.5">
          <label className="flex items-center gap-1.5 text-[11px] text-text-muted cursor-pointer select-none">
            <input
              type="checkbox"
              checked={scanDelta}
              disabled={busy || chatting}
              onChange={(event) => onScanDelta(event.target.checked)}
            />
            {intl.formatMessage(i18n.scanDelta)}
          </label>
          <ComposerHint label={intl.formatMessage(i18n.scanDeltaHelpAria)}>
            {intl.formatMessage(i18n.scanDeltaHelp)}
          </ComposerHint>
        </div>

        {socketConfigured === false && onOpenSocketSettings && (
          <button
            type="button"
            onClick={onOpenSocketSettings}
            title={intl.formatMessage(i18n.socketOffHint)}
            className="text-[11px] text-text-muted hover:text-text-secondary whitespace-nowrap"
          >
            {intl.formatMessage(i18n.socketOff)}
          </button>
        )}

        <div className="ms-auto flex shrink-0 items-center justify-end gap-1.5">
          {canChat && (
            <Button
              size="sm"
              variant="ghost"
              shape="round"
              onClick={toggleExpanded}
              aria-expanded={expanded}
              aria-label={
                expanded
                  ? intl.formatMessage(i18n.collapseComposer)
                  : intl.formatMessage(i18n.expandComposer)
              }
              data-testid="findings-composer-expand"
              className="bg-background-tertiary"
              title={
                expanded
                  ? intl.formatMessage(i18n.collapseComposer)
                  : intl.formatMessage(i18n.expandComposer)
              }
            >
              {expanded ? (
                <Minimize2 className="w-4 h-4" strokeWidth={2.25} />
              ) : (
                <Maximize2 className="w-4 h-4" strokeWidth={2.25} />
              )}
            </Button>
          )}
          {busy ? (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPause(!paused)}
                disabled={pausing || cancelling || !hasAssessment}
              >
                {paused ? <Play className="size-4" /> : <Pause className="size-4" />}
                {paused
                  ? intl.formatMessage(i18n.resumeScan)
                  : intl.formatMessage(i18n.pauseScan)}
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={onStop}
                disabled={cancelling || !hasAssessment}
              >
                <Stop size={14} />
                {cancelling
                  ? intl.formatMessage(i18n.stopping)
                  : intl.formatMessage(i18n.stopScan)}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" size="sm" onClick={() => onScan('diff')} disabled={chatting}>
                {intl.formatMessage(i18n.scanChanged)}
              </Button>
              <Button size="sm" onClick={() => onScan('quick')} disabled={chatting}>
                <ShieldAlert className="size-4" />
                {hasAssessment
                  ? intl.formatMessage(i18n.rescan)
                  : intl.formatMessage(i18n.scanAction)}
              </Button>
              {canChat &&
                (chatting ? (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={onStopChat}
                    aria-label={intl.formatMessage(i18n.stopChat)}
                  >
                    <Stop size={14} />
                    {intl.formatMessage(i18n.stopChat)}
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="ghost"
                    shape="round"
                    disabled={!draft.trim()}
                    onClick={sendDraft}
                    aria-label={intl.formatMessage(i18n.send)}
                    className="bg-background-tertiary"
                  >
                    <ArrowUp className="w-4 h-4" strokeWidth={2.25} />
                  </Button>
                ))}
            </>
          )}
        </div>
      </div>
    </ChatInputCard>
  );
}

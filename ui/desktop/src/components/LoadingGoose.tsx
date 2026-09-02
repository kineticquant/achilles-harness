import { Loader2 } from 'lucide-react';
import { ChatState } from '../types/chatState';
import { defineMessages, useIntl } from '../i18n';

interface LoadingGooseProps {
  message?: string;
  chatState?: ChatState;
  icon?: React.ReactNode;
}

const i18n = defineMessages({
  loadingConversation: {
    id: 'loadingGoose.loadingConversation',
    defaultMessage: 'loading conversation...',
  },
  thinking: {
    id: 'loadingGoose.thinking',
    defaultMessage: 'Achilles is thinking…',
  },
  streaming: {
    id: 'loadingGoose.streaming',
    defaultMessage: 'Achilles is working on it…',
  },
  waiting: {
    id: 'loadingGoose.waiting',
    defaultMessage: 'Achilles is waiting…',
  },
  compacting: {
    id: 'loadingGoose.compacting',
    defaultMessage: 'Achilles is compacting the conversation...',
  },
  idle: {
    id: 'loadingGoose.idle',
    defaultMessage: 'Achilles is working on it…',
  },
  restartingAgent: {
    id: 'loadingGoose.restartingAgent',
    defaultMessage: 'restarting session...',
  },
});

const spinner = (
  <Loader2 className="size-4 shrink-0 animate-spin text-text-primary" aria-hidden="true" />
);

const STATE_MESSAGE_KEYS: Record<ChatState, keyof typeof i18n> = {
  [ChatState.LoadingConversation]: 'loadingConversation',
  [ChatState.Thinking]: 'thinking',
  [ChatState.Streaming]: 'streaming',
  [ChatState.WaitingForUserInput]: 'waiting',
  [ChatState.Compacting]: 'compacting',
  [ChatState.Idle]: 'idle',
  [ChatState.RestartingAgent]: 'restartingAgent',
};

const LoadingGoose = ({ message, chatState = ChatState.Idle, icon }: LoadingGooseProps) => {
  const intl = useIntl();
  const displayMessage = message || intl.formatMessage(i18n[STATE_MESSAGE_KEYS[chatState]]);
  const glyph = icon ?? spinner;

  return (
    <div className="w-full animate-fade-slide-up">
      <div
        data-testid="loading-indicator"
        className="flex items-start gap-2 text-xs text-text-primary py-2 min-w-0"
      >
        <span className="shrink-0 mt-0.5">{glyph}</span>
        <span className="min-w-0 break-words">{displayMessage}</span>
      </div>
    </div>
  );
};

export default LoadingGoose;

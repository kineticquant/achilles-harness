import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../i18n/test-utils';
import type { Message, MessageContent } from '../types/message';
import GooseMessage from './GooseMessage';

vi.mock('./ToolCallWithResponse', () => ({
  default: () => <div data-testid="tool-call" />,
}));

const meta = { userVisible: true, agentVisible: true };

function toolRequest(id: string): MessageContent {
  return {
    type: 'toolRequest',
    id,
    toolCall: { status: 'success', value: { name: 'developer__shell', arguments: {} } },
  };
}

function assistant(id: string, content: MessageContent[]): Message {
  return { id, role: 'assistant', created: 1, content, metadata: meta };
}

function renderGoose(message: Message, options?: { isStreaming?: boolean; messages?: Message[] }) {
  const messages = options?.messages ?? [message];
  return render(
    <GooseMessage
      sessionId="session-1"
      message={message}
      messages={messages}
      toolCallNotifications={new Map()}
      append={() => {}}
      isStreaming={options?.isStreaming ?? false}
    />,
    { wrapper: IntlTestWrapper }
  );
}

describe('GooseMessage working notes', () => {
  it('renders preamble-plus-tool turns as receded thoughts, not reply bubbles', () => {
    const message = assistant('a1', [
      { type: 'text', text: "I'll unpack what that risks in plain terms." },
      toolRequest('t1'),
    ]);

    renderGoose(message);

    expect(screen.getByText("I'll unpack what that risks in plain terms.")).toBeInTheDocument();
    expect(document.querySelector('.agent-message-bubble')).toBeNull();
    expect(document.querySelector('[data-working-note="true"]')).not.toBeNull();
    expect(screen.queryByText('Thinking')).not.toBeInTheDocument();
    expect(screen.getByTestId('tool-call')).toBeInTheDocument();
  });

  it('keeps a text-only reply in the message bubble', () => {
    const message = assistant('a2', [
      { type: 'text', text: 'This finding means a dotenv file was committed.' },
    ]);

    renderGoose(message);

    expect(screen.getByText('This finding means a dotenv file was committed.')).toBeInTheDocument();
    expect(document.querySelector('.agent-message-bubble')).not.toBeNull();
    expect(document.querySelector('[data-working-note="true"]')).toBeNull();
    expect(screen.queryByText('Thinking')).not.toBeInTheDocument();
  });
});

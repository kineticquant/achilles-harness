import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IntlTestWrapper } from '../i18n/test-utils';
import type { Message } from '../types/message';
import UserMessage from './UserMessage';

beforeEach(() => {
  (window as unknown as { electron: { logInfo: ReturnType<typeof vi.fn> } }).electron = {
    logInfo: vi.fn(),
  };
});

function userMsg(text = 'Hello there'): Message {
  return {
    id: 'msg-1',
    role: 'user',
    created: 1,
    content: [{ type: 'text', text }],
    metadata: { userVisible: true, agentVisible: true },
  };
}

describe('UserMessage delete', () => {
  it('shows a delete action when onMessageDelete is provided', () => {
    render(<UserMessage message={userMsg()} onMessageDelete={vi.fn()} />, {
      wrapper: IntlTestWrapper,
    });
    expect(screen.getByRole('button', { name: /delete message/i })).toBeInTheDocument();
  });

  it('does not show delete without onMessageDelete', () => {
    render(<UserMessage message={userMsg()} />, { wrapper: IntlTestWrapper });
    expect(screen.queryByRole('button', { name: /delete message/i })).not.toBeInTheDocument();
  });

  it('confirms before deleting the message', async () => {
    const user = userEvent.setup();
    const onMessageDelete = vi.fn().mockResolvedValue(undefined);

    render(<UserMessage message={userMsg()} onMessageDelete={onMessageDelete} />, {
      wrapper: IntlTestWrapper,
    });

    await user.click(screen.getByRole('button', { name: /delete message/i }));
    expect(onMessageDelete).not.toHaveBeenCalled();
    expect(
      screen.getByText('This will remove this message and everything after it from the session.')
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^delete$/i }));
    expect(onMessageDelete).toHaveBeenCalledWith('msg-1');
  });
});

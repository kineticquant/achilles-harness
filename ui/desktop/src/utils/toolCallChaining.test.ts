import { describe, expect, it } from 'vitest';
import type { Message, MessageContent } from '../types/message';
import {
  identifyConsecutiveToolCalls,
  isInChain,
  isWorkingNote,
  shouldHideTimestamp,
} from './toolCallChaining';

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

function user(id: string, text: string): Message {
  return {
    id,
    role: 'user',
    created: 1,
    content: [{ type: 'text', text }],
    metadata: meta,
  };
}

describe('isWorkingNote', () => {
  it('treats assistant text plus a tool call as a working note', () => {
    expect(
      isWorkingNote(
        assistant('a', [{ type: 'text', text: "I'll open .env.erb" }, toolRequest('t1')])
      )
    ).toBe(true);
  });

  it('does not treat a final text-only reply as a working note', () => {
    expect(isWorkingNote(assistant('a', [{ type: 'text', text: 'This finding means…' }]))).toBe(
      false
    );
  });

  it('does not treat a tool-only turn as a working note', () => {
    expect(isWorkingNote(assistant('a', [toolRequest('t1')]))).toBe(false);
  });
});

describe('identifyConsecutiveToolCalls', () => {
  it('chains consecutive preamble-plus-tool turns', () => {
    const messages = [
      user('u', 'what does this mean'),
      assistant('a1', [{ type: 'text', text: "I'll unpack this." }, toolRequest('t1')]),
      assistant('a2', [{ type: 'text', text: "I'll open the file." }, toolRequest('t2')]),
      assistant('a3', [{ type: 'text', text: 'This finding means…' }]),
    ];

    const chains = identifyConsecutiveToolCalls(messages);
    expect(chains).toEqual([[1, 2]]);
    expect(isInChain(1, chains)).toBe(true);
    expect(isInChain(2, chains)).toBe(true);
    expect(isInChain(3, chains)).toBe(false);
    expect(shouldHideTimestamp(1, chains)).toBe(true);
    expect(shouldHideTimestamp(2, chains)).toBe(false);
  });
});

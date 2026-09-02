import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { IntlTestWrapper } from '../../i18n/test-utils';
import ToolsView from './ToolsView';
import { NAV_ITEMS } from '../../hooks/useNavigationItems';

vi.mock('../../utils/workingDir', () => ({
  getInitialWorkingDir: () => 'H:\\workspace',
}));

describe('NAV_ITEMS utils placement', () => {
  it('places Utils immediately after Extensions', () => {
    const ids = NAV_ITEMS.map((item) => item.id);
    expect(ids.indexOf('tools')).toBe(ids.indexOf('extensions') + 1);
    expect(NAV_ITEMS.find((item) => item.id === 'tools')?.label).toBe('Utils');
  });
});

describe('ToolsView', () => {
  it('shows a generic page description and updates util copy on selection', async () => {
    const user = userEvent.setup();
    render(
      <IntlTestWrapper>
        <ToolsView />
      </IntlTestWrapper>
    );

    expect(screen.getByRole('heading', { level: 1, name: 'Utils' })).toBeInTheDocument();
    expect(
      screen.getByText(/Built-in utilities for security work that sits outside scans and chats/i)
    ).toBeInTheDocument();
    expect(screen.queryByText(/Workspace helpers\. Not a scan/i)).not.toBeInTheDocument();

    expect(
      screen.getByText(/Computes a SHA-256 digest of a file in the current workspace/i)
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Entropy' }));
    expect(
      screen.getByText(/Estimates Shannon entropy of pasted text/i)
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Computes a SHA-256 digest of a file in the current workspace/i)
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Shred file' }));
    expect(screen.getByText(/Overwrites a working-tree file, then deletes it/i)).toBeInTheDocument();
    expect(
      screen.getByText('I understand this overwrites and deletes the file')
    ).toBeInTheDocument();
  });
});

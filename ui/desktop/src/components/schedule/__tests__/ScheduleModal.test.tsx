import { describe, it, expect, vi } from 'vitest';
import { render, type RenderOptions, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ScheduledJobDto } from '@aaif/goose-sdk';
import { ScheduleModal } from '../ScheduleModal';
import { IntlTestWrapper } from '../../../i18n/test-utils';

vi.mock('../../../recipe/recipe_management', () => ({
  getStorageDirectory: () => '/tmp/recipes',
  listSavedRecipes: vi.fn().mockResolvedValue([
    {
      id: 'scan-recap',
      file_path: '/data/shipped-recipes/scan-recap.yaml',
      last_modified: '2026-01-01T00:00:00Z',
      recipe: {
        title: 'Scan and recap',
        description: 'Run Achilles engines',
        prompt: 'Scan',
      },
    },
  ]),
}));

const renderWithIntl = (ui: React.ReactElement, options?: RenderOptions) =>
  render(ui, { wrapper: IntlTestWrapper, ...options });

const existingSchedule = {
  id: 'daily-summary-job',
  cron: '0 0 14 * * *',
} as ScheduledJobDto;

const baseProps = {
  onClose: vi.fn(),
  onSubmit: vi.fn().mockResolvedValue(undefined),
  isLoadingExternally: false,
  apiErrorExternally: null,
  initialDeepLink: null,
};

describe('ScheduleModal', () => {
  it('clears a validation error from create mode when reopened to edit a schedule', async () => {
    const user = userEvent.setup();
    const { rerender } = renderWithIntl(<ScheduleModal {...baseProps} isOpen schedule={null} />);

    await user.type(screen.getByLabelText(/name/i), 'my-job');
    await user.click(screen.getByRole('button', { name: 'Create Schedule' }));
    await waitFor(() => {
      expect(screen.getByText('Please provide a valid recipe source.')).toBeInTheDocument();
    });

    rerender(<ScheduleModal {...baseProps} isOpen={false} schedule={null} />);
    rerender(<ScheduleModal {...baseProps} isOpen schedule={existingSchedule} />);

    expect(screen.getByText('Edit Schedule')).toBeInTheDocument();
    expect(screen.queryByText('Please provide a valid recipe source.')).not.toBeInTheDocument();
  });

  it('lets you pick a library recipe including shipped ones', async () => {
    const user = userEvent.setup();
    renderWithIntl(<ScheduleModal {...baseProps} isOpen schedule={null} />);

    const select = await screen.findByLabelText('Select a recipe...');
    await user.selectOptions(select, 'scan-recap');

    expect(screen.getByText('Title: Scan and recap')).toBeInTheDocument();
    expect(screen.getByDisplayValue('scan-and-recap')).toBeInTheDocument();
  });
});

import React, { useCallback } from 'react';
import SessionListView from './SessionListView';
import { useNavigation } from '../../hooks/useNavigation';
import { destinationForHistorySession } from '../findings/startScanSession';

const SessionsView: React.FC = () => {
  const setView = useNavigation();

  const handleSelectSession = useCallback(
    async (sessionId: string, session?: { name: string; workingDir: string }) => {
      const { view, assessmentId } = await destinationForHistorySession({
        id: sessionId,
        name: session?.name ?? '',
        workingDir: session?.workingDir,
      });
      if (view === 'findings') {
        setView('findings', {
          disableAnimation: true,
          assessmentId,
          resumeSessionId: sessionId,
        });
        return;
      }
      setView('pair', {
        disableAnimation: true,
        resumeSessionId: sessionId,
      });
    },
    [setView]
  );

  return <SessionListView onSelectSession={handleSelectSession} />;
};

export default SessionsView;

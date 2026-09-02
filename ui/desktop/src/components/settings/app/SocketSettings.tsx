import { useCallback, useEffect, useState } from 'react';
import { toast } from 'react-toastify';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../ui/card';
import { Button } from '../../ui/button';
import { Input } from '../../ui/input';
import { useConfig } from '../../ConfigContext';
import { defineMessages, useIntl } from '../../../i18n';
import { errorMessage } from '../../../utils/conversionUtils';
import {
  SOCKET_CLI_URL,
  SOCKET_GITHUB_URL,
  SOCKET_ORG_KEY,
  SOCKET_PRICING_URL,
  SOCKET_SIGNUP_URL,
  SOCKET_TOKEN_KEY,
  socketSecretIsSet,
} from '../../../utils/socketConfig';
import { SecureStorageNotice } from '../providers/modal/subcomponents/SecureStorageNotice';

const i18n = defineMessages({
  title: {
    id: 'socketSettings.title',
    defaultMessage: 'Socket API',
  },
  description: {
    id: 'socketSettings.description',
    defaultMessage:
      'Optional add-on. Scans already check lockfiles for known CVEs (OSV), unpinned dependencies, install-time scripts, and lookalike package names — no token needed. Socket adds extra package-risk signals the tree and OSV do not cover.',
  },
  tokenLabel: {
    id: 'socketSettings.tokenLabel',
    defaultMessage: 'API token',
  },
  tokenPlaceholder: {
    id: 'socketSettings.tokenPlaceholder',
    defaultMessage: 'Organization API token',
  },
  tokenSavedPlaceholder: {
    id: 'socketSettings.tokenSavedPlaceholder',
    defaultMessage: 'Token saved — paste a new one to replace',
  },
  orgLabel: {
    id: 'socketSettings.orgLabel',
    defaultMessage: 'Organization slug',
  },
  orgPlaceholder: {
    id: 'socketSettings.orgPlaceholder',
    defaultMessage: 'your-org (from socket.dev)',
  },
  save: {
    id: 'socketSettings.save',
    defaultMessage: 'Save',
  },
  remove: {
    id: 'socketSettings.remove',
    defaultMessage: 'Remove token',
  },
  saved: {
    id: 'socketSettings.saved',
    defaultMessage: 'Socket API settings saved',
  },
  removed: {
    id: 'socketSettings.removed',
    defaultMessage: 'Socket token removed',
  },
  saveFailed: {
    id: 'socketSettings.saveFailed',
    defaultMessage: 'Could not save Socket settings: {error}',
  },
  signup: {
    id: 'socketSettings.signup',
    defaultMessage: 'Create a free Socket account',
  },
  signupHint: {
    id: 'socketSettings.signupHint',
    defaultMessage:
      'Free add-on for extra package-risk signals. You keep the token — Achilles never ships one.',
  },
  pricing: {
    id: 'socketSettings.pricing',
    defaultMessage: 'Pricing',
  },
  cli: {
    id: 'socketSettings.cli',
    defaultMessage: 'Socket CLI',
  },
  github: {
    id: 'socketSettings.github',
    defaultMessage: 'GitHub / CI',
  },
  extraHint: {
    id: 'socketSettings.extraHint',
    defaultMessage:
      'PR diffs, SBOMs, and threat feeds stay in Socket’s own CLI and CI. Use the same org if you already have them.',
  },
});

function openUrl(url: string) {
  if (window.electron?.openExternal) {
    void window.electron.openExternal(url);
    return;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

export default function SocketSettings() {
  const intl = useIntl();
  const { read, upsert, remove } = useConfig();
  const [token, setToken] = useState('');
  const [org, setOrg] = useState('');
  const [hasToken, setHasToken] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    const [tokenValue, orgValue] = await Promise.all([
      read(SOCKET_TOKEN_KEY, true),
      read(SOCKET_ORG_KEY, false),
    ]);
    setHasToken(socketSecretIsSet(tokenValue));
    setToken('');
    setOrg(typeof orgValue === 'string' ? orgValue : '');
  }, [read]);

  useEffect(() => {
    void load().catch((error) => console.error(error));
  }, [load]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const trimmedToken = token.trim();
      if (trimmedToken) {
        await upsert(SOCKET_TOKEN_KEY, trimmedToken, true);
      }
      const trimmedOrg = org.trim();
      if (trimmedOrg) {
        await upsert(SOCKET_ORG_KEY, trimmedOrg, false);
      } else {
        await remove(SOCKET_ORG_KEY, false).catch(() => undefined);
      }
      await load();
      toast.success(intl.formatMessage(i18n.saved));
    } catch (error) {
      toast.error(intl.formatMessage(i18n.saveFailed, { error: errorMessage(error) }));
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    setSaving(true);
    try {
      await remove(SOCKET_TOKEN_KEY, true);
      await load();
      toast.success(intl.formatMessage(i18n.removed));
    } catch (error) {
      toast.error(intl.formatMessage(i18n.saveFailed, { error: errorMessage(error) }));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="rounded-lg">
      <CardHeader className="pb-0">
        <CardTitle className="mb-1">{intl.formatMessage(i18n.title)}</CardTitle>
        <CardDescription>{intl.formatMessage(i18n.description)}</CardDescription>
      </CardHeader>
      <CardContent className="pt-4 px-4 space-y-4">
        <div className="space-y-2">
          <label className="text-xs text-text-primary" htmlFor="socket-token">
            {intl.formatMessage(i18n.tokenLabel)}
          </label>
          <Input
            id="socket-token"
            type="password"
            autoComplete="off"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder={
              hasToken
                ? intl.formatMessage(i18n.tokenSavedPlaceholder)
                : intl.formatMessage(i18n.tokenPlaceholder)
            }
          />
          <SecureStorageNotice />
        </div>
        <div className="space-y-2">
          <label className="text-xs text-text-primary" htmlFor="socket-org">
            {intl.formatMessage(i18n.orgLabel)}
          </label>
          <Input
            id="socket-org"
            value={org}
            onChange={(event) => setOrg(event.target.value)}
            placeholder={intl.formatMessage(i18n.orgPlaceholder)}
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => void handleSave()} disabled={saving}>
            {intl.formatMessage(i18n.save)}
          </Button>
          {hasToken && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => void handleRemove()}
              disabled={saving}
            >
              {intl.formatMessage(i18n.remove)}
            </Button>
          )}
        </div>
        <p className="text-xs text-text-secondary">{intl.formatMessage(i18n.signupHint)}</p>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
          <button
            type="button"
            className="text-text-secondary underline hover:text-text-primary"
            onClick={() => openUrl(SOCKET_SIGNUP_URL)}
          >
            {intl.formatMessage(i18n.signup)}
          </button>
          <button
            type="button"
            className="text-text-secondary underline hover:text-text-primary"
            onClick={() => openUrl(SOCKET_PRICING_URL)}
          >
            {intl.formatMessage(i18n.pricing)}
          </button>
          <button
            type="button"
            className="text-text-secondary underline hover:text-text-primary"
            onClick={() => openUrl(SOCKET_CLI_URL)}
          >
            {intl.formatMessage(i18n.cli)}
          </button>
          <button
            type="button"
            className="text-text-secondary underline hover:text-text-primary"
            onClick={() => openUrl(SOCKET_GITHUB_URL)}
          >
            {intl.formatMessage(i18n.github)}
          </button>
        </div>
        <p className="text-xs text-text-muted">{intl.formatMessage(i18n.extraHint)}</p>
      </CardContent>
    </Card>
  );
}

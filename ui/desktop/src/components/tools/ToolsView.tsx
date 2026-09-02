import { useMemo, useState, type ComponentType } from 'react';
import {
  Activity,
  Binary,
  EyeOff,
  FileCode,
  GitBranch,
  GitFork,
  Hash,
  Info,
  KeyRound,
  Lock,
  ShieldCheck,
  Trash2,
  Unlock,
} from 'lucide-react';
import { MainPanelLayout } from '../Layout/MainPanelLayout';
import { ScrollArea } from '../ui/scroll-area';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { defineMessages, useIntl } from '../../i18n';
import { getInitialWorkingDir } from '../../utils/workingDir';
import { errorMessage } from '../../utils/conversionUtils';
import { acpRunUtils } from '../../acp/achilles';
import { cn } from '../../utils';
import {
  relativeToWorkspace,
  toolOf,
  TOOL_GROUPS,
  type ToolAction,
} from './toolsCatalog';

const i18n = defineMessages({
  title: { id: 'toolsView.title', defaultMessage: 'Utils' },
  description: {
    id: 'toolsView.description',
    defaultMessage:
      'Built-in utilities for security work that sits outside scans and chats: hashing, encoding, redaction, encryption, and related helpers. They run locally on workspace files or pasted text, and they do not start a conversation or a scan.',
  },
  noDir: {
    id: 'toolsView.noDir',
    defaultMessage: 'Pick a workspace folder in Chat or Scan first.',
  },
  pathHint: {
    id: 'toolsView.pathHint',
    defaultMessage: 'Relative to the current workspace. Paths outside it are refused.',
  },
  groupInspect: { id: 'toolsView.groupInspect', defaultMessage: 'Inspect' },
  groupTransform: { id: 'toolsView.groupTransform', defaultMessage: 'Transform' },
  groupProtect: { id: 'toolsView.groupProtect', defaultMessage: 'Protect' },
  hash: { id: 'toolsView.hash', defaultMessage: 'Hash file' },
  hash_verify: { id: 'toolsView.hashVerify', defaultMessage: 'Verify hash' },
  entropy: { id: 'toolsView.entropy', defaultMessage: 'Entropy' },
  redact: { id: 'toolsView.redact', defaultMessage: 'Redact' },
  hex: { id: 'toolsView.hex', defaultMessage: 'Hex' },
  base64: { id: 'toolsView.base64', defaultMessage: 'Base64' },
  jwt: { id: 'toolsView.jwt', defaultMessage: 'Decode JWT' },
  encrypt: { id: 'toolsView.encrypt', defaultMessage: 'Encrypt file' },
  decrypt: { id: 'toolsView.decrypt', defaultMessage: 'Decrypt file' },
  shred: { id: 'toolsView.shred', defaultMessage: 'Shred file' },
  git_purge_plan: { id: 'toolsView.gitPurge', defaultMessage: 'Git purge plan' },
  hashHelp: {
    id: 'toolsView.hashHelp',
    defaultMessage:
      'Computes a SHA-256 digest of a file in the current workspace. Use it to fingerprint a file before sharing, or to compare the same path later. The digest is shown here; the file is not modified.',
  },
  hash_verifyHelp: {
    id: 'toolsView.hashVerifyHelp',
    defaultMessage:
      'Compares a workspace file to an expected SHA-256 hex digest. Use this after a download or handoff to confirm the bytes match. A mismatch means the file is not the same as the one that produced the digest.',
  },
  entropyHelp: {
    id: 'toolsView.entropyHelp',
    defaultMessage:
      'Estimates Shannon entropy of pasted text. Higher values look more random (typical of keys and tokens); lower values look structured. This is a local statistic, not a cryptographic strength test.',
  },
  redactHelp: {
    id: 'toolsView.redactHelp',
    defaultMessage:
      'Masks common secret shapes in pasted text, such as tokens, keys, and similar patterns, so a snippet is safer to share. Nothing is written to disk. Review the output; unusual formats can still leak.',
  },
  hexHelp: {
    id: 'toolsView.hexHelp',
    defaultMessage:
      'Converts between UTF-8 text and hexadecimal. Paste text to encode, or an even-length hex string to decode. Useful for inspecting binary-ish payloads without opening a hex editor.',
  },
  base64Help: {
    id: 'toolsView.base64Help',
    defaultMessage:
      'If the paste is valid base64, it is decoded; otherwise it is encoded. Handy for tokens, small blobs, and protocol payloads. Invalid input is reported rather than silently mangled.',
  },
  jwtHelp: {
    id: 'toolsView.jwtHelp',
    defaultMessage:
      'Splits a JSON Web Token and shows the header and payload as JSON. The signature is not verified, so this does not prove who issued the token or that it is unaltered.',
  },
  encryptHelp: {
    id: 'toolsView.encryptHelp',
    defaultMessage:
      'Writes a sibling .ach1 file using AES-256-GCM with an Argon2id passphrase. The passphrase is never stored. Keep the original until you confirm you can decrypt the new file.',
  },
  decryptHelp: {
    id: 'toolsView.decryptHelp',
    defaultMessage:
      'Decrypts an .ach1 file to a .decrypted sibling using your passphrase. Do not paste the recovered plaintext into chat. A wrong passphrase fails closed.',
  },
  shredHelp: {
    id: 'toolsView.shredHelp',
    defaultMessage:
      'Overwrites a working-tree file, then deletes it. SSDs and snapshots can still retain remnants. Git history is not rewritten. Use Git purge plan if the file was committed.',
  },
  git_purge_planHelp: {
    id: 'toolsView.gitPurgeHelp',
    defaultMessage:
      'Builds a command plan to rewrite git history for a leaked path. Achilles does not run those commands. Review them yourself if you intend to purge, and treat the plan as advisory only.',
  },
  callGraph: { id: 'toolsView.callGraph', defaultMessage: 'Call graph' },
  path: { id: 'toolsView.path', defaultMessage: 'File' },
  browse: { id: 'toolsView.browse', defaultMessage: 'Browse' },
  text: { id: 'toolsView.text', defaultMessage: 'Text' },
  passphrase: { id: 'toolsView.passphrase', defaultMessage: 'Passphrase' },
  expected: { id: 'toolsView.expected', defaultMessage: 'Expected SHA-256' },
  confirm: {
    id: 'toolsView.confirmShred',
    defaultMessage: 'I understand this overwrites and deletes the file',
  },
  run: { id: 'toolsView.run', defaultMessage: 'Run' },
  running: { id: 'toolsView.running', defaultMessage: 'Running…' },
  result: { id: 'toolsView.result', defaultMessage: 'Result' },
  emptyResult: {
    id: 'toolsView.emptyResult',
    defaultMessage: 'Run to see output here. Secrets and passphrases stay off this page.',
  },
});

const GROUP_COPY: Record<string, keyof typeof i18n> = {
  inspect: 'groupInspect',
  transform: 'groupTransform',
  protect: 'groupProtect',
};

const ACTION_ICONS: Record<ToolAction, ComponentType<{ className?: string }>> = {
  hash: Hash,
  hash_verify: ShieldCheck,
  entropy: Activity,
  redact: EyeOff,
  hex: Binary,
  base64: FileCode,
  jwt: KeyRound,
  encrypt: Lock,
  decrypt: Unlock,
  shred: Trash2,
  git_purge_plan: GitBranch,
};

const fieldClass =
  'w-full rounded-md border bg-background-primary px-3 py-2 text-sm text-text-primary placeholder:text-text-secondary focus-visible:outline-none focus:border-border-secondary hover:border-border-secondary';

export default function ToolsView() {
  const intl = useIntl();
  const workingDir = getInitialWorkingDir();
  const [action, setAction] = useState<ToolAction>('hash');
  const [path, setPath] = useState('');
  const [text, setText] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [expected, setExpected] = useState('');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const tool = useMemo(() => toolOf(action), [action]);
  const helpKey = `${action}Help` as keyof typeof i18n;
  const ActionIcon = ACTION_ICONS[action];

  const pickFile = async () => {
    const selected = await window.electron.selectFileOrDirectory(workingDir || undefined);
    if (!selected) return;
    setPath(relativeToWorkspace(workingDir, selected));
  };

  const onRun = async () => {
    if (!workingDir) {
      setError(intl.formatMessage(i18n.noDir));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const value = await acpRunUtils({
        workingDir,
        action,
        path: tool.needs.includes('path') ? path : undefined,
        text: tool.needs.includes('text') ? text : undefined,
        passphrase: tool.needs.includes('passphrase') ? passphrase : undefined,
        expected: tool.needs.includes('expected') ? expected : undefined,
        confirm: tool.needs.includes('confirm') ? confirm : undefined,
      });
      setResult(JSON.stringify(value, null, 2));
      setPassphrase('');
    } catch (err) {
      setError(errorMessage(err, intl.formatMessage(i18n.run)));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const selectAction = (id: ToolAction) => {
    setAction(id);
    setError(null);
    setResult(null);
    setConfirm(false);
  };

  return (
    <MainPanelLayout>
      <div className="flex-1 flex flex-col min-h-0">
        <div className="bg-background-primary px-8 pb-5 pt-16">
          <div className="page-transition max-w-3xl">
            <h1 className="text-4xl font-light mb-2">{intl.formatMessage(i18n.title)}</h1>
            <p className="text-sm text-text-secondary leading-relaxed">
              {intl.formatMessage(i18n.description)}
            </p>
          </div>
        </div>

        <div className="flex flex-1 min-h-0 px-8 pb-8 gap-8">
          <nav
            aria-label={intl.formatMessage(i18n.title)}
            className="w-56 shrink-0 overflow-y-auto border-r border-border-tertiary pr-5"
          >
            {TOOL_GROUPS.map((group) => (
              <div key={group.id} className="mb-6 last:mb-0">
                <p className="mb-2 text-xs font-medium text-text-tertiary">
                  {intl.formatMessage(i18n[GROUP_COPY[group.id]])}
                </p>
                <ul className="flex flex-col gap-0.5">
                  {group.id === 'inspect' ? (
                    <li>
                      <button
                        type="button"
                        onClick={() => {
                          if (!workingDir) {
                            setError(intl.formatMessage(i18n.noDir));
                            return;
                          }
                          void window.electron.openCodeMapWindow({ workingDir });
                        }}
                        className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm text-text-secondary transition-colors duration-150 hover:bg-background-secondary/70 hover:text-text-primary"
                      >
                        <GitFork className="size-4 shrink-0 text-text-tertiary" />
                        <span className="min-w-0 truncate">
                          {intl.formatMessage(i18n.callGraph)}
                        </span>
                      </button>
                    </li>
                  ) : null}
                  {group.tools.map((id) => {
                    const ItemIcon = ACTION_ICONS[id];
                    const selected = action === id;
                    return (
                      <li key={id}>
                        <button
                          type="button"
                          aria-current={selected ? 'page' : undefined}
                          onClick={() => selectAction(id)}
                          className={cn(
                            'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition-colors duration-150',
                            selected
                              ? 'bg-background-secondary text-text-primary'
                              : 'text-text-secondary hover:bg-background-secondary/70 hover:text-text-primary'
                          )}
                        >
                          <ItemIcon
                            className={cn(
                              'size-4 shrink-0',
                              selected ? 'text-text-primary' : 'text-text-tertiary'
                            )}
                          />
                          <span className="min-w-0 truncate">{intl.formatMessage(i18n[id])}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </nav>

          <div className="flex-1 min-w-0 flex flex-col min-h-0">
            <div className="flex items-start gap-3 mb-4">
              <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-background-secondary text-text-primary">
                <ActionIcon className="size-4" />
              </div>
              <div className="min-w-0 pt-1.5">
                <h2 className="text-lg font-medium text-text-primary leading-none">
                  {intl.formatMessage(i18n[action])}
                </h2>
              </div>
            </div>

            <div className="mb-5 flex gap-3 rounded-xl bg-background-info/10 px-3.5 py-3">
              <Info className="mt-0.5 size-4 shrink-0 text-text-info" aria-hidden />
              <p className="text-sm leading-relaxed text-text-secondary">
                {intl.formatMessage(i18n[helpKey])}
              </p>
            </div>

            <div className="flex flex-col gap-4 max-w-xl mb-5">
              {tool.needs.includes('path') ? (
                <label className="flex flex-col gap-1.5 text-sm">
                  <span className="text-text-secondary">{intl.formatMessage(i18n.path)}</span>
                  <div className="flex gap-2">
                    <Input
                      value={path}
                      onChange={(event) => setPath(event.target.value)}
                      spellCheck={false}
                    />
                    <Button type="button" variant="outline" onClick={() => void pickFile()}>
                      {intl.formatMessage(i18n.browse)}
                    </Button>
                  </div>
                  <span className="text-xs text-text-tertiary">
                    {workingDir
                      ? intl.formatMessage(i18n.pathHint)
                      : intl.formatMessage(i18n.noDir)}
                  </span>
                </label>
              ) : null}
              {tool.needs.includes('text') ? (
                <label className="flex flex-col gap-1.5 text-sm">
                  <span className="text-text-secondary">{intl.formatMessage(i18n.text)}</span>
                  <textarea
                    value={text}
                    onChange={(event) => setText(event.target.value)}
                    rows={7}
                    spellCheck={false}
                    className={cn(fieldClass, 'min-h-[10rem] resize-y font-mono')}
                  />
                </label>
              ) : null}
              {tool.needs.includes('expected') ? (
                <label className="flex flex-col gap-1.5 text-sm">
                  <span className="text-text-secondary">{intl.formatMessage(i18n.expected)}</span>
                  <Input
                    value={expected}
                    onChange={(event) => setExpected(event.target.value)}
                    spellCheck={false}
                    className="font-mono"
                  />
                </label>
              ) : null}
              {tool.needs.includes('passphrase') ? (
                <label className="flex flex-col gap-1.5 text-sm">
                  <span className="text-text-secondary">{intl.formatMessage(i18n.passphrase)}</span>
                  <Input
                    type="password"
                    autoComplete="new-password"
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                  />
                </label>
              ) : null}
              {tool.needs.includes('confirm') ? (
                <label className="flex items-start gap-2.5 rounded-lg bg-background-danger/10 px-3 py-2.5 text-sm text-text-primary">
                  <input
                    type="checkbox"
                    className="mt-0.5 size-4 accent-background-danger"
                    checked={confirm}
                    onChange={(event) => setConfirm(event.target.checked)}
                  />
                  <span>{intl.formatMessage(i18n.confirm)}</span>
                </label>
              ) : null}
              <div>
                <Button
                  type="button"
                  variant={tool.destructive ? 'destructive' : 'default'}
                  disabled={busy || !workingDir}
                  onClick={() => void onRun()}
                >
                  {busy ? intl.formatMessage(i18n.running) : intl.formatMessage(i18n.run)}
                </Button>
              </div>
            </div>

            {error ? (
              <p role="alert" className="text-sm text-text-danger mb-3">
                {error}
              </p>
            ) : null}

            <div className="flex-1 min-h-0 flex flex-col rounded-xl border border-border-tertiary bg-background-secondary overflow-hidden">
              <div className="shrink-0 px-3 py-2 border-b border-border-tertiary">
                <p className="text-xs font-medium text-text-tertiary">
                  {intl.formatMessage(i18n.result)}
                </p>
              </div>
              <ScrollArea className="flex-1 min-h-0">
                <pre
                  className={cn(
                    'p-3 text-xs font-mono whitespace-pre-wrap break-all',
                    result ? 'text-text-primary' : 'text-text-tertiary'
                  )}
                >
                  {result ?? intl.formatMessage(i18n.emptyResult)}
                </pre>
              </ScrollArea>
            </div>
          </div>
        </div>
      </div>
    </MainPanelLayout>
  );
}

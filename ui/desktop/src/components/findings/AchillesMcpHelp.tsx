import { useEffect, useMemo, useState } from 'react';
import { Copy, Plug } from 'lucide-react';
import { toast } from 'react-toastify';
import { defineMessages, useIntl } from '../../i18n';
import { Button } from '../ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '../ui/dialog';

const i18n = defineMessages({
  trigger: {
    id: 'findingsView.mcpTrigger',
    defaultMessage: 'Find out how to connect Achilles MCP to your favorite editor',
  },
  title: {
    id: 'findingsView.mcpTitle',
    defaultMessage: 'Connect Achilles MCP in your coding app',
  },
  body: {
    id: 'findingsView.mcpBody',
    defaultMessage:
      'Add Achilles as an MCP server in the app you already write code in. Cursor, Claude Code, Codex, and OpenCode can then pull findings, investigate, and mark them fixed. They apply the patch. You stay here to Rescan. Copy the snippet for the app you use:',
  },
  commandLabel: {
    id: 'findingsView.mcpCommandLabel',
    defaultMessage: 'Command',
  },
  cursorLabel: {
    id: 'findingsView.mcpCursorLabel',
    defaultMessage: 'Cursor — .cursor/mcp.json',
  },
  claudeLabel: {
    id: 'findingsView.mcpClaudeLabel',
    defaultMessage: 'Claude Code',
  },
  codexLabel: {
    id: 'findingsView.mcpCodexLabel',
    defaultMessage: 'Codex — ~/.codex/config.toml',
  },
  opencodeLabel: {
    id: 'findingsView.mcpOpencodeLabel',
    defaultMessage: 'OpenCode — opencode.json',
  },
  copySnippet: {
    id: 'findingsView.mcpCopySnippet',
    defaultMessage: 'Copy',
  },
  copied: {
    id: 'findingsView.mcpCopied',
    defaultMessage: 'Copied',
  },
  copyFailed: {
    id: 'findingsView.mcpCopyFailed',
    defaultMessage: 'Could not copy',
  },
});

function shellQuote(command: string): string {
  if (/[\s"]/.test(command)) {
    return `"${command.replace(/"/g, '\\"')}"`;
  }
  return command;
}

function mcpSnippets(command: string) {
  const jsonCommand = JSON.stringify(command);
  return {
    argv: `${shellQuote(command)} mcp`,
    cursor: `{
  "mcpServers": {
    "achilles": {
      "command": ${jsonCommand},
      "args": ["mcp"]
    }
  }
}`,
    claude: `claude mcp add achilles -- ${shellQuote(command)} mcp`,
    codex: `[mcp_servers.achilles]
command = ${jsonCommand}
args = ["mcp"]`,
    opencode: `{
  "mcp": {
    "achilles": {
      "command": [${jsonCommand}, "mcp"]
    }
  }
}`,
  };
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function Snippet({
  label,
  value,
  copyLabel,
  onCopied,
  onFailed,
}: {
  label: string;
  value: string;
  copyLabel: string;
  onCopied: () => void;
  onFailed: () => void;
}) {
  return (
    <div className="min-w-0">
      <div className="flex items-center justify-between gap-2 mb-1">
        <p className="text-[11px] text-text-muted">{label}</p>
        <Button
          type="button"
          size="xs"
          variant="ghost"
          onClick={() => {
            void copyText(value).then((ok) => (ok ? onCopied() : onFailed()));
          }}
        >
          <Copy className="size-3.5" />
          {copyLabel}
        </Button>
      </div>
      <pre className="text-[11px] leading-snug bg-background-secondary border border-border-primary rounded-md p-2 overflow-x-auto whitespace-pre-wrap break-all">
        {value}
      </pre>
    </div>
  );
}

export default function AchillesMcpHelp() {
  const intl = useIntl();
  const [command, setCommand] = useState('achilles');

  useEffect(() => {
    let cancelled = false;
    void window.electron
      ?.getBinaryPath?.('achilles')
      .then((path) => {
        if (!cancelled && path) setCommand(path);
      })
      .catch(() => {
        /* keep achilles on PATH */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const snippets = useMemo(() => mcpSnippets(command), [command]);
  const copied = () => toast.success(intl.formatMessage(i18n.copied));
  const failed = () => toast.error(intl.formatMessage(i18n.copyFailed));

  return (
    <Dialog>
      <DialogTrigger asChild>
        <button
          type="button"
          className="shrink-0 w-full text-left px-4 py-2 border-t border-border-primary text-[11px] leading-snug text-text-muted hover:text-text-primary hover:bg-background-secondary/50"
        >
          <span className="inline-flex items-center gap-1.5 min-w-0">
            <Plug className="size-3 shrink-0" aria-hidden="true" />
            <span className="min-w-0">{intl.formatMessage(i18n.trigger)}</span>
          </span>
        </button>
      </DialogTrigger>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{intl.formatMessage(i18n.title)}</DialogTitle>
          <DialogDescription>{intl.formatMessage(i18n.body)}</DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <Snippet
            label={intl.formatMessage(i18n.commandLabel)}
            value={snippets.argv}
            copyLabel={intl.formatMessage(i18n.copySnippet)}
            onCopied={copied}
            onFailed={failed}
          />
          <Snippet
            label={intl.formatMessage(i18n.cursorLabel)}
            value={snippets.cursor}
            copyLabel={intl.formatMessage(i18n.copySnippet)}
            onCopied={copied}
            onFailed={failed}
          />
          <Snippet
            label={intl.formatMessage(i18n.claudeLabel)}
            value={snippets.claude}
            copyLabel={intl.formatMessage(i18n.copySnippet)}
            onCopied={copied}
            onFailed={failed}
          />
          <Snippet
            label={intl.formatMessage(i18n.codexLabel)}
            value={snippets.codex}
            copyLabel={intl.formatMessage(i18n.copySnippet)}
            onCopied={copied}
            onFailed={failed}
          />
          <Snippet
            label={intl.formatMessage(i18n.opencodeLabel)}
            value={snippets.opencode}
            copyLabel={intl.formatMessage(i18n.copySnippet)}
            onCopied={copied}
            onFailed={failed}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

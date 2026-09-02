export type ToolAction =
  | 'hash'
  | 'hash_verify'
  | 'redact'
  | 'entropy'
  | 'hex'
  | 'base64'
  | 'jwt'
  | 'encrypt'
  | 'decrypt'
  | 'shred'
  | 'git_purge_plan';

export type ToolField = 'path' | 'text' | 'passphrase' | 'expected' | 'confirm';

export type ToolGroupId = 'inspect' | 'transform' | 'protect';

export type ToolDef = {
  action: ToolAction;
  group: ToolGroupId;
  needs: ToolField[];
  destructive?: boolean;
};

export const TOOL_GROUPS: { id: ToolGroupId; tools: ToolAction[] }[] = [
  { id: 'inspect', tools: ['hash', 'hash_verify', 'entropy'] },
  { id: 'transform', tools: ['redact', 'hex', 'base64', 'jwt'] },
  { id: 'protect', tools: ['encrypt', 'decrypt', 'shred', 'git_purge_plan'] },
];

export const TOOLS: ToolDef[] = [
  { action: 'hash', group: 'inspect', needs: ['path'] },
  { action: 'hash_verify', group: 'inspect', needs: ['path', 'expected'] },
  { action: 'entropy', group: 'inspect', needs: ['text'] },
  { action: 'redact', group: 'transform', needs: ['text'] },
  { action: 'hex', group: 'transform', needs: ['text'] },
  { action: 'base64', group: 'transform', needs: ['text'] },
  { action: 'jwt', group: 'transform', needs: ['text'] },
  { action: 'encrypt', group: 'protect', needs: ['path', 'passphrase'] },
  { action: 'decrypt', group: 'protect', needs: ['path', 'passphrase'] },
  { action: 'shred', group: 'protect', needs: ['path', 'confirm'], destructive: true },
  { action: 'git_purge_plan', group: 'protect', needs: ['path'] },
];

export function toolOf(action: ToolAction): ToolDef {
  return TOOLS.find((tool) => tool.action === action) ?? TOOLS[0];
}

/** Prefer a workspace-relative path so the engine can refuse escapes. */
export function relativeToWorkspace(root: string, selected: string): string {
  const norm = (value: string) => value.replace(/\\/g, '/').replace(/\/+$/, '');
  const base = norm(root);
  const abs = norm(selected);
  if (!base) return abs;
  const prefix = `${base.toLowerCase()}/`;
  const lower = abs.toLowerCase();
  if (lower === base.toLowerCase()) return '';
  if (lower.startsWith(prefix)) return abs.slice(base.length + 1);
  return abs;
}

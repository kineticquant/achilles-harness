import type { AchillesFinding } from '../../acp/achilles';
import { ACHILLES_REPO, ACHILLES_SITE } from '../../utils/achillesLinks';

export type AttachedFinding = {
  id: string;
  title: string;
  context: string;
};

export { ACHILLES_REPO, ACHILLES_SITE };

export const EDITOR_BRIEF_LEAD =
  'You are fixing a finding from Achilles (https://achilles.sh). Achilles is a local AppSec harness: a native desktop agent that scans your own workspace for leaked secrets, insecure code patterns (SAST), vulnerable dependencies (SCA), and exposed deploy/CI surfaces, then records those findings for triage. It is not an IDE. Product: https://achilles.sh — source: https://github.com/kineticquant/achilles-harness';

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function snippetOf(finding: AchillesFinding): string | null {
  const investigation = asRecord(finding.evidence.investigation);
  if (typeof investigation.snippet === 'string' && investigation.snippet.trim()) {
    return investigation.snippet.trim();
  }
  if (typeof finding.evidence.preview === 'string' && finding.evidence.preview.trim()) {
    return finding.evidence.preview.trim();
  }
  return null;
}

function locOf(finding: AchillesFinding): string {
  if (!finding.path) return finding.ruleId;
  if (finding.lineStart && finding.lineEnd && finding.lineEnd !== finding.lineStart) {
    return `${finding.path}:${finding.lineStart}-${finding.lineEnd}`;
  }
  if (finding.lineStart) return `${finding.path}:${finding.lineStart}`;
  return finding.path;
}

function listOf(value: unknown): string | null {
  if (Array.isArray(value)) {
    const parts = value
      .map((item) => (typeof item === 'string' ? item.trim() : item == null ? '' : String(item)))
      .filter(Boolean);
    return parts.length ? parts.join(', ') : null;
  }
  if (typeof value === 'string' && value.trim()) return value.trim();
  return null;
}

function kindOf(category: string): string {
  if (category === 'sast') return 'insecure code pattern (SAST)';
  if (category === 'delta') return 'issue introduced by local git changes';
  if (category === 'literals') {
    return 'hardcoded value (not a security finding — stability / config hygiene)';
  }
  if (category === 'sca') return 'vulnerable dependency (SCA)';
  if (category === 'secrets') return 'leaked secret';
  if (category === 'history') return 'secret still in git history';
  if (category === 'harden') return 'insecure app/config default (cookies, CORS, CSP)';
  if (category === 'surface' || category === 'surfaces') return 'exposed deploy/CI surface';
  return 'finding';
}

function evidenceContext(finding: AchillesFinding): string[] {
  const keys = ['engine', 'kind', 'origin', 'unit', 'package', 'name', 'ecosystem', 'version', 'advisory', 'cve', 'surface'];
  const lines: string[] = [];
  for (const key of keys) {
    const value = finding.evidence[key];
    if (typeof value === 'string' && value.trim()) {
      lines.push(`${key}: ${value.trim()}`);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      lines.push(`${key}: ${String(value)}`);
    }
  }
  return lines.length ? ['', 'Extra context:', ...lines] : [];
}

export const USER_QUESTION_MARKER = '\n\nUser question:\n';
export const FINDING_CONTEXT_LEAD = 'Achilles finding (id=';

export function findingAsChatContext(finding: AchillesFinding): string {
  const loc = finding.path
    ? `${finding.path}${finding.lineStart ? `:${finding.lineStart}` : ''}`
    : '';
  const snippet = snippetOf(finding);
  return [
    `Achilles finding (id=${finding.id}). Use this finding only. Do not invent other findings, CVEs, or exploits.`,
    `Explain and triage in plain language. Say findings, never ledger. Do not mention that chat is a preview.`,
    `Do not call appsec_scan. This finding is from a completed scan. Use appsec_investigate with this finding_id only if you need more nearby source.`,
    `Prefer they apply a patch in their usual editor or coding agent; edit files here only if they clearly ask.`,
    `severity=${finding.severity}`,
    `rule=${finding.ruleId}`,
    `title=${finding.title}`,
    loc ? `location=${loc}` : null,
    finding.description.trim() ? finding.description.trim() : null,
    snippet ? `snippet:\n${snippet}` : null,
  ]
    .filter((line): line is string => Boolean(line))
    .join('\n');
}

export function composeFindingChatPayload(context: string, question: string): string {
  return `${context}${USER_QUESTION_MARKER}${question}`;
}

export function splitFindingChatPayload(
  text: string
): { context: string; question: string } | null {
  if (!text.startsWith(FINDING_CONTEXT_LEAD)) return null;
  const idx = text.indexOf(USER_QUESTION_MARKER);
  if (idx === -1) return null;
  const context = text.slice(0, idx);
  const question = text.slice(idx + USER_QUESTION_MARKER.length);
  if (!context.trim()) return null;
  return { context, question };
}

export function findingContextTitle(context: string): string | null {
  const match = /^title=(.+)$/m.exec(context);
  const title = match?.[1]?.trim();
  return title || null;
}

export function findingAsEditorBrief(finding: AchillesFinding): string {
  const loc = locOf(finding);
  const snippet = snippetOf(finding);
  const source = snippet ? `\`\`\`\n${snippet}\n\`\`\`` : '(no source snippet on this finding)';
  const cwe = listOf(finding.cwe);
  const cve = listOf(finding.cve);
  return [
    EDITOR_BRIEF_LEAD,
    '',
    '## Finding',
    `Achilles finding id: ${finding.id}`,
    `State: ${finding.state}`,
    `File: ${loc}`,
    `Severity: ${finding.severity}`,
    `Confidence: ${finding.confidence}`,
    `Kind: ${kindOf(finding.category)}`,
    `Rule: ${finding.ruleId}`,
    `Title: ${finding.title}`,
    ...(cwe ? [`CWE: ${cwe}`] : []),
    ...(cve ? [`CVE: ${cve}`] : []),
    ...evidenceContext(finding),
    '',
    'What Achilles found:',
    finding.description.trim() || '(no description)',
    '',
    'Source (may be redacted by Achilles; do not print secret values):',
    source,
    '',
    '## Rules for the coding agent',
    '- Fix only this finding (the id above). Do not invent other findings, CVEs, or exploits.',
    '- Do not print secrets. If this is a leaked credential, rotate it at the provider and remove it from the file (and from git history if it was committed).',
    '- After a real patch, tell the user they can Rescan in Achilles Findings, or mark this finding fixed there.',
    '',
    '## Achilles MCP (optional)',
    'If Achilles MCP is connected in this editor, or the user asks you to use it, you may close or inspect this finding yourself. Tools (never invent finding ids):',
    `- \`appsec_investigate\` with \`finding_id=${finding.id}\` — extra nearby source for this finding only.`,
    '- `appsec_query` — current findings list / ranking. Do not invent ids.',
    `- After the fix is actually in the tree: \`appsec_triage\` with \`finding_id=${finding.id}\` and \`state=verified_fixed\`.`,
    `- If this is a false positive and the user agrees: \`appsec_triage\` with \`finding_id=${finding.id}\` and \`state=dismissed\`.`,
    '- Do not call `appsec_scan` unless they ask. If MCP is not connected, apply the patch here and tell them to Rescan or mark the finding in Achilles Findings.',
    '',
  ].join('\n');
}

export function attachFinding(finding: AchillesFinding): AttachedFinding {
  return {
    id: finding.id,
    title: finding.title,
    context: findingAsChatContext(finding),
  };
}

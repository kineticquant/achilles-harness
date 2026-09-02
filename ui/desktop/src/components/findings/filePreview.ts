/** Caps a preview so Monaco stays responsive on large lockfiles / dumps. */
export const MAX_PREVIEW_CHARS = 1_000_000;

const BINARY_EXT = new Set([
  '7z',
  'bin',
  'bmp',
  'class',
  'dll',
  'dylib',
  'eot',
  'exe',
  'gif',
  'gz',
  'ico',
  'jar',
  'jpeg',
  'jpg',
  'mp3',
  'mp4',
  'o',
  'obj',
  'otf',
  'pdf',
  'png',
  'pyc',
  'pyo',
  'rar',
  'so',
  'tgz',
  'ttf',
  'wasm',
  'webm',
  'webp',
  'woff',
  'woff2',
  'zip',
]);

const LANGUAGE_BY_EXT: Record<string, string> = {
  bash: 'shell',
  bat: 'bat',
  c: 'c',
  cc: 'cpp',
  cmake: 'plaintext',
  coffee: 'coffee',
  cpp: 'cpp',
  cs: 'csharp',
  css: 'css',
  cxx: 'cpp',
  dart: 'dart',
  env: 'ini',
  erl: 'plaintext',
  ex: 'plaintext',
  exs: 'plaintext',
  fs: 'fsharp',
  go: 'go',
  graphql: 'graphql',
  groovy: 'plaintext',
  h: 'c',
  hpp: 'cpp',
  htm: 'html',
  html: 'html',
  ini: 'ini',
  java: 'java',
  js: 'javascript',
  json: 'json',
  jsonc: 'json',
  jsx: 'javascript',
  kts: 'kotlin',
  kt: 'kotlin',
  less: 'less',
  lua: 'lua',
  m: 'objective-c',
  md: 'markdown',
  mdx: 'markdown',
  mm: 'objective-c',
  php: 'php',
  pl: 'perl',
  pm: 'perl',
  proto: 'plaintext',
  ps1: 'powershell',
  py: 'python',
  r: 'r',
  rb: 'ruby',
  rs: 'rust',
  sass: 'scss',
  scala: 'plaintext',
  scss: 'scss',
  sh: 'shell',
  sql: 'sql',
  swift: 'swift',
  tf: 'plaintext',
  tfvars: 'plaintext',
  toml: 'ini',
  ts: 'typescript',
  tsx: 'typescript',
  vb: 'vb',
  vue: 'html',
  xml: 'xml',
  yaml: 'yaml',
  yml: 'yaml',
  zsh: 'shell',
};

const LANGUAGE_BY_BASENAME: Record<string, string> = {
  dockerfile: 'dockerfile',
  justfile: 'shell',
  makefile: 'plaintext',
  procfile: 'plaintext',
};

export function isWindowsPath(workingDir: string): boolean {
  return /^[a-zA-Z]:/.test(workingDir) || workingDir.includes('\\');
}

export function resolveFindingPath(workingDir: string, rel: string): string {
  if (/^[a-zA-Z]:[\\/]/.test(rel) || rel.startsWith('\\\\') || rel.startsWith('/')) {
    return rel;
  }
  const sep = isWindowsPath(workingDir) ? '\\' : '/';
  const root = workingDir.replace(/[\\/]+$/, '').replace(/[\\/]/g, sep);
  const leaf = rel.replace(/[\\/]/g, sep);
  return `${root}${sep}${leaf}`;
}

export function fileBasename(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] ?? path;
}

export function fileExtension(path: string): string {
  const name = fileBasename(path);
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return '';
  return name.slice(dot + 1).toLowerCase();
}

export function languageFromPath(path: string): string {
  const name = fileBasename(path).toLowerCase();
  if (LANGUAGE_BY_BASENAME[name]) return LANGUAGE_BY_BASENAME[name];
  if (name.startsWith('.env') || name.endsWith('.env') || name.includes('.env.')) {
    return 'ini';
  }
  if (name.endsWith('.erb')) return 'ruby';
  const ext = fileExtension(path);
  return LANGUAGE_BY_EXT[ext] ?? 'plaintext';
}

export function isBinaryPath(path: string): boolean {
  return BINARY_EXT.has(fileExtension(path));
}

export function looksBinary(content: string): boolean {
  const sample = content.slice(0, 8_192);
  if (sample.includes('\0')) return true;
  let suspicious = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const code = sample.charCodeAt(i);
    if (code === 0xfffd || (code < 9 && code !== 0) || (code > 14 && code < 32 && code !== 27)) {
      suspicious += 1;
    }
  }
  return sample.length > 0 && suspicious / sample.length > 0.3;
}

export type PreviewLoad =
  | { status: 'ready'; value: string }
  | { status: 'missing' }
  | { status: 'tooLarge' }
  | { status: 'binary' }
  | { status: 'error' };

export function previewFromRead(
  result: { found: boolean; error?: unknown; file?: string | null },
  path: string
): PreviewLoad {
  if (isBinaryPath(path)) return { status: 'binary' };
  if (!result.found || result.error || result.file == null) return { status: 'missing' };
  if (result.file.length > MAX_PREVIEW_CHARS) return { status: 'tooLarge' };
  if (looksBinary(result.file)) return { status: 'binary' };
  return { status: 'ready', value: result.file };
}

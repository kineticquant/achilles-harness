import { describe, expect, it } from 'vitest';
import {
  fileBasename,
  isBinaryPath,
  isWindowsPath,
  languageFromPath,
  looksBinary,
  previewFromRead,
  resolveFindingPath,
} from './filePreview';

describe('resolveFindingPath', () => {
  it('joins a Windows workspace that used forward slashes', () => {
    expect(resolveFindingPath('H:/repo', '.env.erb')).toBe('H:\\repo\\.env.erb');
  });

  it('joins a Windows workspace that used backslashes', () => {
    expect(resolveFindingPath('H:\\repo', 'src/app.py')).toBe('H:\\repo\\src\\app.py');
  });

  it('joins a posix workspace', () => {
    expect(resolveFindingPath('/home/me/repo', 'src/app.py')).toBe('/home/me/repo/src/app.py');
  });

  it('keeps an absolute Windows path', () => {
    expect(resolveFindingPath('H:\\repo', 'H:\\repo\\.env.erb')).toBe('H:\\repo\\.env.erb');
  });
});

describe('isWindowsPath', () => {
  it('detects a drive letter even with forward slashes', () => {
    expect(isWindowsPath('H:/repo')).toBe(true);
    expect(isWindowsPath('/home/me')).toBe(false);
  });
});

describe('languageFromPath', () => {
  it('maps source, env, and docker files', () => {
    expect(languageFromPath('leak.env')).toBe('ini');
    expect(languageFromPath('.env.erb')).toBe('ini');
    expect(languageFromPath('app.py')).toBe('python');
    expect(languageFromPath('inject.go')).toBe('go');
    expect(languageFromPath('ui/App.tsx')).toBe('typescript');
    expect(languageFromPath('Dockerfile')).toBe('dockerfile');
    expect(fileBasename('crates/store/src/lib.rs')).toBe('lib.rs');
    expect(languageFromPath('crates/store/src/lib.rs')).toBe('rust');
  });
});

describe('previewFromRead', () => {
  it('rejects binaries by extension without reading contents', () => {
    expect(previewFromRead({ found: true, file: 'not-an-image' }, 'icon.png')).toEqual({
      status: 'binary',
    });
    expect(isBinaryPath('font.woff2')).toBe(true);
  });

  it('rejects NUL bytes as binary', () => {
    expect(looksBinary('abc\0def')).toBe(true);
    expect(previewFromRead({ found: true, file: 'abc\0def' }, 'blob.dat')).toEqual({
      status: 'binary',
    });
  });

  it('returns missing when the file was not found', () => {
    expect(previewFromRead({ found: false, file: '', error: 'enoent' }, 'gone.env')).toEqual({
      status: 'missing',
    });
  });

  it('returns the text when the file is small and readable', () => {
    expect(previewFromRead({ found: true, file: 'KEY=1\n' }, '.env')).toEqual({
      status: 'ready',
      value: 'KEY=1\n',
    });
  });
});

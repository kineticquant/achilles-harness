/** Test/vendor fixtures and third-party URLs are not app HTTP. */

const NOISE_DIR =
  /(^|\/)(?:test|tests|spec|specs|__tests__|fixtures|factories|mocks|vendor|node_modules|dist|build)(?:\/|$)/i;

const NOISE_FILE = /\.(?:test|spec|min)\.[^.]+$/i;

const SKIP_HELPER =
  /(?:avatar|logo|asset|webpack|vite|image_tag|stylesheet|javascript_path|csrf|nonce)$/i;

export function isNoiseFile(file: string): boolean {
  const norm = file.replace(/\\/g, '/');
  if (NOISE_DIR.test(norm)) return true;
  const base = norm.split('/').pop() || norm;
  return NOISE_FILE.test(base);
}

export function isSkipHelper(helper: string): boolean {
  return SKIP_HELPER.test(helper.replace(/_(?:path|url)$/i, ''));
}

/** Absolute URLs to public hosts (Twitter stubs, etc.) are not this app's API. */
export function isExternalHttpLiteral(raw: string): boolean {
  const trimmed = raw.trim();
  if (!/^(?:https?:)?\/\//i.test(trimmed) && !/^https?:\/\//i.test(trimmed)) return false;
  const withScheme = /^https?:/i.test(trimmed) ? trimmed : `https:${trimmed}`;
  try {
    const url = new URL(withScheme);
    const host = url.hostname.toLowerCase();
    if (!host || /[#{]/.test(host) || host.includes('$')) return false;
    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host.endsWith('.local')) {
      return false;
    }
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}

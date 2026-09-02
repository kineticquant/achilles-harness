export function normalizePath(raw: string): string | undefined {
  let value = raw.trim();
  if (!value || value.length > 240) return undefined;
  value = value.replace(/\\/g, '/');
  value = value.replace(/\$\{[^}]+\}/g, ':param');
  value = value.replace(/\{[^}]+\}/g, ':param');
  value = value.replace(/<[^>]+>/g, ':param');
  value = value.replace(/:[A-Za-z_][\w]*/g, ':param');
  value = value.replace(/\[[^\]]+\]/g, ':param');
  if (/^(?:https?:)?\/\//i.test(value)) {
    try {
      const url = new URL(value.startsWith('http') ? value : `https:${value}`);
      value = url.pathname || '/';
    } catch {
      const cut = value.replace(/^(?:https?:)?\/\/[^/]+/i, '');
      value = cut.startsWith('/') ? cut : `/${cut}`;
    }
  }
  const q = value.indexOf('?');
  if (q >= 0) value = value.slice(0, q);
  const hash = value.indexOf('#');
  if (hash >= 0) value = value.slice(0, hash);
  if (!value.startsWith('/')) {
    if (!/^[A-Za-z0-9._~/-]+$/.test(value) || !value.includes('/')) return undefined;
    value = `/${value}`;
  }
  if (value === '/' || value === '/:param') return undefined;
  const parts = value
    .split('/')
    .filter(Boolean)
    .map((part) => (part === ':param' || part === '*' ? ':param' : part.toLowerCase()));
  if (!parts.length) return undefined;
  return `/${parts.join('/')}`;
}

export function pathsMatch(a: string, b: string): boolean {
  const left = segs(a);
  const right = segs(b);
  if (left.length === right.length && segsMatch(left, right)) return true;
  const shorter = left.length <= right.length ? left : right;
  const longer = left.length > right.length ? left : right;
  if (!shorter.length) return false;
  if (shorter.length === 1 && (shorter[0] === ':param' || (shorter[0]?.length ?? 0) < 4)) {
    return false;
  }
  return segsMatch(shorter, longer.slice(longer.length - shorter.length));
}

function segs(path: string): string[] {
  return path.split('/').filter(Boolean);
}

function segsMatch(a: string[], b: string[]): boolean {
  return a.every((part, i) => part === b[i] || part === ':param' || b[i] === ':param');
}

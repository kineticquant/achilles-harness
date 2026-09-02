export type FileOption = { value: string; label: string };

function dirOf(file: string): string {
  const norm = file.replace(/\\/g, '/');
  const slash = norm.lastIndexOf('/');
  return slash === -1 ? '.' : norm.slice(0, slash);
}

function baseOf(file: string): string {
  const norm = file.replace(/\\/g, '/');
  const slash = norm.lastIndexOf('/');
  return slash === -1 ? norm : norm.slice(slash + 1);
}

export function groupFilesByFolder(files: string[]): { label: string; options: FileOption[] }[] {
  const map = new Map<string, FileOption[]>();
  for (const file of files) {
    const value = file.replace(/\\/g, '/');
    const dir = dirOf(value);
    const list = map.get(dir) ?? [];
    list.push({ value, label: baseOf(value) });
    map.set(dir, list);
  }
  return [...map.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([label, options]) => ({
      label,
      options: options.sort((a, b) => a.label.localeCompare(b.label)),
    }));
}

export function fileOptionLabel(file: string): string {
  const dir = dirOf(file);
  const base = baseOf(file);
  return dir === '.' ? base : `${dir}/${base}`;
}

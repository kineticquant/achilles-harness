import fsSync from 'node:fs';
import path from 'node:path';

function imageDirs(): string[] {
  return [
    path.join(process.cwd(), 'src', 'images'),
    path.join(process.resourcesPath || '', 'images'),
    path.join(__dirname, '..', 'images'),
    path.join(__dirname, 'images'),
    path.join(process.cwd(), 'images'),
  ];
}

export function resolveDesktopImage(...fileNames: string[]): string | undefined {
  for (const dir of imageDirs()) {
    for (const name of fileNames) {
      const candidate = path.join(dir, name);
      if (fsSync.existsSync(candidate)) {
        return candidate;
      }
    }
  }
  return undefined;
}

export function resolveWindowIcon(): string | undefined {
  if (process.platform === 'win32') {
    return resolveDesktopImage('icon.ico', 'icon.png');
  }
  if (process.platform === 'darwin') {
    return resolveDesktopImage('icon.icns', 'icon.png');
  }
  return resolveDesktopImage('icon.png', 'icon.ico');
}

export function resolveTrayIcon(hasUpdate = false): string | undefined {
  if (process.platform === 'win32') {
    return hasUpdate
      ? resolveDesktopImage('iconTrayUpdate-win.png', 'iconTemplateUpdate.png', 'icon.ico')
      : resolveDesktopImage('iconTray-win.png', 'iconTray-win@2x.png', 'icon.ico', 'icon.png');
  }
  return hasUpdate
    ? resolveDesktopImage('iconTemplateUpdate.png', 'iconTemplate.png')
    : resolveDesktopImage('iconTemplate.png');
}

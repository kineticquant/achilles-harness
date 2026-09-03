import { describe, expect, it } from 'vitest';

import { groupFilesByFolder } from './groupFiles';

describe('groupFilesByFolder', () => {
  it('groups by directory', () => {
    const groups = groupFilesByFolder([
      'app/javascript/controllers/composer_controller.js',
      'app/javascript/controllers/other.js',
      'api/routes.py',
    ]);
    expect(groups.map((g) => g.label)).toEqual(['api', 'app/javascript/controllers']);
    expect(groups[1]?.options.map((o) => o.label)).toEqual(['composer_controller.js', 'other.js']);
  });
});

import { describe, expect, it } from 'vitest';

import { enclosingFunction, listFunctionsInSource, seedSymbolFromSource } from './seedSymbol';

const rust = `fn helper() {}
fn process() {
    validate(1);
}
`;

describe('seedSymbolFromSource', () => {
  it('uses a definition on the hit line', () => {
    expect(seedSymbolFromSource(rust, 2)).toBe('process');
  });

  it('uses the enclosing function for a body line, including calls', () => {
    expect(seedSymbolFromSource(rust, 3)).toBe('process');
    expect(seedSymbolFromSource('fn process() {\n    let x = 1;\n}\n', 2)).toBe('process');
  });

  it('uses the callee when there is no enclosing def nearby', () => {
    expect(seedSymbolFromSource('    validate(1);\n', 1)).toBe('validate');
  });

  it('reads python defs and js functions', () => {
    expect(seedSymbolFromSource('def load_config():\n    pass\n', 1)).toBe('load_config');
    expect(seedSymbolFromSource('export async function fetchUser() {}\n', 1)).toBe('fetchUser');
  });

  it('strips a rust path prefix on a call', () => {
    expect(seedSymbolFromSource('    Foo::bar(x);\n', 1)).toBe('bar');
  });

  it('does not treat Stimulus anonymous class extends as the symbol', () => {
    const src = `import { Controller } from '@hotwired/stimulus';

export default class extends Controller {
  preview(file) {
    this.iconTarget.innerHTML = fileType.match(/x/) ? '<img>' : '<span>';
  }
}
`;
    expect(listFunctionsInSource(src).map((item) => item.name)).toEqual(['preview']);
    expect(listFunctionsInSource(src).map((item) => item.name)).not.toContain('Controller');
    expect(enclosingFunction(listFunctionsInSource(src), 5)).toBe('preview');
    expect(seedSymbolFromSource(src, 3)).not.toBe('extends');
    expect(seedSymbolFromSource(src, 5)).not.toBe('innerHTML');
  });

  it('picks the enclosing method for a body line even when the line is a call', () => {
    const src = `fn process() {
    validate(1);
}
`;
    expect(seedSymbolFromSource(src, 2)).toBe('process');
  });
});

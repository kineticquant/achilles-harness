import { describe, expect, it } from 'vitest';

import { layoutInspectGraph } from './layout';
import type { InspectGraph } from './types';

describe('layoutInspectGraph', () => {
  it('places callers left of focus and callees to the right', () => {
    const graph: InspectGraph = {
      focus: 'process',
      found: true,
      filesAnalyzed: 2,
      truncated: false,
      nodes: [
        { id: 'a.rs:1:process', file: 'a.rs', name: 'process', line: 1, kind: 'focus', depth: 0 },
        { id: 'b.rs:1:caller', file: 'b.rs', name: 'caller', line: 1, kind: 'caller', depth: 1 },
        { id: 'c.rs:1:callee', file: 'c.rs', name: 'callee', line: 1, kind: 'callee', depth: 1 },
      ],
      edges: [
        { id: 'e1', source: 'b.rs:1:caller', target: 'a.rs:1:process' },
        { id: 'e2', source: 'a.rs:1:process', target: 'c.rs:1:callee' },
      ],
    };

    const { nodes, edges } = layoutInspectGraph(graph);
    const focus = nodes.find((n) => n.id === 'a.rs:1:process');
    const caller = nodes.find((n) => n.id === 'b.rs:1:caller');
    const callee = nodes.find((n) => n.id === 'c.rs:1:callee');
    expect(focus && caller && callee).toBeTruthy();
    expect(caller!.position.x).toBeLessThan(focus!.position.x);
    expect(callee!.position.x).toBeGreaterThan(focus!.position.x);
    expect(edges).toHaveLength(2);
  });

  it('does not stack template nodes on top of renderers', () => {
    const graph: InspectGraph = {
      focus: 'allow_browser',
      found: true,
      filesAnalyzed: 2,
      truncated: false,
      nodes: [
        {
          id: 'comp:1',
          file: 'app/components/allow_browser.rb',
          name: 'allow_browser',
          line: 1,
          kind: 'focus',
          depth: 0,
        },
        {
          id: 'tmpl:1',
          file: 'app/views/sessions/incompatible_browser.html.erb',
          name: 'sessions/incompatible_browser',
          line: 1,
          kind: 'template',
          depth: 1,
        },
        {
          id: 'var:1',
          file: 'app/views/sessions/incompatible_browser.html.erb',
          name: '{{ page_title }}',
          line: 3,
          kind: 'callee',
          depth: 2,
        },
      ],
      edges: [
        { id: 'e1', source: 'comp:1', target: 'tmpl:1' },
        { id: 'e2', source: 'tmpl:1', target: 'var:1' },
      ],
    };
    const { nodes } = layoutInspectGraph(graph);
    const xs = nodes.map((node) => node.position.x);
    const ys = nodes.map((node) => node.position.y);
    expect(new Set(xs).size).toBe(3);
    expect(new Set(nodes.map((node) => `${node.position.x},${node.position.y}`)).size).toBe(3);
    const renderer = nodes.find((node) => node.id === 'comp:1');
    const tmpl = nodes.find((node) => node.id === 'tmpl:1');
    const variable = nodes.find((node) => node.id === 'var:1');
    expect(renderer!.position.x).toBeLessThan(tmpl!.position.x);
    expect(tmpl!.position.x).toBeLessThan(variable!.position.x);
    expect(ys.every((y) => y >= 40)).toBe(true);
  });
});

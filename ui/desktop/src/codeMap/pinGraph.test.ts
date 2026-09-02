import { pinGraphToFileSymbol } from './pinGraph';
import type { InspectGraph } from './types';

const graph: InspectGraph = {
  focus: 'connect',
  found: true,
  filesAnalyzed: 4,
  truncated: false,
  nodes: [
    { id: 'a:1:connect', file: 'composer_controller.js', name: 'connect', line: 4, kind: 'focus', depth: 0 },
    { id: 'b:1:connect', file: 'other_controller.js', name: 'connect', line: 8, kind: 'focus', depth: 0 },
    { id: 'a:10:submit', file: 'composer_controller.js', name: 'submit', line: 10, kind: 'callee', depth: 1 },
  ],
  edges: [{ id: 'e1', source: 'a:1:connect', target: 'a:10:submit' }],
};

describe('pinGraphToFileSymbol', () => {
  it('drops same-named functions in other files', () => {
    const pinned = pinGraphToFileSymbol(graph, 'composer_controller.js', 'connect', 4);
    expect(pinned.nodes.map((node) => node.id).sort()).toEqual(['a:10:submit', 'a:1:connect']);
  });

  it('does not pull in other callers of a shared callee', () => {
    const shared: InspectGraph = {
      ...graph,
      nodes: [
        ...graph.nodes,
        { id: 'c:12:update', file: 'badge_dot_controller.js', name: 'update', line: 12, kind: 'callee', depth: 1 },
      ],
      edges: [
        { id: 'e1', source: 'a:1:connect', target: 'c:12:update' },
        { id: 'e2', source: 'b:1:connect', target: 'c:12:update' },
      ],
    };
    const pinned = pinGraphToFileSymbol(shared, 'composer_controller.js', 'connect', 4);
    expect(pinned.nodes.map((node) => node.id).sort()).toEqual(['a:1:connect', 'c:12:update']);
  });
});

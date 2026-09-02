import type { InspectGraph } from './types';

function norm(path: string): string {
  return path.replace(/\\/g, '/').toLowerCase();
}

function fileMatches(nodeFile: string, want: string): boolean {
  const a = norm(nodeFile);
  const b = norm(want).split('/').filter(Boolean).join('/');
  if (!b) return true;
  return a === b || a.endsWith(`/${b}`) || b.endsWith(`/${a}`);
}

/** Keep the neighborhood of one file's function, not every same-named function in the walk. */
export function pinGraphToFileSymbol(
  graph: InspectGraph,
  file: string | undefined,
  name: string,
  line?: number
): InspectGraph {
  if (!graph.found || !file) return graph;
  let starts = graph.nodes.filter((node) => node.name === name && fileMatches(node.file, file));
  if (line) {
    const atLine = starts.filter((node) => node.line === line);
    if (atLine.length) starts = atLine;
  }
  if (!starts.length) return graph;

  const startIds = new Set(starts.map((node) => node.id));
  const ids = new Set(startIds);

  const walk = (forward: boolean) => {
    const frontier = new Set(startIds);
    while (frontier.size) {
      const next = new Set<string>();
      for (const edge of graph.edges) {
        const from = forward ? edge.source : edge.target;
        const to = forward ? edge.target : edge.source;
        if (frontier.has(from) && !ids.has(to)) {
          ids.add(to);
          next.add(to);
        }
      }
      frontier.clear();
      for (const id of next) frontier.add(id);
    }
  };

  // Callees and callers of this function only — not other functions that share a callee.
  walk(true);
  walk(false);

  const nodes = graph.nodes.filter((node) => ids.has(node.id));
  return {
    ...graph,
    nodes,
    edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
    found: nodes.length > 0,
  };
}

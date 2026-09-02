import type { Edge, Node } from '@xyflow/react';
import type { InspectGraph, InspectNode } from './types';

const COL = 280;
const ROW = 96;
const FOCUS_X = 560;

export type CodeMapNodeData = {
  label: string;
  file: string;
  name: string;
  line: number;
  kind: string;
};

function columnKey(node: InspectNode): string {
  if (node.kind === 'focus') return 'focus';
  if (node.kind === 'both') return 'both';
  if (node.kind === 'api') return 'api';
  if (node.kind === 'template') return 'template';
  if (node.kind === 'caller') return `in:${Math.max(1, node.depth || 1)}`;
  return `out:${Math.max(1, node.depth || 1)}`;
}

function columnX(key: string, apiSharesFocus: boolean): number {
  if (key === 'focus' || key === 'both') return FOCUS_X;
  if (key === 'api') return apiSharesFocus ? FOCUS_X + COL : FOCUS_X;
  if (key === 'template') return FOCUS_X + COL;
  if (key.startsWith('in:')) {
    const hops = Number(key.slice(3)) || 1;
    return FOCUS_X - hops * COL;
  }
  const hops = Number(key.slice(4)) || 1;
  return FOCUS_X + hops * COL;
}

function displayName(node: InspectNode): string {
  if (node.name === '<module>') {
    const base = node.file.split('/').pop() || node.file;
    return `${base} (module)`;
  }
  return node.name;
}

function sortNodes(list: InspectNode[]): InspectNode[] {
  return [...list].sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.name.localeCompare(b.name)
  );
}

export function layoutInspectGraph(graph: InspectGraph): {
  nodes: Node<CodeMapNodeData>[];
  edges: Edge[];
} {
  const apiSharesFocus = graph.nodes.some(
    (node) => node.kind === 'focus' || node.kind === 'both' || node.kind === 'template'
  );
  const buckets = new Map<string, InspectNode[]>();
  for (const node of graph.nodes) {
    const key = columnKey(node);
    const list = buckets.get(key) ?? [];
    list.push(node);
    buckets.set(key, list);
  }

  const byX = new Map<number, InspectNode[]>();
  const keys = [...buckets.keys()].sort();
  for (const key of keys) {
    const list = sortNodes(buckets.get(key) ?? []);
    const x = columnX(key, apiSharesFocus);
    const existing = byX.get(x) ?? [];
    byX.set(x, existing.concat(list));
  }

  const nodes: Node<CodeMapNodeData>[] = [];
  for (const [x, list] of byX) {
    list.forEach((node, index) => {
      nodes.push({
        id: node.id,
        type: 'codeMap',
        position: { x, y: 40 + index * ROW },
        data: {
          label: displayName(node),
          file: node.file,
          name: node.name,
          line: node.line,
          kind: node.kind,
        },
      });
    });
  }

  const edges: Edge[] = graph.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: 'smoothstep',
    animated: false,
  }));

  return { nodes, edges };
}

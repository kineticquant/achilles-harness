export type InspectNodeKind = 'focus' | 'caller' | 'callee' | 'both' | 'api' | 'template';

export type InspectNode = {
  id: string;
  file: string;
  name: string;
  line: number;
  kind: InspectNodeKind | string;
  depth: number;
};

export type InspectEdge = {
  id: string;
  source: string;
  target: string;
};

export type InspectGraph = {
  focus: string;
  found: boolean;
  filesAnalyzed: number;
  truncated: boolean;
  nodes: InspectNode[];
  edges: InspectEdge[];
};

export type InspectCallGraphRequest = {
  workingDir: string;
  focus: string;
  path?: string;
  file?: string;
  maxDepth?: number;
  followDepth?: number;
};

export type InspectCallGraphResult =
  | { ok: true; graph: InspectGraph; files?: string[] }
  | { ok: false; error: string };

export type CodeMapProgress = {
  current: number;
  total: number;
  file: string;
};

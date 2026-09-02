import { useCallback, useMemo } from 'react';
import {
  Background,
  ControlButton,
  Controls,
  ReactFlow,
  useReactFlow,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { LocateFixed } from 'lucide-react';
import { defineMessages, useIntl } from '../../i18n';
import { layoutInspectGraph } from '../../codeMap/layout';
import type { InspectGraph } from '../../codeMap/types';
import { useTheme } from '../../contexts/ThemeContext';
import CodeMapNode, { type CodeMapFlowNode } from './CodeMapNode';

const nodeTypes = { codeMap: CodeMapNode };

const i18n = defineMessages({
  recenter: {
    id: 'codeMap.recenter',
    defaultMessage: 'Back to center',
  },
});

function RecenterControl() {
  const intl = useIntl();
  const { fitView } = useReactFlow();
  const label = intl.formatMessage(i18n.recenter);
  return (
    <Controls showInteractive={false} showFitView={false}>
      <ControlButton
        onClick={() => {
          void fitView({ padding: 0.2, duration: 220 });
        }}
        title={label}
        aria-label={label}
      >
        <LocateFixed className="size-3.5" />
      </ControlButton>
    </Controls>
  );
}

export default function CodeMapCanvas({
  graph,
  onOpenNode,
  onFocusNode,
}: {
  graph: InspectGraph;
  onOpenNode: (file: string, line: number) => void;
  onFocusNode: (name: string, file: string, line: number) => void;
}) {
  const { resolvedTheme } = useTheme();
  const { nodes, edges } = useMemo(() => layoutInspectGraph(graph), [graph]);

  const onNodeClick: NodeMouseHandler<CodeMapFlowNode> = useCallback(
    (_event, node) => {
      onOpenNode(node.data.file, node.data.line);
    },
    [onOpenNode]
  );

  const onNodeDoubleClick: NodeMouseHandler<CodeMapFlowNode> = useCallback(
    (_event, node) => {
      if (
        node.data.kind === 'api' ||
        node.data.kind === 'template' ||
        !node.data.name ||
        node.data.name === '<module>' ||
        node.data.name.startsWith('{{')
      ) {
        return;
      }
      onFocusNode(node.data.name, node.data.file, node.data.line);
    },
    [onFocusNode]
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={onNodeClick}
      onNodeDoubleClick={onNodeDoubleClick}
      fitView
      nodesConnectable={false}
      edgesReconnectable={false}
      minZoom={0.25}
      maxZoom={1.6}
      colorMode={resolvedTheme === 'dark' ? 'dark' : 'light'}
      proOptions={{ hideAttribution: true }}
      className="code-map-flow bg-background-primary"
    >
      <Background gap={18} size={1} />
      <RecenterControl />
    </ReactFlow>
  );
}

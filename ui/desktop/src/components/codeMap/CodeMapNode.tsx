import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { cn } from '../../utils';
import type { CodeMapNodeData } from '../../codeMap/layout';

export type CodeMapFlowNode = Node<CodeMapNodeData, 'codeMap'>;

const KIND_CLASS: Record<string, string> = {
  focus:
    'border-text-info bg-background-info/15 text-text-primary ring-1 ring-text-info/40',
  caller: 'border-border-secondary bg-background-secondary text-text-primary',
  callee: 'border-border-secondary bg-background-secondary text-text-primary',
  both: 'border-text-warning bg-background-warning/10 text-text-primary',
  api: 'border-text-success bg-background-success/10 text-text-primary ring-1 ring-text-success/30',
  template:
    'border-text-warning bg-background-warning/10 text-text-primary ring-1 ring-text-warning/30',
};

export default function CodeMapNode({ data }: NodeProps<CodeMapFlowNode>) {
  const kindClass = KIND_CLASS[data.kind] ?? KIND_CLASS.caller;
  return (
    <div
      className={cn(
        'min-w-[168px] max-w-[240px] rounded-lg border px-3 py-2 shadow-sm',
        kindClass
      )}
    >
      <Handle type="target" position={Position.Left} className="!size-2 !bg-text-tertiary" />
      <p className="truncate font-mono text-[13px] font-medium leading-tight">{data.label}</p>
      <p className="mt-1 truncate font-mono text-[10px] text-text-tertiary">
        {data.file}:{data.line}
      </p>
      <Handle type="source" position={Position.Right} className="!size-2 !bg-text-tertiary" />
    </div>
  );
}

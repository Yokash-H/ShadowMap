import { useCallback, useMemo } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

interface AttackChainProps {
  chain: {
    nodes: { id: string; label: string; type: string }[];
    edges: { from: string; to: string }[];
  };
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  file:        { bg: '#1e1b4b', border: '#6366f1', text: '#c7d2fe' },
  process:     { bg: '#0c2d48', border: '#3b82f6', text: '#93c5fd' },
  download:    { bg: '#451a03', border: '#f59e0b', text: '#fde68a' },
  network:     { bg: '#0f172a', border: '#06b6d4', text: '#67e8f9' },
  file_op:     { bg: '#1c1917', border: '#78716c', text: '#d6d3d1' },
  persistence: { bg: '#3b0764', border: '#a855f7', text: '#d8b4fe' },
};

const NODE_ICONS: Record<string, string> = {
  file: '📄',
  process: '⚙️',
  download: '⬇️',
  network: '🌐',
  file_op: '📝',
  persistence: '🔒',
};

export default function AttackReplay({ chain }: AttackChainProps) {
  const { nodes, edges } = useMemo(() => {
    // Layout: arrange nodes in a top-to-bottom flow
    const flowNodes: Node[] = chain.nodes.map((n, i) => {
      const colors = NODE_COLORS[n.type] || NODE_COLORS.process;
      const icon = NODE_ICONS[n.type] || '•';
      const col = i % 3;
      const row = Math.floor(i / 3);

      return {
        id: n.id,
        position: { x: 80 + col * 280, y: 40 + row * 120 },
        data: {
          label: (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              padding: '4px 0',
            }}>
              <span style={{ fontSize: 16 }}>{icon}</span>
              <span style={{
                fontSize: 12,
                fontWeight: 600,
                fontFamily: "'JetBrains Mono', monospace",
                color: colors.text,
                wordBreak: 'break-all' as const,
                lineHeight: 1.3,
              }}>
                {n.label.length > 45 ? n.label.slice(0, 45) + '...' : n.label}
              </span>
            </div>
          ),
        },
        sourcePosition: Position.Bottom,
        targetPosition: Position.Top,
        style: {
          background: colors.bg,
          border: `1px solid ${colors.border}`,
          borderRadius: 10,
          padding: '8px 14px',
          boxShadow: `0 0 12px ${colors.border}33`,
          minWidth: 200,
          maxWidth: 260,
        },
      };
    });

    const flowEdges: Edge[] = chain.edges.map((e, i) => ({
      id: `e-${i}`,
      source: e.from,
      target: e.to,
      animated: true,
      style: { stroke: '#6366f1', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#6366f1' },
    }));

    return { nodes: flowNodes, edges: flowEdges };
  }, [chain]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      fitView
      proOptions={{ hideAttribution: true }}
      style={{ background: '#050810' }}
      minZoom={0.3}
      maxZoom={2}
    >
      <Controls
        style={{
          background: '#0d1321',
          border: '1px solid rgba(99,102,241,0.2)',
          borderRadius: 8,
        }}
      />
      <Background color="rgba(99,102,241,0.05)" gap={20} />
    </ReactFlow>
  );
}

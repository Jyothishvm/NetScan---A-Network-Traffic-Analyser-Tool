import React, { useCallback } from 'react';
import ReactFlow, {
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    addEdge,
} from 'reactflow';
import 'reactflow/dist/style.css';

// Custom stylings for our dark mode dashboard
const minimapStyle = {
    height: 120,
    backgroundColor: '#0f172a',
    maskColor: 'rgba(255, 255, 255, 0.1)',
};

const NetworkGraph = ({ graphData }) => {
    // graphData will contain { nodes: [], edges: [] } from our backend generator

    // React Flow hooks to manage state
    const [nodes, setNodes, onNodesChange] = useNodesState(graphData?.nodes || []);
    const [edges, setEdges, onEdgesChange] = useEdgesState(graphData?.edges || []);

    const onConnect = useCallback((params) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

    if (!graphData || (!graphData.nodes.length && !graphData.edges.length)) {
        return (
            <div className="flex h-96 items-center justify-center text-slate-500 bg-black/20 rounded-xl border border-white/5">
                Not enough network relationships detected to generate a graph map.
            </div>
        );
    }

    return (
        <div style={{ height: '500px', width: '100%' }} className="rounded-xl overflow-hidden border border-white/10 shadow-2xl bg-slate-900/50">
            <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                fitView
                attributionPosition="bottom-right"
                className="dark"
            >
                <Controls className="bg-slate-800 border-slate-700 text-white fill-white" />
                <MiniMap style={minimapStyle} nodeStrokeColor="#ffffff" nodeColor="#334155" />
                <Background color="#334155" gap={16} />
            </ReactFlow>
        </div>
    );
};

export default NetworkGraph;

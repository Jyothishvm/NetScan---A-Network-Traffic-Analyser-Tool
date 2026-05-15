import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Play, Square, Activity, Radio, AlertTriangle } from 'lucide-react';
import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:8000' });

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }
    componentDidCatch(error, errorInfo) {
        this.setState({ hasError: true, error: error, errorInfo: errorInfo });
    }
    render() {
        if (this.state.hasError) {
            return (
                <div className="bg-red-900/50 p-6 rounded-xl border border-red-500 text-white font-mono break-all overflow-auto h-[600px]">
                    <h2 className="text-2xl font-bold mb-4">LiveSniffer Component Crashed!</h2>
                    <p className="text-red-300 font-bold">{this.state.error && this.state.error.toString()}</p>
                    <pre className="mt-4 text-sm text-red-200">{this.state.errorInfo && this.state.errorInfo.componentStack}</pre>
                </div>
            );
        }
        return this.props.children;
    }
}

const LiveSnifferContent = () => {
    const [interfaces, setInterfaces] = useState([]);
    const [selectedInterface, setSelectedInterface] = useState('');
    const [isSniffing, setIsSniffing] = useState(false);
    const [livePackets, setLivePackets] = useState([]);
    const [liveRiskScore, setLiveRiskScore] = useState(0);
    const [selectedPacket, setSelectedPacket] = useState(null);
    const [autoScroll, setAutoScroll] = useState(true);
    const [displayFilter, setDisplayFilter] = useState('');
    const [isFilterValid, setIsFilterValid] = useState(true);
    const wsRef = useRef(null);
    const tableContainerRef = useRef(null);

    // Fetch available interfaces on load
    useEffect(() => {
        api.get('/interfaces')
            .then(res => {
                setInterfaces(res.data);
                if (res.data.length > 0) {
                    setSelectedInterface(res.data[0].name);
                }
            })
            .catch(console.error);
    }, []);

    // Auto-scroll the table view
    useEffect(() => {
        if (autoScroll && tableContainerRef.current) {
            tableContainerRef.current.scrollTop = tableContainerRef.current.scrollHeight;
        }
    }, [livePackets, autoScroll]);

    // Anomaly Score Decay
    useEffect(() => {
        if (!isSniffing) return;
        const interval = setInterval(() => {
            setLiveRiskScore(prev => Math.max(0, prev - 1.5));
        }, 1000);
        return () => clearInterval(interval);
    }, [isSniffing]);

    const connectWebSocket = () => {
        // Adjust protocol based on http/https
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        // In dev, the backend runs on port 8000
        const wsUrl = `${protocol}//localhost:8000/sniff/stream`;

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log("WebSocket connected");
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === "packet") {
                    const pkt = msg.data;

                    // Add new packet to the stream, keeping only the last 300 for performance in table mode
                    setLivePackets(prev => {
                        // Attach an incrementing ID to mimic Wireshark's "No." column
                        const newPkt = { ...pkt, id: prev.length > 0 ? prev[prev.length - 1].id + 1 : 1 };
                        const newStream = [...prev, newPkt];
                        return newStream.length > 300 ? newStream.slice(-300) : newStream;
                    });

                    // Super basic live risk calculation based purely on arriving traffic types 
                    // (A full implementation would stream this from the backend loop)
                    if (['DNS', 'HTTP', 'TLS', 'TCP'].includes(pkt.highest_layer)) {
                        setLiveRiskScore(prev => Math.min(100, prev + 0.5));
                    }
                }
            } catch (e) {
                console.error("Error parsing websocket message", e);
            }
        };

        ws.onclose = () => {
            console.log("WebSocket disconnected");
            if (isSniffing) {
                // Try to reconnect if it unexpectedly closed during an active session
                setTimeout(connectWebSocket, 3000);
            }
        };

        wsRef.current = ws;
    };

    const startSniffing = async () => {
        if (!selectedInterface) return;

        try {
            await api.post(`/sniff/start?interface=${encodeURIComponent(selectedInterface)}`);
            setIsSniffing(true);
            setLivePackets([]);
            setLiveRiskScore(0);
            setSelectedPacket(null);
            setAutoScroll(true);
            connectWebSocket();
        } catch (error) {
            console.error("Failed to start sniffing:", error);
            alert("Failed to start sniffer. Check backend logs.");
        }
    };

    const stopSniffing = async () => {
        try {
            await api.post(`/sniff/stop?interface=${encodeURIComponent(selectedInterface)}`);
            setIsSniffing(false);
            if (wsRef.current) {
                wsRef.current.close();
            }
        } catch (error) {
            console.error("Failed to stop sniffing:", error);
        }
    };

    const exportCapture = async () => {
        if (!selectedInterface) return;
        try {
            // Fetch the raw PCAP directly from the backend dumper
            const response = await api.get(`/sniff/download?interface=${encodeURIComponent(selectedInterface)}`, {
                responseType: 'blob'
            });

            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `live_capture_${selectedInterface.replace(/\s+/g, '_')}.pcap`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (error) {
            console.error("Failed to download PCAP:", error);
            alert("No PCAP data available yet. Try sniffing first!");
        }
    };

    // --- WireShark-style Display Filter Engine ---
    const evaluateFilter = (pkt) => {
        if (!displayFilter.trim()) return true;

        try {
            const query = displayFilter.toLowerCase().trim();

            // Basic Protocol matching: e.g. "tcp", "http", "tls"
            if (['tcp', 'udp', 'http', 'tls', 'dns', 'icmp', 'ftp'].includes(query)) {
                return pkt.highest_layer.toLowerCase() === query || !!pkt.layers[query];
            }

            // Simple property search (e.g. an exact IP or port)
            if (!query.includes('==') && !query.includes('!=')) {
                return JSON.stringify(pkt).toLowerCase().includes(query);
            }

            // Syntax matching: tcp.port == 80, ip.src == 192.168.1.1
            const parts = query.split(/(\s*==\s*|\s*!=\s*)/);
            if (parts.length === 3) {
                const [targetPath, op, valueRaw] = parts;
                const fieldPath = targetPath.trim();
                const opTrimmed = op.trim();
                const val = valueRaw.trim();

                // Walk the packet dict: ip.src -> pkt.layers.ip.src
                const keys = fieldPath.split('.');
                let current = pkt.layers;
                for (let k of keys) {
                    if (current === undefined || current === null) break;
                    current = current[k];
                }

                if (current === undefined || current === null) return false;

                const fieldStr = String(current).toLowerCase();
                if (opTrimmed === '==') return fieldStr === val;
                if (opTrimmed === '!=') return fieldStr !== val;
            }

            return false; // Valid syntax but no match
        } catch (e) {
            return true; // If syntax is temporarily broken, just show everything
        }
    };

    // Only validate the filter syntax when the user typing changes, NOT during the render array mapping!
    useEffect(() => {
        if (!displayFilter.trim()) {
            setIsFilterValid(true);
            return;
        }
        try {
            const query = displayFilter.toLowerCase().trim();
            const parts = query.split(/(\s*==\s*|\s*!=\s*)/);
            if (parts.length === 3) {
                // valid syntax
            }
            setIsFilterValid(true);
        } catch (e) {
            setIsFilterValid(false);
        }
    }, [displayFilter]);

    const visiblePackets = livePackets.filter(evaluateFilter);

    return (
        <div className="space-y-6">
            <div className="flex flex-col md:flex-row gap-6">

                {/* Control Panel */}
                <div className="w-full md:w-1/3 bg-white/5 backdrop-blur-md rounded-2xl border border-white/10 p-6 flex flex-col justify-between">
                    <div>
                        <div className="flex items-center gap-3 mb-6">
                            <Radio className={`w-6 h-6 ${isSniffing ? 'text-green-400 animate-pulse' : 'text-blue-400'}`} />
                            <h2 className="text-xl font-bold text-white">Live Capture</h2>
                        </div>

                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-white/70 mb-2">Network Interface</label>
                                <select
                                    value={selectedInterface}
                                    onChange={(e) => setSelectedInterface(e.target.value)}
                                    disabled={isSniffing}
                                    className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 transition-all appearance-none"
                                >
                                    {interfaces.map(iface => (
                                        <option key={iface.name} value={iface.name}>
                                            {iface.name} ({iface.addresses.join(', ')})
                                        </option>
                                    ))}
                                </select>
                            </div>
                        </div>
                    </div>

                    <div className="pt-8">
                        {!isSniffing ? (
                            <button
                                onClick={startSniffing}
                                disabled={!selectedInterface}
                                className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white font-semibold py-3 px-6 rounded-xl transition-colors shadow-lg shadow-blue-500/20"
                            >
                                <Play className="w-5 h-5 fill-current" /> Initialize Sniffer
                            </button>
                        ) : (
                            <button
                                onClick={stopSniffing}
                                className="w-full flex items-center justify-center gap-2 bg-red-500/20 hover:bg-red-500/30 text-red-500 border border-red-500/50 font-semibold py-3 px-6 rounded-xl transition-colors"
                            >
                                <Square className="w-5 h-5 fill-current" /> Stop Capture
                            </button>
                        )}
                    </div>
                </div>

                {/* Real-time Threat Gauge */}
                <div className="w-full md:w-2/3 bg-white/5 backdrop-blur-md rounded-2xl border border-white/10 p-6 flex items-center justify-center relative overflow-hidden">
                    {/* Background glows */}
                    <div className={`absolute -bottom-20 -right-20 w-64 h-64 rounded-full blur-3xl opacity-20 transition-colors duration-1000 ${isSniffing ? (liveRiskScore > 50 ? 'bg-red-500' : 'bg-green-500') : 'bg-blue-500'}`}></div>

                    <div className="text-center z-10 w-full flex flex-col items-center">
                        <h3 className="text-lg font-medium text-white/80 mb-6">Real-Time Baseline Anomaly Score</h3>

                        <div className="relative w-48 h-48 flex items-center justify-center">
                            {/* SVG Static Circle */}
                            <svg className="absolute w-full h-full transform -rotate-90">
                                <circle cx="96" cy="96" r="88" stroke="currentColor" strokeWidth="12" fill="transparent" className="text-white/5" />

                                {/* Animated active circle */}
                                <motion.circle
                                    cx="96" cy="96" r="88"
                                    stroke="currentColor"
                                    strokeWidth="12"
                                    fill="transparent"
                                    className={`${liveRiskScore > 50 ? 'text-red-500' : liveRiskScore > 20 ? 'text-yellow-500' : 'text-green-500'}`}
                                    strokeDasharray="552.92" // 2 * pi * 88
                                    initial={{ strokeDashoffset: 552.92 }}
                                    animate={{ strokeDashoffset: 552.92 - ((liveRiskScore / 100) * 552.92) }}
                                    transition={{ duration: 0.5, ease: "easeOut" }}
                                />
                            </svg>

                            <div className="flex flex-col items-center">
                                <span className={`text-5xl font-bold tabular-nums ${liveRiskScore > 50 ? 'text-red-500' : 'text-white'}`}>
                                    {Math.round(liveRiskScore)}
                                </span>
                                <span className="text-xs font-semibold uppercase tracking-wider text-white/50 mt-1">out of 100</span>
                            </div>
                        </div>

                        {liveRiskScore > 75 && (
                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="mt-6 flex items-center gap-2 text-red-400 bg-red-400/10 px-4 py-2 rounded-lg border border-red-400/20"
                            >
                                <AlertTriangle className="w-5 h-5" />
                                <span className="text-sm font-medium">Critical anomalies detected in live traffic</span>
                            </motion.div>
                        )}
                        {!isSniffing && liveRiskScore === 0 && (
                            <div className="mt-6 text-sm text-white/40 flex items-center gap-2">
                                <Activity className="w-4 h-4" /> Waiting for capture to begin...
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Wireshark-Style Split Pane */}
            <div className="bg-[#1A1D24] rounded-2xl border border-white/10 overflow-hidden shadow-2xl flex flex-col h-[700px]">

                {/* Header Bar & Display Filter */}
                <div className="bg-white/5 border-b border-white/10 px-4 py-3 z-20 space-y-3">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <span className="text-sm font-semibold text-white">Live Packet Inspection</span>
                            {!autoScroll && (
                                <button
                                    onClick={() => setAutoScroll(true)}
                                    className="text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 px-3 py-1 rounded hover:bg-blue-500/30 transition-colors"
                                >
                                    Resume Auto-Scroll
                                </button>
                            )}
                        </div>
                        <div className="flex items-center gap-4">
                            <button
                                onClick={exportCapture}
                                disabled={!selectedInterface}
                                className="flex items-center gap-2 text-xs bg-white/5 hover:bg-white/10 text-white/70 border border-white/10 px-3 py-1 rounded mb-0 disabled:opacity-50 transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                                Download PCAP
                            </button>
                            {isSniffing && (
                                <div className="flex items-center gap-2 text-xs font-mono text-green-400">
                                    <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
                                    CAPTURING
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Filter Input Bar */}
                    <div className="relative flex items-center w-full shadow-inner">
                        <div className={`absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none ${isFilterValid ? 'text-blue-500' : 'text-red-500'}`}>
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fillRule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clipRule="evenodd" />
                            </svg>
                        </div>
                        <input
                            type="text"
                            value={displayFilter}
                            onChange={(e) => {
                                setDisplayFilter(e.target.value);
                                setIsFilterValid(true);
                            }}
                            placeholder="Apply a display filter ... e.g.   tcp.port == 80   or   ip.src == 192.168.1.5   or   http"
                            className={`w-full bg-[#0D1117] border ${isFilterValid ? (displayFilter ? 'border-green-500/50 bg-[#0D1117]/80' : 'border-white/10') : 'border-red-500/50 bg-red-500/5'} rounded-md py-1.5 pl-10 pr-10 text-sm font-mono text-white placeholder-white/30 focus:outline-none focus:ring-1 ${isFilterValid ? 'focus:ring-blue-500' : 'focus:ring-red-500'} transition-colors`}
                        />
                        {displayFilter && (
                            <button
                                onClick={() => setDisplayFilter('')}
                                className="absolute inset-y-0 right-0 pr-3 flex items-center text-white/50 hover:text-white"
                            >
                                ×
                            </button>
                        )}
                    </div>
                </div>

                {/* Packet List (Table) - Top Pane */}
                <div
                    className="flex-1 overflow-y-auto custom-scrollbar border-b border-white/10"
                    ref={tableContainerRef}
                    onWheel={() => setAutoScroll(false)} // User scrolls manually -> disable autoscroll
                >
                    <table className="w-full text-left border-collapse text-xs font-mono whitespace-nowrap">
                        <thead className="sticky top-0 bg-[#0D1117] border-b border-white/10 z-10 text-gray-400 shadow-md">
                            <tr>
                                <th className="px-3 py-2 font-medium w-16">No.</th>
                                <th className="px-3 py-2 font-medium w-32">Time</th>
                                <th className="px-3 py-2 font-medium w-40">Source</th>
                                <th className="px-3 py-2 font-medium w-40">Destination</th>
                                <th className="px-3 py-2 font-medium w-24">Protocol</th>
                                <th className="px-3 py-2 font-medium w-20">Length</th>
                                <th className="px-3 py-2 font-medium">Info</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5 cursor-default">
                            {visiblePackets.length === 0 && (
                                <tr>
                                    <td colSpan="7" className="text-center py-12 text-white/30">
                                        {isSniffing ? 'Waiting for packets... (or Filter blocked all)' : 'No packets captured yet. Initialize Sniffer.'}
                                    </td>
                                </tr>
                            )}
                            {visiblePackets.map((pkt) => {
                                // Determine Row Styling based on protocol
                                let rowClass = "hover:bg-white/10 transition-colors ";
                                const proto = pkt.highest_layer || 'UNKNOWN';
                                if (selectedPacket?.id === pkt.id) {
                                    rowClass = "bg-blue-600/40 text-white font-medium";
                                } else {
                                    if (proto === 'TCP') rowClass += 'bg-[#2D3748]/30 text-blue-200';
                                    else if (proto === 'UDP') rowClass += 'bg-[#44337A]/30 text-purple-200';
                                    else if (proto === 'DNS') rowClass += 'bg-[#744210]/30 text-yellow-200';
                                    else if (proto === 'HTTP') rowClass += 'bg-[#22543D]/30 text-green-200';
                                    else if (proto === 'TLS') rowClass += 'bg-[#4A5568]/30 text-gray-200';
                                    else if (proto === 'ICMP') rowClass += 'bg-[#7B341E]/30 text-red-200';
                                    else rowClass += 'text-white/70';
                                }

                                // Synthesize "Info" column
                                let info = `${proto} Payload`;
                                if (pkt.layers?.http?.request_method) {
                                    info = `${pkt.layers.http.request_method} ${pkt.layers.http.request_uri || '/'} - ${pkt.layers.http.host || ''}`;
                                } else if (pkt.layers?.dns?.qry_name) {
                                    info = `Standard query ${pkt.layers.dns.qry_name}`;
                                } else if (pkt.layers?.tls?.sni) {
                                    info = `Client Hello, SNI: ${pkt.layers.tls.sni}`;
                                } else if (pkt.layers?.tcp) {
                                    info = `${pkt.layers.tcp.srcport || '*'} → ${pkt.layers.tcp.dstport || '*'} [TCP Segment]`;
                                } else if (pkt.layers?.udp) {
                                    info = `${pkt.layers.udp.srcport || '*'} → ${pkt.layers.udp.dstport || '*'} [UDP]`;
                                } else if (proto === 'ARP' && pkt.layers?.arp) {
                                    const arp = pkt.layers.arp;
                                    if (arp.opcode === '1') info = `Who has ${arp.dst_ip}? Tell ${arp.src_ip}`;
                                    else if (arp.opcode === '2') info = `${arp.src_ip} is at ${arp.src_mac}`;
                                    else info = `ARP (Opcode ${arp.opcode})`;
                                }

                                let timeStr = '';
                                try {
                                    const rawTs = pkt.timestamp || pkt.sniff_time;
                                    if (rawTs && rawTs !== "Unknown Time") {
                                        timeStr = new Date(rawTs).toISOString().split('T')[1].replace('Z', '');
                                    } else {
                                        timeStr = String(rawTs || "Unknown");
                                    }
                                } catch (e) {
                                    timeStr = String(pkt.timestamp || "Unknown");
                                }

                                return (
                                    <tr
                                        key={pkt.id}
                                        className={rowClass}
                                        onClick={() => {
                                            setSelectedPacket(pkt);
                                            setAutoScroll(false);
                                        }}
                                    >
                                        <td className="px-3 py-1 opacity-70">{pkt.id}</td>
                                        <td className="px-3 py-1 opacity-80">{timeStr}</td>
                                        <td className="px-3 py-1">{proto === 'ARP' ? (pkt.layers?.arp?.src_mac || 'N/A') : (pkt.layers?.ip?.src || pkt.layers?.eth?.src || 'N/A')}</td>
                                        <td className="px-3 py-1 text-white/80 italic">{proto === 'ARP' ? (pkt.layers?.arp?.dst_mac === '00:00:00:00:00:00' ? 'Broadcast' : pkt.layers?.arp?.dst_mac || 'Broadcast') : (pkt.layers?.ip?.dst || pkt.layers?.eth?.dst || 'N/A')}</td>
                                        <td className="px-3 py-1 font-semibold">{proto}</td>
                                        <td className="px-3 py-1 opacity-80">{pkt.length}</td>
                                        <td className="px-3 py-1 truncate max-w-xs">{info}</td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>

                {/* Packet Details - Bottom Pane */}
                <div className="h-[200px] bg-[#0A0D14] overflow-y-auto custom-scrollbar p-4 text-sm font-mono text-white/80">
                    {selectedPacket ? (
                        <div className="space-y-2">
                            <div className="font-semibold text-white mb-3">Frame {selectedPacket.id}: {selectedPacket.length} bytes on wire ({selectedPacket.length * 8} bits)</div>

                            {/* Render extracted layers dynamically */}
                            {Object.entries(selectedPacket.layers || {}).map(([layerName, layerData], i) => (
                                <details key={i} className="mb-1 group" open>
                                    <summary className="cursor-pointer hover:bg-white/5 py-1 px-2 rounded -mx-2 select-none flex items-center">
                                        <span className="w-4 h-4 inline-flex items-center justify-center mr-1 text-white/40 group-open:rotate-90 transition-transform">▸</span>
                                        <span className="font-semibold uppercase text-blue-300">{layerName} Layer</span>
                                    </summary>
                                    <div className="pl-6 border-l border-white/10 ml-[7px] py-1 mt-1 flex flex-col gap-1">
                                        {Object.entries(layerData || {}).map(([k, v]) => (
                                            <div key={k} className="flex">
                                                <span className="text-white/50 w-32">{k}:</span>
                                                <span className={`${k === 'src' || k === 'dst' || k.includes('port') ? 'text-green-300' : 'text-yellow-200'} break-all`}>
                                                    {String(v)}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </details>
                            ))}
                        </div>
                    ) : (
                        <div className="flex h-full items-center justify-center text-white/30 italic">
                            Select a packet from the list above to view details
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

const LiveSniffer = () => (
    <ErrorBoundary>
        <LiveSnifferContent />
    </ErrorBoundary>
);

export default LiveSniffer;

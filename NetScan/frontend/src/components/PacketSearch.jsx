import React, { useState, useMemo } from 'react';
import { Search, Filter, Server, Link, TerminalSquare } from 'lucide-react';

const PacketSearch = ({ packets }) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [filterProtocol, setFilterProtocol] = useState('ALL');

    // Memoize the filtered list so we don't recalculate 100,000 raw packets on every tiny keystroke
    const filteredPackets = useMemo(() => {
        if (!packets || !packets.length) return [];

        return packets.filter((pkt) => {
            const term = searchTerm.toLowerCase();
            const protoMatch = filterProtocol === 'ALL' || pkt.highest_layer === filterProtocol;

            // Deep search across standard nested layer dicts representing the raw packet
            const stringifiedPacket = JSON.stringify(pkt).toLowerCase();
            const searchMatch = !term || stringifiedPacket.includes(term);

            return protoMatch && searchMatch;
        }).slice(0, 100); // Cap display to top 100 for performance
    }, [packets, searchTerm, filterProtocol]);

    // Extract all unique protocols from the dataset for the filter dropdown
    const availableProtocols = useMemo(() => {
        if (!packets) return [];
        const protos = new Set(packets.map(p => p.highest_layer));
        return ['ALL', ...Array.from(protos).sort()];
    }, [packets]);

    if (!packets || packets.length === 0) {
        return <div className="p-8 text-center text-white/50 bg-black/20 rounded-xl">No raw packet data available for this analysis.</div>;
    }

    return (
        <div className="space-y-4">
            {/* Search and Filter Controls */}
            <div className="flex flex-col md:flex-row gap-4 bg-white/5 p-4 rounded-2xl border border-white/10">
                <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40 w-5 h-5" />
                    <input
                        type="text"
                        placeholder="Search IP, Port, URI, User-Agent..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white placeholder-white/30 focus:outline-none focus:ring-2 focus:ring-accent/50 transition-all font-mono"
                    />
                </div>

                <div className="relative min-w-[200px]">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40 w-5 h-5" />
                    <select
                        value={filterProtocol}
                        onChange={(e) => setFilterProtocol(e.target.value)}
                        className="w-full bg-black/40 border border-white/10 rounded-xl py-3 pl-10 pr-4 text-white appearance-none focus:outline-none focus:ring-2 focus:ring-accent/50 transition-all"
                    >
                        {availableProtocols.map(proto => (
                            <option key={proto} value={proto} className="bg-slate-900">{proto}</option>
                        ))}
                    </select>
                </div>
            </div>

            <div className="text-sm text-white/50 px-2 flex justify-between">
                <span>Total Packets: {packets.length.toLocaleString()}</span>
                <span>Showing Top: {filteredPackets.length}</span>
            </div>

            {/* Packet Table */}
            <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr className="bg-black/40 text-white/60 text-xs uppercase tracking-wider font-semibold border-b border-white/10">
                                <th className="p-4 font-medium">Timestamp</th>
                                <th className="p-4 font-medium">Protocol</th>
                                <th className="p-4 font-medium">Size</th>
                                <th className="p-4 font-medium w-1/2">Key Telemetry (IP/Port/URI)</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {filteredPackets.map((pkt, idx) => {
                                // Extract standard display fields if available
                                const ipLayer = pkt.layers?.ip;
                                const tcpLayer = pkt.layers?.tcp;
                                const udpLayer = pkt.layers?.udp;
                                const httpLayer = pkt.layers?.http;
                                const dnsLayer = pkt.layers?.dns;

                                return (
                                    <tr key={idx} className="hover:bg-white/5 transition-colors group">
                                        <td className="p-4 text-sm font-mono text-white/70 whitespace-nowrap">
                                            {pkt.timestamp !== "Unknown Time" ? new Date(pkt.timestamp).toLocaleTimeString() : "N/A"}
                                        </td>
                                        <td className="p-4">
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-white/10 text-white/90">
                                                {pkt.highest_layer}
                                            </span>
                                        </td>
                                        <td className="p-4 text-sm text-white/60">
                                            {pkt.length} B
                                        </td>
                                        <td className="p-4">
                                            <div className="flex flex-col gap-1 text-sm font-mono text-white/80">
                                                {ipLayer && (
                                                    <div className="flex items-center gap-2 text-xs">
                                                        <Server className="w-3 h-3 text-blue-400" />
                                                        <span>{ipLayer.src} → {ipLayer.dst}</span>
                                                    </div>
                                                )}
                                                {(tcpLayer || udpLayer) && (
                                                    <div className="flex items-center gap-2 text-xs text-white/50">
                                                        <Link className="w-3 h-3 text-purple-400" />
                                                        <span>Port: {(tcpLayer || udpLayer).srcport} → {(tcpLayer || udpLayer).dstport}</span>
                                                    </div>
                                                )}
                                                {httpLayer?.request_uri && (
                                                    <div className="flex items-center gap-2 text-xs text-orange-300 mt-1 bg-black/30 p-1.5 rounded w-fit max-w-[400px] truncate">
                                                        <TerminalSquare className="w-3 h-3 shrink-0" />
                                                        <span className="truncate">{httpLayer.request_uri}</span>
                                                    </div>
                                                )}
                                                {dnsLayer?.qry_name && (
                                                    <div className="flex items-center gap-2 text-xs text-green-300 mt-1 bg-black/30 p-1.5 rounded w-fit">
                                                        <Globe className="w-3 h-3" />
                                                        <span>{dnsLayer.qry_name}</span>
                                                    </div>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>

                    {filteredPackets.length === 0 && (
                        <div className="p-12 text-center text-white/50">
                            No packets match your search filters.
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default PacketSearch;

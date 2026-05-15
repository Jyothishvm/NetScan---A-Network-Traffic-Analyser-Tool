import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';
import { ShieldAlert, Activity, Eye, GlobeLock, Database, AlertCircle, Globe, Network, Search, Clock, Cpu, Key, FileArchive, UserX, DownloadCloud } from 'lucide-react';
import clsx from 'clsx';
import NetworkGraph from './NetworkGraph';
import PacketSearch from './PacketSearch';

const COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6'];

const Dashboard = ({ report }) => {
    const [activeTab, setActiveTab] = useState('overview');

    if (!report || !report.engines) return null;

    const { engines, total_score } = report;

    // Prepare chart data
    const threatDistribution = [
        { name: 'DNS', value: engines.dns.score },
        { name: 'C2', value: engines.c2.score },
        { name: 'TLS', value: engines.tls.score },
        { name: 'Exfil', value: engines.exfil.score },
        { name: 'Lateral', value: engines.lateral.score },
        { name: 'HTTP', value: engines.http.score },
        { name: 'ICMP', value: engines.icmp.score },
        { name: 'Scan', value: engines.port_scan.score },
    ].filter(item => item.value > 0);

    const getRiskColor = (score) => {
        if (score >= 70) return 'text-danger shadow-danger/20';
        if (score >= 40) return 'text-warning shadow-warning/20';
        return 'text-accent shadow-accent/20';
    };

    const getSeverityBadge = (severity) => {
        const colors = {
            Critical: 'bg-danger/20 text-danger border-danger/30',
            High: 'bg-orange-500/20 text-orange-500 border-orange-500/30',
            Medium: 'bg-warning/20 text-warning border-warning/30',
            Low: 'bg-accent/20 text-accent border-accent/30'
        };
        return colors[severity] || colors.Low;
    };

    const tabs = [
        { id: 'overview', label: 'Overview', icon: Activity },
        { id: 'dns', label: 'DNS Analysis', icon: GlobeLock },
        { id: 'c2', label: 'C2 Beacons', icon: ShieldAlert },
        { id: 'tls', label: 'TLS Inspection', icon: Eye },
        { id: 'exfil', label: 'Data Exfil', icon: Database },
        { id: 'lateral', label: 'Lateral Movement', icon: Activity },
        { id: 'http', label: 'HTTP / Web Attacks', icon: Globe },
        { id: 'icmp', label: 'ICMP Exfil', icon: Network },
        { id: 'port_scan', label: 'Port Scans', icon: Search },
        { id: 'timeline', label: 'Attack Timeline', icon: Clock },
        { id: 'behavior', label: 'Behavior Profiler', icon: Cpu },
        { id: 'graph', label: 'Network Graph (DFIR)', icon: Network },
        { id: 'packets', label: 'Packet Explorer', icon: Database },
        { id: 'credentials', label: 'Credentials', icon: Key },
        { id: 'carved_files', label: 'Carved Files', icon: FileArchive },
        { id: 'vpn_tor', label: 'Anonymized Networks', icon: UserX },
        { id: 'osint', label: 'OSINT & YARA', icon: ShieldAlert },
    ];

    const renderTable = (engineName) => {
        let data = [];
        if (engineName === 'carved_files') {
            data = report.carved_files || [];
        } else {
            data = engines[engineName]?.findings || [];
        }

        if (!data || data.length === 0) {
            return (
                <div className="flex flex-col items-center justify-center p-12 text-slate-500 glass rounded-2xl">
                    <CheckCircle size={48} className="text-accent/50 mb-4" />
                    <h3 className="text-xl font-medium">No Threats Detected</h3>
                    <p>This engine found no suspicious activity.</p>
                </div>
            );
        }

        // Safely extract keys for table headers, avoiding functions or complex objects
        const columns = Object.keys(data[0]).filter(k => typeof data[0][k] !== 'object');

        return (
            <div className="w-full overflow-x-auto glass rounded-2xl border border-white/5 shadow-2xl">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-white/5 border-b border-white/10">
                            {columns.map(col => (
                                <th key={col} className="p-4 uppercase text-xs font-semibold text-slate-400 tracking-wider">
                                    {col}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {data.map((row, idx) => (
                            <tr key={idx} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                                {columns.map(col => (
                                    <td key={col} className="p-4 text-sm text-slate-300">
                                        {col === 'severity' ? (
                                            <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityBadge(row[col])}`}>
                                                {String(row[col])}
                                            </span>
                                        ) : (
                                            // Ensure everything renders as a string to avoid React 'object' child bugs
                                            String(row[col] || 'N/A')
                                        )}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    return (
        <div className="space-y-6">

            {/* Overview Headings */}
            <div className="flex flex-col md:flex-row gap-6">

                {/* Total Risk Score Card */}
                <div className="glass rounded-3xl p-8 flex-1 flex flex-col items-center justify-center relative overflow-hidden group">
                    <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent z-0 pointer-events-none" />
                    <h3 className="text-slate-400 font-medium mb-4 z-10 w-full flex justify-between items-center px-4">
                        <span>Overall Network Risk</span>
                        <a
                            href={`http://localhost:8000/report/${report.case_id}/download`}
                            download
                            className="flex items-center gap-2 bg-blue-500/20 hover:bg-blue-500/40 text-blue-400 text-xs px-3 py-1.5 rounded-lg border border-blue-500/30 transition-all font-semibold"
                        >
                            <DownloadCloud size={14} /> Output PDF Summary
                        </a>
                    </h3>
                    <div className={clsx("text-7xl font-bold z-10 drop-shadow-2xl transition-all", getRiskColor(total_score))}>
                        {total_score}
                    </div>
                    <p className="mt-4 text-sm text-slate-500 z-10">Calculated across 5 Threat Engines</p>
                </div>

                {/* Primary Victim Card */}
                {engines.victim?.most_compromised_host !== "None" && (
                    <div className="glass rounded-3xl p-8 flex-1 relative border-danger/20 border">
                        <div className="absolute top-4 right-4 text-danger animate-pulse">
                            <AlertCircle size={24} />
                        </div>
                        <h3 className="text-slate-400 font-medium mb-2">Most Compromised Host</h3>
                        <div className="text-3xl font-mono text-white mb-4">
                            {engines.victim.most_compromised_host}
                        </div>
                        <div className="text-sm text-danger bg-danger/10 p-3 rounded-lg border border-danger/20 inline-block">
                            Immediate isolation recommended.
                        </div>
                    </div>
                )}

            </div>

            {/* Tabs */}
            <div className="flex overflow-x-auto hide-scrollbar gap-2 p-1 bg-white/5 rounded-2xl backdrop-blur-md border border-white/10">
                {tabs.map(tab => {
                    const Icon = tab.icon;
                    const isActive = activeTab === tab.id;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={clsx(
                                "flex items-center gap-2 px-6 py-3 rounded-xl font-medium transition-all shrink-0",
                                isActive
                                    ? "bg-primary text-white shadow-lg shadow-primary/25"
                                    : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                            )}
                        >
                            <Icon size={18} />
                            {tab.label}
                            {tab.id !== 'overview' && engines[tab.id]?.findings?.length > 0 && (
                                <div className="w-2 h-2 rounded-full bg-danger animate-pulse ml-2" />
                            )}
                        </button>
                    )
                })}
            </div>

            {/* Tab Content */}
            <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className="min-h-[400px]"
            >
                {activeTab === 'overview' ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                        <div className="glass rounded-3xl p-6 h-80 flex flex-col">
                            <h3 className="text-lg font-semibold mb-4 text-white">Threat Distribution (Risk Source)</h3>
                            {threatDistribution.length > 0 ? (
                                <div className="flex-1 min-h-0">
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie
                                                data={threatDistribution}
                                                cx="50%"
                                                cy="50%"
                                                innerRadius={60}
                                                outerRadius={100}
                                                paddingAngle={5}
                                                dataKey="value"
                                                stroke="none"
                                            >
                                                {threatDistribution.map((entry, index) => (
                                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                                ))}
                                            </Pie>
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px' }}
                                                itemStyle={{ color: '#f8fafc' }}
                                            />
                                        </PieChart>
                                    </ResponsiveContainer>
                                </div>
                            ) : (
                                <div className="flex-1 flex items-center justify-center text-slate-500">No score data to visualize</div>
                            )}
                        </div>

                        <div className="glass rounded-3xl p-6 h-80 flex flex-col">
                            <h3 className="text-lg font-semibold mb-4 text-white">Engine Scores</h3>
                            <div className="flex-1 min-h-0">
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart data={threatDistribution} layout="vertical" margin={{ left: 10, right: 10 }}>
                                        <XAxis type="number" hide />
                                        <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#94a3b8' }} width={60} />
                                        <Tooltip
                                            cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                                            contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px' }}
                                        />
                                        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                            {threatDistribution.map((entry, index) => (
                                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                        </div>

                    </div>
                ) : activeTab === 'behavior' ? (
                    <div className="space-y-4">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-xl font-semibold opacity-90 text-[#3b82f6]">MITRE ATT&CK Mapping</h2>
                            <span className="bg-[#3b82f6]/20 text-[#3b82f6] px-3 py-1 rounded-full text-sm">Killchain Score: {engines.behavior?.killchain_score || 0}%</span>
                        </div>
                        <div className="grid grid-cols-1 gap-4">
                            {engines.behavior?.matrix && Object.entries(engines.behavior.matrix).map(([stage, events]) => (
                                <div key={stage} className="bg-white/5 p-4 rounded-xl border border-white/5">
                                    <h3 className="text-lg font-medium text-white/90 mb-2">{stage}</h3>
                                    <ul className="list-disc pl-5 space-y-1">
                                        {events.map((e, i) => (
                                            <li key={i} className="text-sm text-white/70">{e.type}: {e.description}</li>
                                        ))}
                                    </ul>
                                </div>
                            ))}
                        </div>
                    </div>
                ) : activeTab === 'timeline' ? (
                    <div className="space-y-4 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-white/20 before:to-transparent">
                        {engines.timeline && engines.timeline.map((event, index) => (
                            <div key={index} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active text-white">
                                <div className="flex items-center justify-center w-10 h-10 rounded-full border border-white/20 bg-gray-900 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 text-xs font-bold font-mono">
                                    {event.category.substring(0, 3)}
                                </div>
                                <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-white/5 border border-white/10 p-4 rounded-xl shadow">
                                    <div className="flex items-center justify-between mb-1">
                                        <div className="font-bold text-white/90">{event.type}</div>
                                        <time className="font-mono text-xs font-medium text-white/50">{event.time !== "Unknown Time" ? new Date(event.time).toLocaleTimeString() : "N/A"}</time>
                                    </div>
                                    <div className="text-white/70 text-sm">{event.description}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    renderTable(activeTab)
                )}
            </motion.div>
        </div>
    );
};

// Simple stand-in icon for empty state if CheckCircle isn't available at the top scope
const CheckCircle = ({ size, className }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
        <polyline points="22 4 12 14.01 9 11.01"></polyline>
    </svg>
)

export default Dashboard;

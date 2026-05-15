import React, { useState } from 'react';
import axios from 'axios';
import { UploadCloud, Shield, AlertTriangle, FileText, CheckCircle, Loader } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import Dashboard from './components/Dashboard';
import LiveSniffer from './components/LiveSniffer';

const api = axios.create({ baseURL: 'http://localhost:8000' });

function App() {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [showLiveSniffer, setShowLiveSniffer] = useState(false);
  const [packetProgress, setPacketProgress] = useState({ current: 0, total: 0 });
  const [progressPercent, setProgressPercent] = useState(0);
  const [phase, setPhase] = useState("parsing_pcap");

  const handleDrop = (e) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile?.name.endsWith('.pcap') || droppedFile?.name.endsWith('.pcapng')) {
      setFile(droppedFile);
      setError('');
    } else {
      setError('Please upload a valid .pcap or .pcapng file');
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setError('');
    setProgressPercent(0);
    setPacketProgress({ current: 0, total: 0 });
    setPhase("parsing_pcap");

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post('/upload', formData);

      if (response.data.status === 'processing') {
        const case_id = response.data.case_id;

        // Start polling for status
        const pollInterval = setInterval(async () => {
          try {
            const statusRes = await api.get(`/status/${case_id}`);

            if (statusRes.data.status === 'completed') {
              clearInterval(pollInterval);
              // Fetch final report
              const reportData = await api.get(`/report/${case_id}`);
              setReport(reportData.data);
              setIsUploading(false);
            } else if (statusRes.data.status === 'error') {
              clearInterval(pollInterval);
              setPhase('error');
              setError('Analysis failed on server during background processing.');
              setIsUploading(false);
            } else if (statusRes.data.status === 'processing' && statusRes.data.progress) {
              const { current_packet, total_packets, phase } = statusRes.data.progress;
              setPhase(phase);

              if (phase === "initializing_parser") {
                setProgressPercent(0);
                setPacketProgress({ current: 0, total: 0 });
              } else if (phase === "parsing_pcap" && total_packets > 0) {
                const percent = Math.round((current_packet / total_packets) * 100);
                setProgressPercent(Math.min(99, Math.max(0, percent))); // cap at 99 until truly done
                setPacketProgress({ current: current_packet, total: total_packets });
              } else {
                setPacketProgress({ current: 0, total: 0 });
              }
            }
          } catch (pollErr) {
            console.error("Polling error:", pollErr);
            clearInterval(pollInterval); // Stop polling on error
            setError('Error during analysis polling.');
            setIsUploading(false);
          }
        }, 1000);
      } else {
        setError('Unexpected upload response');
        setIsUploading(false);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'An error occurred during analysis');
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-darker text-slate-200">
      {/* Navbar */}
      <nav className="border-b border-white/5 bg-dark/50 backdrop-blur-xl sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-primary/20 p-2 rounded-lg text-primary">
              <Shield size={24} />
            </div>
            <span className="text-xl font-bold tracking-wider text-white">NetScan</span>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => { setShowLiveSniffer(!showLiveSniffer); setReport(null); setFile(null); }}
              className={`text-sm px-4 py-2 rounded-lg transition-colors border ${showLiveSniffer ? 'bg-primary border-primary text-white' : 'border-white/10 text-slate-400 hover:text-white hover:border-white/30'}`}
            >
              {showLiveSniffer ? "Switch to Upload Mode" : "Live Network Sniff"}
            </button>
            {report && !showLiveSniffer && (
              <button
                onClick={() => { setReport(null); setFile(null); }}
                className="text-sm text-slate-400 hover:text-white transition-colors"
              >
                New PCAP
              </button>
            )}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <AnimatePresence mode="wait">
          {showLiveSniffer ? (
            <motion.div
              key="livesniffer"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
            >
              <LiveSniffer />
            </motion.div>
          ) : !report ? (
            <motion.div
              key="uploader"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-2xl mx-auto mt-20"
            >
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDrop}
                className="glass rounded-3xl p-12 text-center border-dashed border-2 border-white/10 hover:border-primary/50 transition-all duration-300 group"
              >
                <div className="bg-white/5 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:scale-110 group-hover:bg-primary/20 transition-all">
                  <UploadCloud size={32} className="text-primary" />
                </div>
                <h2 className="text-2xl font-semibold mb-2 text-white">Upload PCAP for Analysis</h2>
                <p className="text-slate-400 mb-8">Drag and drop your network capture file here</p>

                <input
                  type="file"
                  id="file-input"
                  className="hidden"
                  accept=".pcap,.pcapng"
                  onChange={(e) => {
                    setFile(e.target.files[0]);
                    setError('');
                  }}
                />
                <label
                  htmlFor="file-input"
                  className="cursor-pointer bg-primary hover:bg-primary/90 text-white px-6 py-3 rounded-full font-medium transition-colors shadow-lg shadow-primary/25"
                >
                  Browse Files
                </label>

                {file && (
                  <div className="mt-8 flex items-center justify-between bg-dark p-4 rounded-xl border border-white/5">
                    <div className="flex items-center gap-3">
                      <FileText className="text-primary" size={20} />
                      <span className="text-sm font-medium">{file.name}</span>
                    </div>
                    <CheckCircle className="text-accent" size={20} />
                  </div>
                )}

                {error && (
                  <div className="mt-4 flex items-center justify-center gap-2 text-danger text-sm bg-danger/10 p-3 rounded-lg">
                    <AlertTriangle size={16} />
                    {error}
                  </div>
                )}
              </div>

              {file && (
                <motion.button
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  onClick={handleUpload}
                  disabled={isUploading}
                  className="w-full mt-6 bg-white text-darker font-bold py-4 rounded-xl flex items-center justify-center gap-2 hover:bg-slate-200 transition-colors disabled:opacity-50"
                >
                  {isUploading ? (
                    <>
                      <Loader className="animate-spin" size={20} />
                      <div className="flex flex-col items-start text-left">
                        <span className="font-semibold text-sm">
                          {phase === "initializing_parser" ? "Booting Security Engines..." :
                            phase === "parsing_pcap" ? `Analyzing PCAP... ${progressPercent}%` :
                              phase === "carving_files" ? "Carving Packet Artifacts..." :
                                phase === "running_detectors" ? "Running Threat Detection Engines..." :
                                  "Generating PDF Report..."}
                        </span>
                        {packetProgress.total > 0 && phase === "parsing_pcap" && (
                          <span className="text-xs text-slate-400">{packetProgress.current.toLocaleString()} / {packetProgress.total.toLocaleString()} packets processed</span>
                        )}
                      </div>
                    </>
                  ) : (
                    "Start Deep Scan"
                  )}
                </motion.button>
              )}
            </motion.div>
          ) : (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <Dashboard report={report} />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

export default App;

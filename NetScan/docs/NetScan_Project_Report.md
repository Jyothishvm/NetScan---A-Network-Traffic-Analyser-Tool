# PROJECT REPORT: NETSCAN

## INDEX

1. INTRODUCTION
2. PURPOSE OF THE PROJECT
3. SYSTEM OVERVIEW / TECHNOLOGY SOLUTION
4. NATURAL LANGUAGE PROCESSING (NLP)
5. NLP AND MACHINE LEARNING IN THE SYSTEM
6. SYSTEM ARCHITECTURE AND MODULE BREAKDOWN
7. ALGORITHMS USED
8. METHODOLOGY
9. WORKFLOW DIAGRAM
10. CODE
11. OUTPUT
12. EXISTING SYSTEM VS PROPOSED SYSTEM
13. FUTURE SCOPE
14. CONCLUSION
15. REFERENCES

---

## 1. INTRODUCTION

NetScan is an advanced, comprehensive network forensic and threat detection application designed to provide robust analysis of network traffic. By inspecting packet captures (PCAP files) and monitoring live network interfaces, NetScan identifies suspicious activities, extracts critical forensic artifacts, and generates actionable intelligence. The system aggregates multiple detection heuristics—ranging from Command and Control (C2) beaconing to Domain Name System (DNS) tunneling—and provides security analysts with a clear, interactive visual interface to investigate network compromises.

## 2. PURPOSE OF THE PROJECT

The primary purpose of the NetScan project is to simplify and automate the complex process of network traffic analysis. Security operation centers (SOCs) and forensic analysts are often overwhelmed by the sheer volume of packet data. NetScan aims to:
- **Automate Threat Detection**: Quickly parse through thousands of network packets to identify indicators of compromise (IoCs).
- **Enhance Visibility**: Provide interactive network graphs that map out the relationships and communication patterns between hosts.
- **Generate Actionable Intelligence**: Use automated summarization routines to translate complex heuristic scores into human-readable threat summaries.
- **Provide a Unified Platform**: Integrate both static PCAP file analysis and live network monitoring within a single, standalone application.

## 3. SYSTEM OVERVIEW / TECHNOLOGY SOLUTION

NetScan utilizes a modern, decoupled architecture featuring a performant backend and an interactive frontend, which can be packaged together as a single standalone executable.

- **Frontend (Client Interface)**:
  - Built using **React.js** for building a dynamic, component-based user interface.
  - Styled with **Tailwind CSS** for a responsive and modern aesthetic.
  - Packaged and integrated via **Electron** to run as a cross-platform desktop application.
  - Interactive network visualization powered by specialized React charting libraries (e.g., Force-directed graphs).

- **Backend (Analysis Engine)**:
  - Developed in **Python 3** using the **FastAPI** framework to provide a high-performance RESTful API.
  - Network parsing handled by **PyShark** (a Python wrapper for `tshark`), enabling deep packet inspection.
  - Modular detection engines that can independently identify disparate threat classes (DNS anomalies, TLS irregularities, Data Exfiltration, etc.).
  - Packaged via **PyInstaller** to ensure the desktop app can run without requiring Python to be pre-installed on the host machine.

## 4. NATURAL LANGUAGE PROCESSING (NLP)

Natural Language Processing (NLP) and Natural Language Generation (NLG) techniques are crucial for translating raw telemetry into summaries that analysts can act upon immediately. In NetScan, generation capabilities are leveraged to provide context around numerical risk scores and heuristic flags. Instead of merely presenting an analyst with a grid of alerts, the system synthesizes sentences that explain *what* happened, *why* it is considered suspicious, and *how* to remediate it.

## 5. NLP AND MACHINE LEARNING IN THE SYSTEM

Within the NetScan system, intelligent summarization is driven by the `ai_summarizer.py` component. While currently utilizing an advanced heuristic mapping rather than a heavyweight neural network, it simulates an "AI Analyst" by dynamically generating reports based on the aggregated findings of multiple detection modules.

- **Scoring & Contextualization**: The system calculates a `total_score` and analyzes the distribution of risk across engines like `victim`, `lateral`, `exfil`, and `tls`.
- **Dynamic NLG Generation**: Based on the active threats, the summarizer logically concatenates narrative segments (e.g., "Anomalous TLS fingerprints (JA3 anomalies) were observed...").
- **Recommendation Engine**: It prescribes remediation actions, such as isolating the primary compromised IP if the threat score crosses a critical threshold. This bridges the gap between raw data and machine-assisted incident response.

## 6. SYSTEM ARCHITECTURE AND MODULE BREAKDOWN

The NetScan architecture is primarily divided into API controllers, a core processing engine, and specific detection modules.

**Module Breakdown**:
1. **Frontend UI**: Handles file uploads, view state management, and data visualization.
2. **FastAPI Endpoints** (`api/`): Processes incoming requests, manages asynchronous tasks for live captures, and returns JSON reports.
3. **Core Engine** (`core/`): 
   - `ai_summarizer.py`: Generates intelligence summaries.
   - Pyshark wrapper: Manages the `asyncio` event loops required to parse large captures robustly on Windows.
4. **Detection Modules** (`detectors/`):
   - `c2_detector.py`: Detects beaconing patterns.
   - `dns_detector.py`: Looks for DGA domains or excessive TXT queries.
   - `exfil_detector.py`: Identifies large outbound data spikes.
   - `lateral_detector.py`: Spots internal port sweeping.
   - `tls_detector.py`: Analyzes JA3/JA3S fingerprints.
   - `credential_detector.py`: Discovers cleartext logins.
   - `vpn_tor_detector.py`: Flags traffic to known anonymity networks.
   - `osint_detector.py`: Performs reputation checks against known bad IP lists.

## 7. ALGORITHMS USED

NetScan relies on several key algorithms to identify network anomalies:
- **Heuristic Rule Matching**: Used extensively across the detection modules to match packet behaviors against known signatures (e.g., searching for "password=" in unencrypted payloads).
- **Time-Series Analysis (Beaconing Detection)**: Identifies C2 communications by calculating the delta between connection timestamps and highlighting persistent, uniform intervals indicative of automated beaconing.
- **Graph / Relationship Analysis**: Building edge-node maps from Source IP to Destination IP to visually cluster communication groups and identify compromised central hubs.
- **Statistical Thresholding**: Used in data exfiltration detection to flag outbound byte transfers that exceed standard standard deviation thresholds relative to the network's baseline.

## 8. METHODOLOGY

The analysis methodology follows a structured pipeline:
1. **Data Ingestion**: A standard PCAP file is uploaded, or a live interface is selected.
2. **Packet Parsing**: `pyshark` is invoked to tear apart the layers of the packets, extracting IPs, Ports, Protocols, and payload metadata.
3. **Parallel Processing**: Extracted metadata is routed through all active detection modules simultaneously.
4. **Scoring & Aggregation**: Each module returns an independent risk score and list of findings. These are aggregated by the main application logic.
5. **Summarization**: The `ai_summarizer` reviews the aggregated output and generates a cohesive forensic report.
6. **Visualization**: The REST API serves the JSON payload back to the React frontend, which renders the Threat Intelligence dashboard and Network Graphs.

## 9. WORKFLOW DIAGRAM

```mermaid
graph TD;
    A[User (Frontend UI)] -->|Uploads PCAP| B(FastAPI Endpoint);
    A -->|Starts Live Scan| B;
    B --> C{Core Processing Engine};
    C --> D[PyShark Parser];
    D --> E[Feature Extraction];
    E --> F1[DNS Detector];
    E --> F2[TLS Detector];
    E --> F3[C2 & Exfil Detectors];
    E --> F4[Other Detectors...];
    F1 --> G[Score Aggregation];
    F2 --> G;
    F3 --> G;
    F4 --> G;
    G --> H[AI Summarizer / NLG];
    H --> I[JSON Report Generation];
    I --> A[Frontend Render / Visualization];
```

## 10. CODE

### Core AI Summarizer snippet (`ai_summarizer.py`):
```python
def generate_ai_summary(report_data: dict) -> str:
    total_score = report_data.get("total_score", 0)
    engines = report_data.get("engines", {})
    victim_data = engines.get("victim", {})
    primary_ip = victim_data.get("most_compromised_host", "an unknown host")
    
    active_threats = []
    for key, engine in engines.items():
        if key not in ["victim", "timeline", "behavior", "graph", "osint"]:
            if engine.get("score", 0) > 0:
                active_threats.append(key)
                
    summary_parts = []
    if total_score >= 80:
        summary_parts.append(f"CRITICAL: The analyzed network capture indicates a severe, multi-stage compromise originating from or targeting {primary_ip}.")
    
    return "\n\n".join(summary_parts)
```

### Frontend Network Graph component (`NetworkGraph.jsx`):
```javascript
import React, { useRef, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const NetworkGraph = ({ nodes, links }) => {
  const fgRef = useRef();

  useEffect(() => {
    // Zoom to fit nodes after loading
    if (nodes.length && fgRef.current) {
      fgRef.current.zoomToFit(400, 50);
    }
  }, [nodes]);

  return (
    <div className="w-full h-[500px] border border-gray-700 bg-gray-900 rounded-lg overflow-hidden">
      <ForceGraph2D
        ref={fgRef}
        graphData={{ nodes, links }}
        nodeAutoColorBy="group"
        nodeLabel="id"
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
      />
    </div>
  );
};
export default NetworkGraph;
```

## 11. OUTPUT

The anticipated output of the NetScan system includes:
- **Interactive UI Dashboard**: Displays key metrics, risk scores, and alert lists.
- **Narrative Threat Summary**: Paragraphs generated by the AI Summarizer explaining the network compromise.
- **Visual Node Graph**: An interactive cluster map showing which IP addresses communicated the most and identifying the "victim" nodes.
- **Detailed JSON Reports**: Exportable data containing precise packet findings, timestamps, and flagged heuristics.

## 12. EXISTING SYSTEM VS PROPOSED SYSTEM

| Feature | Existing Systems (e.g., Wireshark, Snort) | Proposed System (NetScan) |
| :--- | :--- | :--- |
| **Data Parsing** | Very detailed packet-by-packet, but requires manual interpretation. | Automates interpretation using multiple heuristic engines. |
| **Ease of Use** | Steep learning curve for analysts requiring complex display filters. | Web-based visual dashboard with narrative summaries. |
| **Architectural Focus** | Typically separated: Wireshark for static PCAP, Snort for live IDS. | Unified platform for both historical and live capture analysis. |
| **Reporting / NLP** | No native natural language explanation of threats. | Generates clear "AI-driven" summaries of network compromises. |

## 13. FUTURE SCOPE

Future enhancements to NetScan will focus on:
- **True AI / Deep Learning**: Replacing heuristic rules with trained anomaly-detection models (Autoencoders, Isolation Forests) for entirely unknown zero-day threats.
- **Real-Time Remediation**: Active integration with firewalls and routers to automatically block malicious IP addresses.
- **Extended Protocol Parsing**: Adding deep inspection capabilities for industrial protocols (SCADA/ICS) or modern encrypted traffic analysis via enhanced fingerprinting.

## 14. CONCLUSION

NetScan represents a modern approach to network forensics. By integrating complex packet parsing capabilities (via PyShark) with an intelligent, heuristic-driven backend and a visually rich React frontend, it empowers security analysts to rapidly respond to incidents. The automatic summarization features drastically lower the cognitive load required to understand a network compromise, bridging the gap between raw data collection and actionable threat intelligence. 

## 15. REFERENCES

1. FastAPI Documentation: https://fastapi.tiangolo.com/
2. React.js Documentation: https://reactjs.org/
3. PyShark Library / tshark: https://github.com/KimiNewt/pyshark
4. Electron Framework: https://www.electronjs.org/
5. Wireshark Network Protocol Analyzer: https://www.wireshark.org/

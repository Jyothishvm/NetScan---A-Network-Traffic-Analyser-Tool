from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
import os
import uuid
import json
import logging
import subprocess
import re
from core.parser import parse_pcap, TSHARK_PATH
from core.report_generator import generate_pdf_report

logger = logging.getLogger(__name__)

# Import all detection engines
from detectors.dns_detector import detect_dns_threats
from detectors.c2_detector import detect_c2_traffic
from detectors.tls_detector import detect_tls_anomalies
from detectors.exfil_detector import detect_exfiltration
from detectors.lateral_detector import detect_lateral_movement
from detectors.http_detector import detect_http_threats
from detectors.icmp_detector import detect_icmp_exfiltration
from detectors.port_scan_detector import detect_port_scans
from detectors.victim_detector import identify_victim
from detectors.credential_detector import detect_credentials
from detectors.vpn_tor_detector import detect_anonymized_traffic
from detectors.osint_detector import run_osint_analysis
from core.timeline_generator import generate_timeline
from core.behavior_profiler import profile_behavior
from core.file_carver import carve_files
from core.graph_generator import generate_graph
from core.ai_summarizer import generate_ai_summary

router = APIRouter()

UPLOAD_DIR = "uploads"
REPORT_DIR = "reports"
CARVED_DIR = "carved_files"

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(CARVED_DIR, exist_ok=True)

# Global progress tracker dictionary
analysis_progress = {}

def update_progress(case_id, current, total, phase):
    analysis_progress[case_id] = {
        "current_packet": current,
        "total_packets": total,
        "phase": phase
    }

@router.post("/upload")
async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Handles PCAP uploads and triggers the analysis pipeline asynchronously."""
    if not file.filename.endswith(("pcap", "pcapng")):
        raise HTTPException(status_code=400, detail="Only PCAP or PCAPNG files are allowed.")
        
    case_id = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f"{case_id}.pcap")
    
    # Save the file in chunks
    with open(filepath, "wb") as f:
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            f.write(chunk)
            
    # Trigger Analysis in a Background Task, allowing immediate response to client
    background_tasks.add_task(run_analysis_sync, filepath, case_id)
    return {"status": "processing", "case_id": case_id}
    
@router.get("/status/{case_id}")
async def get_status(case_id: str):
    """Fetches the live parsing progress of an analysis."""
    if case_id in analysis_progress:
        progress = analysis_progress[case_id]
        if progress["phase"] == "completed":
            return {"status": "completed", "progress": progress}
        elif progress["phase"] == "error":
            return {"status": "error", "progress": progress}
        else:
            return {"status": "processing", "progress": progress}
        
    report_path = os.path.join(REPORT_DIR, f"{case_id}.json")
    if os.path.exists(report_path):
        return {"status": "completed"}
        
    return {"status": "initializing"}
    
def run_analysis_sync(filepath: str, case_id: str):
    """Central orchestration of PyShark parser and detection engines."""
    
    # Intelligently fetch total packet count using ultra-fast Wireshark capinfos
    total_packets = 0
    try:
        capinfos_path = TSHARK_PATH.replace("tshark.exe", "capinfos.exe")
        if not os.path.exists(capinfos_path):
             capinfos_path = "capinfos"
        out = subprocess.check_output([capinfos_path, "-c", filepath], stderr=subprocess.STDOUT).decode()
        out_clean = out.replace(",", "")
        match = re.search(r"Number of packets:\s+([\d\.]+)\s*([kKmM]?)", out_clean)
        if match:
            num = float(match.group(1))
            suffix = match.group(2).lower()
            if suffix == 'k': num *= 1000
            elif suffix == 'm': num *= 1000000
            total_packets = int(num)
    except Exception as e:
        logger.warning(f"Failed to get total packets with capinfos: {e}")
        
    update_progress(case_id, 0, total_packets, "initializing_parser")
    
    def on_progress(current_count):
        update_progress(case_id, current_count, total_packets, "parsing_pcap")
    
    # Parse PCAP into lightweight dictionaries
    parse_result = parse_pcap(filepath, progress_callback=on_progress)
    if parse_result["status"] == "error":
        raise HTTPException(status_code=500, detail=f"PCAP Parsing Failed: {parse_result.get('message')}")
        
    packets = parse_result["data"]
    
    update_progress(case_id, total_packets, total_packets, "carving_files")
    
    # Run File Carver
    carve_result = carve_files(filepath, CARVED_DIR)
    carved_files_list = carve_result.get("files", []) if carve_result.get("status") == "success" else []
    
    update_progress(case_id, total_packets, total_packets, "running_detectors")
    
    # Run detectors with error boundaries to prevent a single failure from aborting the entire report
    def safe_detect(detector_func, pkts):
        try:
            return detector_func(pkts)
        except Exception as e:
            logger.error(f"Detector {detector_func.__name__} failed: {e}")
            return {"score": 0, "findings": []}
            
    report = {
        "dns": safe_detect(detect_dns_threats, packets),
        "c2": safe_detect(detect_c2_traffic, packets),
        "tls": safe_detect(detect_tls_anomalies, packets),
        "exfil": safe_detect(detect_exfiltration, packets),
        "lateral": safe_detect(detect_lateral_movement, packets),
        "http": safe_detect(detect_http_threats, packets),
        "icmp": safe_detect(detect_icmp_exfiltration, packets),
        "port_scan": safe_detect(detect_port_scans, packets),
        "credentials": safe_detect(detect_credentials, packets),
        "vpn_tor": safe_detect(detect_anonymized_traffic, packets)
    }
    
    # Run victim correlation engine based on initial findings
    report["victim"] = identify_victim(report)
    
    # Generate Advanced Threat Intel
    report["timeline"] = generate_timeline(report)
    report["behavior"] = profile_behavior(report)
    
    # Generate Visual Network Graph Mapping
    report["graph"] = generate_graph(report)
    
    # Run YARA & OSINT Integrations (Requires carved files and initial findings)
    report["osint"] = run_osint_analysis(report, carved_files_list)
    
    # Calculate Total Risk Score (Average of highest severity scores)
    scores = [
        report["dns"]["score"],
        report["c2"]["score"],
        report["tls"]["score"],
        report["exfil"]["score"],
        report["lateral"]["score"],
        report["http"]["score"],
        report["icmp"]["score"],
        report["port_scan"]["score"],
        report["credentials"]["score"],
        report["vpn_tor"]["score"],
        report["victim"]["score"],
        report["osint"]["score"] if report.get("osint") else 0
    ]
    
    total_score = sum(scores) / len(scores) if scores else 0
    
    update_progress(case_id, total_packets, total_packets, "generating_report")
    
    final_report = {
        "case_id": case_id,
        "total_score": round(total_score, 1),
        "engines": report,
        "carved_files": carved_files_list
    }
    
    try:
        # Provide AI perspective over the full intelligence object
        final_report["ai_summary"] = generate_ai_summary(final_report)
        
        # Save report to a temporary file first, then dynamically rename to prevent frontend File I/O Race Conditions
        report_path = os.path.join(REPORT_DIR, f"{case_id}.json")
        temp_path = f"{report_path}.tmp"
        with open(temp_path, "w") as f:
            json.dump(final_report, f, indent=4)
            
        # Atomic rename
        os.replace(temp_path, report_path)
            
        # Free up memory and clean global state
        if case_id in analysis_progress:
            # We explicitly mark this as complete BEFORE deleting it? 
            # Actually frontend relies on deleting it from status?
            # Let's keep phase='completed', frontend logic expects it.
            analysis_progress[case_id]["phase"] = "completed"
            
        return final_report
        
    except Exception as e:
        logger.error(f"Analysis Background Task Failed for case {case_id}: {e}", exc_info=True)
        # Force progress status to show failure
        analysis_progress[case_id] = {
            "current_packet": 0,
            "total_packets": 0,
            "phase": "error"
        }
        return None

@router.get("/report/{case_id}")
async def get_report(case_id: str):
    """Fetches a previously generated report."""
    report_path = os.path.join(REPORT_DIR, f"{case_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found.")
        
    with open(report_path, "r") as f:
        return json.load(f)

@router.get("/report/{case_id}/download")
async def download_pdf_report(case_id: str):
    """Generates and downloads a PDF summary of the report."""
    report_path = os.path.join(REPORT_DIR, f"{case_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report data not found.")
        
    with open(report_path, "r") as f:
        report_data = json.load(f)
        
    # Generate the PDF
    try:
        pdf_path = generate_pdf_report(case_id, report_data)
        return FileResponse(
            path=pdf_path, 
            media_type="application/pdf", 
            filename=f"NetScan_Report_{case_id}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

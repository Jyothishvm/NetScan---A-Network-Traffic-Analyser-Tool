def detect_port_scans(packets):
    """
    Detects potential Port Scans / Reconnaissance sweeps (like Nmap or Masscan).
    Identifies a single source IP rapidly initiating connections to many distinct 
    destination ports on a single target IP.
    """
    findings = []
    risk_score = 0
    
    # Track ports accessed per source-destination pair
    scan_tracker = {}

    for pkt in packets:
        ip_layer = pkt.get("layers", {}).get("ip")
        tcp_layer = pkt.get("layers", {}).get("tcp")
        
        if ip_layer and tcp_layer:
            src_ip = ip_layer.get("src")
            dst_ip = ip_layer.get("dst")
            dst_port = tcp_layer.get("dstport")
            
            key = f"{src_ip}->{dst_ip}"
            
            if key not in scan_tracker:
                scan_tracker[key] = {"ports": set(), "timestamps": []}
                
            scan_tracker[key]["ports"].add(dst_port)
            scan_tracker[key]["timestamps"].append(pkt.get("timestamp", "Unknown"))

    # Threshold for distinct ports hit by one source to one destination
    scan_threshold = 15

    for key, data in scan_tracker.items():
        if len(data["ports"]) > scan_threshold:
            src_ip, dst_ip = key.split("->")
            
            last_seen = sorted(data["timestamps"])[-1]
            
            findings.append({
                "timestamp": last_seen,
                "type": "Port Scan / Reconnaissance",
                "source": src_ip,
                "target": dst_ip,
                "description": f"Source IP rapidly scanned {len(data['ports'])} distinct ports on the target. Possible Nmap/Masscan activity.",
                "severity": "Medium"
            })
            risk_score += 30

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

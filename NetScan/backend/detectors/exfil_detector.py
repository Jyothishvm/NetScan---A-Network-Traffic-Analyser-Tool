def detect_exfiltration(packets):
    """
    Detects potential data exfiltration by looking for abnormally large outbound transfers.
    """
    findings = []
    risk_score = 0
    
    # Calculate bytes sent per IP
    conn_bytes = {}
    
    for pkt in packets:
        ip_layer = pkt.get("layers", {}).get("ip")
        if ip_layer:
            src_ip = ip_layer.get("src")
            dst_ip = ip_layer.get("dst")
            
            # Identify internal to external flows
            if src_ip.startswith(("192.168", "10.", "172.")):
                length = int(pkt.get("length", 0))
                if src_ip not in conn_bytes:
                    conn_bytes[src_ip] = {"bytes": 0, "timestamps": []}
                    
                conn_bytes[src_ip]["bytes"] += length
                conn_bytes[src_ip]["timestamps"].append(pkt.get("timestamp", "Unknown"))
                
    # Flag IPs sending more than 50MB (Arbitrary demo threshold)
    exfil_threshold = 50 * 1024 * 1024
    
    for ip, data in conn_bytes.items():
        if data["bytes"] > exfil_threshold:
            mb_sent = round(data["bytes"] / (1024*1024), 2)
            last_seen = sorted(data["timestamps"])[-1]
            
            findings.append({
                "timestamp": last_seen,
                "type": "Data Exfiltration",
                "source": ip,
                "description": f"Abnormally high outbound traffic: {mb_sent}MB. Possible data theft.",
                "severity": "Critical"
            })
            risk_score += 50
            
    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

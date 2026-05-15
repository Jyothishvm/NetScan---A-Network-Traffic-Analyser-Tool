def detect_icmp_exfiltration(packets):
    """
    Detects potential data exfiltration via ICMP (Ping) packets.
    Standard pings are small (usually 32 or 64 bytes). Unusually large ICMP payloads
    often signify attackers hiding stolen data within ping requests.
    """
    findings = []
    risk_score = 0
    
    # Flag ICMP packets over 256 bytes payload
    suspicious_threshold = 256

    for pkt in packets:
        if "icmp" in pkt.get("layers", {}):
            icmp_layer = pkt["layers"]["icmp"]
            ip_layer = pkt.get("layers", {}).get("ip", {})
            
            length = icmp_layer.get("length", 0)
            
            if length > suspicious_threshold:
                src_ip = ip_layer.get("src", "Unknown")
                dst_ip = ip_layer.get("dst", "Unknown")
                
                # Deduplicate similar alerts for the same flow
                findings.append({
                    "timestamp": pkt.get("timestamp", "Unknown"),
                    "type": "ICMP Data Exfiltration",
                    "source": src_ip,
                    "destination": dst_ip,
                    "description": f"Abnormally large ICMP ping detected ({length} bytes). Usually indicative of tunneling or exfiltration.",
                    "severity": "High"
                })
                risk_score += 15 # Add points incrementally per large packet

    # Deduplicate exact same source-dest alerts to prevent UI flood
    unique_findings = []
    seen = set()
    for f in findings:
        key = f"{f['source']}->{f['destination']}"
        if key not in seen:
            unique_findings.append(f)
            seen.add(key)

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": unique_findings
    }

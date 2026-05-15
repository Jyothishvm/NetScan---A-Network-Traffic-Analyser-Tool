def detect_lateral_movement(packets):
    """
    Detects potential internal spread (lateral movement) via port scans or repeated SMB/RDP access.
    """
    findings = []
    risk_score = 0
    
    internal_connections = {}
    sweep_ports = ["445", "3389", "22"] # SMB, RDP, SSH
    
    for pkt in packets:
        ip_layer = pkt.get("layers", {}).get("ip")
        tcp_layer = pkt.get("layers", {}).get("tcp")
        
        if ip_layer and tcp_layer:
            src_ip = ip_layer.get("src")
            dst_ip = ip_layer.get("dst")
            dst_port = tcp_layer.get("dstport")
            
            # Check internal-to-internal traffic
            if src_ip.startswith(("192.168", "10.", "172.")) and dst_ip.startswith(("192.168", "10.", "172.")):
                if dst_port in sweep_ports:
                    key = f"{src_ip}->{dst_port}"
                    if key not in internal_connections:
                        internal_connections[key] = set()
                    internal_connections[key].add(dst_ip)
                    
    # Alert if a single IP touches many internal hosts on the same port
    for key, targets in internal_connections.items():
        if len(targets) > 5: # Sweeping threshold
            src_ip, port = key.split("->")
            findings.append({
                "type": "Network Sweeping / Lateral Movement",
                "source": src_ip,
                "port": port,
                "description": f"Source IP is sweeping port {port} across {len(targets)} internal hosts.",
                "severity": "High"
            })
            risk_score += 40
            
    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

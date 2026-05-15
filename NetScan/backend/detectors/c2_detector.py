def detect_c2_traffic(packets):
    """
    Detects potential Command & Control beacons.
    Looks for repeated connections to the same external IP on suspicious ports.
    """
    findings = []
    risk_score = 0
    connections = {}
    
    suspicious_ports = ["4444", "8080", "1337", "31337", "8888", "443"]

    for pkt in packets:
        ip_layer = pkt.get("layers", {}).get("ip")
        tcp_layer = pkt.get("layers", {}).get("tcp")
        
        if ip_layer and tcp_layer:
            src_ip = ip_layer.get("src")
            dst_ip = ip_layer.get("dst")
            dst_port = tcp_layer.get("dstport")
            
            # Simple check: if not a local IP (assuming private subnets 192.168, 10., 172.16-31)
            # In a real tool we'd use ipaddress module, keeping it simple here
            if not dst_ip.startswith(("192.168", "10.", "172.")):
                key = f"{src_ip}->{dst_ip}:{dst_port}"
                if key not in connections:
                    connections[key] = []
                connections[key].append(pkt.get("timestamp", "Unknown"))

    # Evaluate beaconing
    for key, timestamps in connections.items():
        count = len(timestamps)
        if count > 50:  # Arbitrary threshold for repeating beacon
            src, dst_info = key.split('->')
            dst_ip, dst_port = dst_info.split(':')
            
            severity = "High" if dst_port in suspicious_ports else "Medium"
            
            # Use the most recent timestamp for the alert
            last_seen = sorted(timestamps)[-1]
            
            findings.append({
                "timestamp": last_seen,
                "type": "Possible C2 Beaconing",
                "source": src,
                "destination": dst_ip,
                "port": dst_port,
                "description": f"High volume ({count}) of connections to the same external IP.",
                "severity": severity
            })
            risk_score += (30 if severity == "High" else 15)

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

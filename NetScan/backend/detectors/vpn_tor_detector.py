import os

# A tiny sample of known Tor exit nodes for demonstration.
# In a production environment, this list should be updated dynamically from a live API.
# For academic demonstration, these static IPs or subnets serve as proofs-of-concept.
KNOWN_TOR_NODES = {
    "185.220.101.44",
    "185.220.101.214",
    "185.220.101.144",
    "199.249.230.125",
    "185.220.101.10",
    "45.154.255.147",
    "185.220.102.248",
    "192.42.116.208"
}

# Common ports used by popular commercial and open-source VPN protocols
VPN_PORTS = {
    "1194": "OpenVPN",
    "500": "IPsec / IKEv2",
    "4500": "IPsec NAT-T",
    "51820": "WireGuard",
    "1701": "L2TP",
    "1723": "PPTP"
}

def detect_anonymized_traffic(packets):
    """
    Scans the packet captures for connections correlating to VPN usage
    or known Tor exit nodes, which attackers use to anonymize their C2 or Exfil.
    """
    findings = []
    risk_score = 0
    
    seen_conversations = set()

    for pkt in packets:
        ip_layer = pkt.get("layers", {}).get("ip")
        if not ip_layer:
            continue
            
        src = ip_layer.get("src")
        dst = ip_layer.get("dst")
        
        # Determine ports
        tcp_layer = pkt.get("layers", {}).get("tcp")
        udp_layer = pkt.get("layers", {}).get("udp")
        
        src_port = None
        dst_port = None
        
        if tcp_layer:
            src_port = tcp_layer.get("srcport")
            dst_port = tcp_layer.get("dstport")
        elif udp_layer:
            src_port = udp_layer.get("srcport")
            dst_port = udp_layer.get("dstport")
            
        if not src or not dst:
            continue
            
        conv_key = f"{src}-{dst}-{dst_port}"
        
        if conv_key not in seen_conversations:
            seen_conversations.add(conv_key)
            timestamp = pkt.get("timestamp", "Unknown Time")
            
            # 1. Tor Exit Node Check
            if src in KNOWN_TOR_NODES or dst in KNOWN_TOR_NODES:
                tor_ip = src if src in KNOWN_TOR_NODES else dst
                findings.append({
                    "timestamp": timestamp,
                    "type": "Tor Network Connection",
                    "ip": tor_ip,
                    "description": f"Connection to/from a known Tor Exit Node detected: {tor_ip}. Highly indicative of anonymized attacker routing.",
                    "severity": "Critical"
                })
                # Max out risk score for Tor
                risk_score += 80 
                
            # 2. VPN Protocol Check
            if str(dst_port) in VPN_PORTS or str(src_port) in VPN_PORTS:
                port_match = str(dst_port) if str(dst_port) in VPN_PORTS else str(src_port)
                vpn_type = VPN_PORTS[port_match]
                
                findings.append({
                    "timestamp": timestamp,
                    "type": "VPN Tunneling",
                    "ip": dst if str(dst_port) in VPN_PORTS else src,
                    "description": f"Potential {vpn_type} VPN tunnel established on port {port_match}. Traffic destination is masked.",
                    "severity": "High"
                })
                risk_score += 30

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

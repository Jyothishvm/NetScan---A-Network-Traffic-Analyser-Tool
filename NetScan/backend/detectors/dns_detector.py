import re

def detect_dns_threats(packets):
    """
    Analyzes DNS packets for Domain Generation Algorithms (DGA) or highly suspicious domains.
    """
    findings = []
    risk_score = 0
    
    # Simple regex for DGA-like random alphanumeric strings longer than 15 chars
    dga_pattern = re.compile(r"^[a-zA-Z0-9]{15,}\.(com|net|org|io|ru|xyz)$")
    
    for pkt in packets:
        if "dns" in pkt.get("layers", {}):
            qry_name = pkt["layers"]["dns"].get("qry_name", "")
            
            # Check for DGA
            if dga_pattern.match(qry_name):
                findings.append({
                    "timestamp": pkt.get("timestamp", "Unknown"),
                    "type": "DGA Detected",
                    "domain": qry_name,
                    "description": "Domain appears to be machine-generated, typical of malware C2.",
                    "severity": "High"
                })
                risk_score += 30
                
            # Check for overly long generic subdomains (DNS Tunneling indicator)
            if len(qry_name) > 60:
                 findings.append({
                    "timestamp": pkt.get("timestamp", "Unknown"),
                    "type": "Possible DNS Tunneling",
                    "domain": qry_name,
                    "description": "Unusually long DNS query, could be exfiltrating data or tunneling traffic.",
                    "severity": "High"
                })
                 risk_score += 40
                 
    # Deduplicate findings based on domain to avoid spam
    unique_findings = []
    seen = set()
    for f in findings:
        if f["domain"] not in seen:
            unique_findings.append(f)
            seen.add(f["domain"])
            
    # Cap risk score
    final_score = min(risk_score, 100)
    
    return {
        "score": final_score,
        "findings": unique_findings
    }

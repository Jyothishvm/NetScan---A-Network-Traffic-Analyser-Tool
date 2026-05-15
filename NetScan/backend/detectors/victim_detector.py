def identify_victim(all_findings):
    """
    Correlates findings across all detection engines (DNS, C2, TLS, Lateral, Exfil, HTTP, ICMP, Port Scan) 
    to pinpoint the primary internal IP address responsible for the most alerts.
    """
    ip_scores = {}
    
    for category, result in all_findings.items():
        if category == "victim": continue # Skip self
        
        findings_list = result.get("findings", [])
        for f in findings_list:
            if "source" in f:
                src_ip = f["source"]
                # Give points based on severity
                score_mod = 30 if f.get("severity") == "High" or f.get("severity") == "Critical" else 15
                ip_scores[src_ip] = ip_scores.get(src_ip, 0) + score_mod

    if not ip_scores:
        return {
            "score": 0,
            "most_compromised_host": "None",
            "findings": []
        }

    # Find the IP with the highest correlated score
    most_compromised_host = max(ip_scores, key=ip_scores.get)
    max_score = ip_scores[most_compromised_host]
    
    findings = []
    if max_score > 0:
        findings.append({
            "type": "Primary Victim Identified",
            "ip": most_compromised_host,
            "description": f"This host generated the highest volume of high-severity alerts.",
            "severity": "Critical"
        })

    return {
        "score": min(max_score, 100),
        "most_compromised_host": most_compromised_host,
        "findings": findings
    }

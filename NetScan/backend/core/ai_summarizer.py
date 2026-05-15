import json

def generate_ai_summary(report_data: dict) -> str:
    """
    Generates a dynamic heuristic-based intelligence summary
    to simulate an AI analyst reviewing the network traffic.
    """
    total_score = report_data.get("total_score", 0)
    engines = report_data.get("engines", {})
    victim_data = engines.get("victim", {})
    primary_ip = victim_data.get("most_compromised_host", "an unknown host")
    
    # Collect active threat categories
    active_threats = []
    for key, engine in engines.items():
        if key not in ["victim", "timeline", "behavior", "graph", "osint"] and isinstance(engine, dict):
            if engine.get("score", 0) > 0 or len(engine.get("findings", [])) > 0:
                active_threats.append(key)
                
    summary_parts = []
    
    # 1. Overall Severity Statement
    if total_score >= 80:
        summary_parts.append(f"CRITICAL: The analyzed network capture indicates a severe, multi-stage compromise originating from or targeting {primary_ip}.")
    elif total_score >= 40:
        summary_parts.append(f"WARNING: The analysis reveals suspicious network activity associated with {primary_ip} that requires further investigation.")
    elif total_score > 0:
        summary_parts.append(f"NOTICE: Low-level anomalous activity was detected in the network trace involving {primary_ip}.")
    else:
        summary_parts.append("The network capture appears benign. No significant malicious indicators were triggered across any detection engines.")
        return " ".join(summary_parts)
        
    # 2. Key Observations
    if active_threats:
        summary_parts.append(f"The automated threat engines flagged {len(active_threats)} distinct threat categories: {', '.join(active_threats).upper()}.")
        
    # 3. Contextual Threat Intelligence Details
    details = []
    if "c2" in active_threats:
        details.append("Evidence of Command and Control (C2) beaconing was observed, suggesting a potential established backdoor.")
    if "exfil" in active_threats:
        details.append("Large outbound data transfers were detected, indicating potential data exfiltration by an unauthorized actor.")
    if "lateral" in active_threats:
        details.append("Internal port sweeping and lateral movement attempts were identified, often a precursor to ransomware deployment or privilege escalation.")
    if "tls" in active_threats:
        details.append("Anomalous TLS fingerprints (JA3 anomalies) were observed, which typically correlates with automated malicious scripts rather than standard web browsers.")
    if "dns" in active_threats:
        details.append("Suspicious DNS queries, potentially involving Domain Generation Algorithms (DGA) or DNS tunneling, were detected.")
    if "credentials" in active_threats:
        details.append("Cleartext credentials were sent over the network, exposing sensitive authentication data to passive interception.")
        
    if details:
        summary_parts.append(" ".join(details))
        
    # 4. Actionable Recommendation
    if total_score >= 70:
        summary_parts.append(f"RECOMMENDATION: Immediate isolation of {primary_ip} is highly advised. Conduct a full forensic memory and disk analysis on the endpoint to identify the payload and assess the scope of the breach.")
    elif total_score >= 40:
        summary_parts.append(f"RECOMMENDATION: Verify the legitimacy of the flagged behavior. Consider rotating potentially exposed credentials and reviewing the originating process on {primary_ip}.")
        
    return "\n\n".join(summary_parts)

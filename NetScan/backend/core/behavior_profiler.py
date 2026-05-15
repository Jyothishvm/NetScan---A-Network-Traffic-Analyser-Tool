def profile_behavior(all_findings):
    """
    Maps detection findings to MITRE ATT&CK concepts to construct a Malware Behavior Profile.
    Stages: Reconnaissance, Infection/Execution, C2, Lateral Movement, Exfiltration.
    """
    profile = {
        "Reconnaissance": [],
        "Execution & Infection": [],
        "Command and Control (C2)": [],
        "Lateral Movement": [],
        "Action on Objectives (Exfil)": []
    }
    
    # Map findings into categories
    if "port_scan" in all_findings:
        profile["Reconnaissance"].extend(all_findings["port_scan"].get("findings", []))
        
    if "http" in all_findings:
        profile["Execution & Infection"].extend(all_findings["http"].get("findings", []))
        
    if "dns" in all_findings:
        profile["Command and Control (C2)"].extend(all_findings["dns"].get("findings", []))
        
    if "c2" in all_findings:
        profile["Command and Control (C2)"].extend(all_findings["c2"].get("findings", []))
        
    if "tls" in all_findings:
        # Suspicious TLS is often C2
        profile["Command and Control (C2)"].extend(all_findings["tls"].get("findings", []))
        
    if "lateral" in all_findings:
        profile["Lateral Movement"].extend(all_findings["lateral"].get("findings", []))
        
    if "exfil" in all_findings:
        profile["Action on Objectives (Exfil)"].extend(all_findings["exfil"].get("findings", []))
        
    if "icmp" in all_findings:
        # ICMP used for tunneling/exfil
        profile["Action on Objectives (Exfil)"].extend(all_findings["icmp"].get("findings", []))
        
    # Analyze the overall matrix to assign a "Behavior Matrix Score" (e.g. how far down the killchain did they get?)
    stages_hit = sum(1 for stage, events in profile.items() if len(events) > 0)
    killchain_score = (stages_hit / 5) * 100
    
    # Strip empty stages for cleaner UI rendering
    clean_profile = {stage: events for stage, events in profile.items() if events}
    
    return {
        "killchain_score": round(killchain_score, 1),
        "stages_hit": stages_hit,
        "matrix": clean_profile
    }

from datetime import datetime

def generate_timeline(all_findings):
    """
    Takes findings across all detection engines (which now include a 'timestamp' if injected)
    and sorts them chronologically to build an Attack Timeline.
    Note: Some findings (like Victim Correlation) don't have direct timestamps, 
    so we append them at the end or filter them.
    """
    events = []
    
    for engine, report in all_findings.items():
        if engine == "victim": continue # Summary engine
        
        findings = report.get("findings", [])
        for f in findings:
            # We assume detectors pass down the timestamp of the triggering packet if available
            time_str = f.get("timestamp", "1970-01-01T00:00:00")
            
            # Map engine names to readable categories
            category = engine.upper()
            if engine == "port_scan": category = "RECON"
            if engine == "lateral": category = "LATERAL"
            
            events.append({
                "time": time_str,
                "category": category,
                "type": f.get("type", "Unknown Event"),
                "description": f.get("description", ""),
                "severity": f.get("severity", "Medium"),
                "source": f.get("source") or f.get("ip") or "Unknown"
            })
            
    # Sort chronologically by ISO 8601 string
    events.sort(key=lambda x: x["time"])
    
    # Optional: If times are purely mock/1970, we can add sequential fake times for UI Demo purposes
    # Alternatively, just let the UI handle it. We will return the sorted list.
    
    return events

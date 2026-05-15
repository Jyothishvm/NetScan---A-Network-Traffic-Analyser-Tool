import urllib.parse
import re

def detect_http_threats(packets):
    """
    Analyzes HTTP unencrypted traffic for common web attacks like SQL Injection (SQLi),
    Cross-Site Scripting (XSS), and Path Traversal attempts in URIs.
    """
    findings = []
    risk_score = 0
    seen_uris = set()
    
    # Common attack signatures
    sqli_pattern = re.compile(r"(%27|')|(--)|(%23|#)|(union.+select)|(select.+from)", re.IGNORECASE)
    xss_pattern = re.compile(r"(%3C|<)script(%3E|>)|javascript:", re.IGNORECASE)
    traversal_pattern = re.compile(r"(\.\./)|(%2E%2E%2F)|(etc/passwd)|(\\\\)", re.IGNORECASE)
    
    # Suspicious User-Agents
    suspicious_uas = [
        "curl", "python-requests", "wget", "nmap", "sqlmap", "nikto", "dirb", "gobuster", "hydra"
    ]

    for pkt in packets:
        if "http" in pkt.get("layers", {}):
            http_layer = pkt["layers"]["http"]
            uri = http_layer.get("request_uri", "")
            ua = http_layer.get("user_agent", "")
            
            # 1. Check User Agent
            if ua and ua not in seen_uris:
                ua_lower = ua.lower()
                for suspect in suspicious_uas:
                    if suspect in ua_lower:
                        findings.append({
                            "timestamp": pkt.get("timestamp", "Unknown"),
                            "type": "Anomalous User-Agent",
                            "target_uri": uri,
                            "description": f"Suspicious automated or attack tool User-Agent detected: {ua}",
                            "severity": "Medium"
                        })
                        risk_score += 20
                        break
            
            # 2. Check URI payloads
            if uri and uri not in seen_uris:
                seen_uris.add(uri)
                seen_uris.add(ua) # store ua to prevent duplicate alerts
                decoded_uri = urllib.parse.unquote(uri)
                
                # Check SQLi
                if sqli_pattern.search(decoded_uri):
                    findings.append({
                        "timestamp": pkt.get("timestamp", "Unknown"),
                        "type": "SQL Injection Attempt",
                        "target_uri": uri,
                        "description": "SQL injection syntax detected in the HTTP request URI.",
                        "severity": "Critical"
                    })
                    risk_score += 40
                
                # Check XSS
                elif xss_pattern.search(decoded_uri):
                    findings.append({
                        "timestamp": pkt.get("timestamp", "Unknown"),
                        "type": "Cross-Site Scripting (XSS)",
                        "target_uri": uri,
                        "description": "Suspicious script tags or javascript detected in URI payload.",
                        "severity": "High"
                    })
                    risk_score += 30
                    
                # Check Directory Traversal
                elif traversal_pattern.search(decoded_uri):
                    findings.append({
                        "timestamp": pkt.get("timestamp", "Unknown"),
                        "type": "Path Traversal Attempt",
                        "target_uri": uri,
                        "description": "Attempted to break out of web directory to access sensitive files.",
                        "severity": "High"
                    })
                    risk_score += 30

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

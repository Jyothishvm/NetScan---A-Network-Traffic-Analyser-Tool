import base64
import re

def detect_credentials(parsed_data):
    """
    Analyzes application layer traffic for exposed credentials (FTP, Telnet, HTTP Basic/Bearer).
    """
    findings = []
    total_score = 0

    for pkt in parsed_data:
        layers = pkt.get("layers", {})
        timestamp = pkt.get("timestamp", "Unknown Time")
        
        # 1. FTP Cleartext Credentials
        if "ftp" in layers:
            ftp = layers["ftp"]
            cmd = ftp.get("request_command", "").upper()
            arg = ftp.get("request_arg", "")
            
            if cmd == "USER":
                findings.append({
                    "timestamp": timestamp,
                    "type": "Cleartext Credential (FTP Username)",
                    "protocol": "FTP",
                    "credential_type": "Username",
                    "value": arg,
                    "description": f"FTP Username '{arg}' transmitted in cleartext.",
                    "severity": "High"
                })
                total_score += 20
            elif cmd == "PASS":
                # For safety, we obfuscate the password slightly in the alert
                obfuscated = arg[:2] + "****" if len(arg) > 2 else "****"
                findings.append({
                    "timestamp": timestamp,
                    "type": "Cleartext Credential (FTP Password)",
                    "protocol": "FTP",
                    "credential_type": "Password",
                    "value": obfuscated,
                    "description": "FTP Password transmitted in cleartext.",
                    "severity": "Critical"
                })
                total_score += 40
                
        # 2. HTTP Authorization Headers
        if "http" in layers:
            http = layers["http"]
            auth = http.get("authorization", "")
            
            if auth.lower().startswith("basic "):
                try:
                    b64_str = auth.split(" ")[1]
                    decodedBytes = base64.b64decode(b64_str)
                    decodedStr = str(decodedBytes, "utf-8")
                    
                    if ":" in decodedStr:
                        user, pw = decodedStr.split(":", 1)
                        # Obfuscate pw
                        obf_pw = pw[:2] + "****" if len(pw) > 2 else "****"
                        findings.append({
                            "timestamp": timestamp,
                            "type": "Insecure HTTP Authentication (Basic)",
                            "protocol": "HTTP",
                            "credential_type": "Username/Password",
                            "value": f"{user}:{obf_pw}",
                            "description": f"Basic Auth credentials transmitted over unencrypted HTTP.",
                            "severity": "Critical"
                        })
                        total_score += 40
                except Exception:
                    pass
            elif auth.lower().startswith("bearer "):
                findings.append({
                    "timestamp": timestamp,
                    "type": "Exposed API Token",
                    "protocol": "HTTP",
                    "credential_type": "Bearer Token",
                    "value": auth[:15] + "...[TRUNCATED]",
                    "description": "Bearer token transmitted over unencrypted HTTP.",
                    "severity": "Critical"
                })
                total_score += 40
                
        # 3. Telnet Raw Data
        if "telnet" in layers:
            telnet = layers["telnet"]
            data = telnet.get("data", "")
            if data:
                # Basic heuristic for finding credentials in telnet stream
                if "login:" in data.lower() or "password:" in data.lower():
                    findings.append({
                        "timestamp": timestamp,
                        "type": "Cleartext Communication (Telnet)",
                        "protocol": "Telnet",
                        "credential_type": "Potential Credential Prompt",
                        "value": data[:50],
                        "description": "Telnet unencrypted login prompt detected.",
                        "severity": "High"
                    })
                    total_score += 20

    # Cap score at 100
    total_score = min(total_score, 100)
    
    return {
        "score": total_score,
        "findings": findings
    }

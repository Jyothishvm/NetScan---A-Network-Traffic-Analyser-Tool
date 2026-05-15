def detect_tls_anomalies(packets):
    """
    Detects suspicious TLS traffic, like unusual SNIs or missing SNIs.
    """
    findings = []
    risk_score = 0
    
    seen_snis = set()

    for pkt in packets:
        if "tls" in pkt.get("layers", {}):
            tls_layer = pkt["layers"]["tls"]
            sni = tls_layer.get("sni")
            ciphers = tls_layer.get("ciphersuites")
            exts = tls_layer.get("extensions")
            cert_issuer = tls_layer.get("cert_issuer")
            
            timestamp = pkt.get("timestamp", "Unknown")
            
            # 1. Check SNI
            if sni and sni not in seen_snis:
                seen_snis.add(sni)
                
                # Check for random looking SNIs or direct IP accesses over HTTPS
                if sum(c.isdigit() for c in sni) > 10 or sni.count('.') > 4:
                    findings.append({
                        "timestamp": timestamp,
                        "type": "Suspicious TLS SNI",
                        "sni": sni,
                        "description": "SNI looks machine-generated or highly unusual.",
                        "severity": "Medium"
                    })
                    risk_score += 15
                    
            # 2. Check JA3 / Client Hello Anomalies
            if ciphers and exts:
                # Basic heuristic for fingerprinting.
                # Malware often has extremely short or specific cipher lists.
                cipher_count = len(ciphers.split(",")) if isinstance(ciphers, str) else 0
                if cipher_count < 3 and ("JA3" not in str(seen_snis)):
                    # A legitimate browser usually sends 15+ ciphers. Very few ciphers indicate a script/malware.
                    seen_snis.add("JA3") # Use seen_snis to deduplicate this alert broadly
                    findings.append({
                        "timestamp": timestamp,
                        "type": "Anomalous TLS Client Hello (JA3)",
                        "sni": sni or "Unknown",
                        "description": "Client SSL negotiation looks like an automated script or malware rather than a standard browser.",
                        "severity": "High"
                    })
                    risk_score += 25
                    
            # 3. Check Certificate Anomalies
            if cert_issuer and cert_issuer not in seen_snis:
                seen_snis.add(cert_issuer)
                issuer_lower = cert_issuer.lower()
                
                # Check for suspicious or self-signed cert issuers often used in C2
                suspicious_issuers = ["default", "localhost", "snakeoil", "internet widgits"]
                if any(sus in issuer_lower for sus in suspicious_issuers):
                    findings.append({
                        "timestamp": timestamp,
                        "type": "Suspicious TLS Certificate",
                        "sni": cert_issuer,
                        "description": f"Untrusted or default SSL Certificate Issuer detected: {cert_issuer}",
                        "severity": "Critical"
                    })
                    risk_score += 35

    final_score = min(risk_score, 100)
    return {
        "score": final_score,
        "findings": findings
    }

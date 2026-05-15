import os
import json
import uuid

def create_test_pcap():
    # Helper to create a fake malware file for the mock OSINT YARA scanner testing
    os.makedirs(os.path.join(os.path.dirname(__file__), "extracted_files"), exist_ok=True)
    fake_malware_path = os.path.join(os.path.dirname(__file__), "extracted_files", "malicious_payload.exe")
    with open(fake_malware_path, "wb") as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00") # MZ Header for YARA mock

    return [
        {
            "filename": "malicious_payload.exe",
            "protocol": "HTTP",
            "size": "500 KB",
            "path": fake_malware_path
        },
        {
            "filename": "stolen_data.zip",
            "protocol": "FTP",
            "size": "12.4 MB",
            "path": "/path/to/extracted/stolen_data.zip"
        },
        {
            "filename": "config.json",
            "protocol": "SMB",
            "size": "2 KB",
            "path": "/path/to/extracted/config.json"
        }
    ]

mock_data = [
    # 1. DGA and Tunneling (DNS detector)
    {
        "highest_layer": "DNS",
        "length": 150,
        "layers": {
            "ip": {"src": "192.168.1.10", "dst": "8.8.8.8"},
            "udp": {"srcport": "54321", "dstport": "53"},
            "dns": {"qry_name": "ajshdfkjahsdfkjhasdkfjh.com"} # DGA
        }
    },
    {
        "highest_layer": "DNS",
        "length": 300,
        "layers": {
            "ip": {"src": "192.168.1.10", "dst": "8.8.8.8"},
            "udp": {"srcport": "54322", "dstport": "53"},
            "dns": {"qry_name": "thisisaverylongsubdomainthatappearstobetunnelingdataweirdlyoutofthenetwork.com"} # Tunneling
        }
    },
    
    # 2. C2 Beaconing (C2 Detector - repeated connections)
    *[
        {
            "highest_layer": "TCP",
            "length": 60,
            "layers": {
                "ip": {"src": "192.168.1.15", "dst": "185.15.22.1"},
                "tcp": {"srcport": str(10000 + i), "dstport": "4444"} # Suspicious port
            }
        } for i in range(55) # Exceeds threshold of 50
    ],
    
    # 3. Suspicious TLS (TLS Detector)
    {
        "highest_layer": "TLS",
        "length": 500,
        "layers": {
            "ip": {"src": "192.168.1.10", "dst": "45.33.22.11"},
            "tls": {"sni": "14234123412341234.xyz"} # Numeric SNI
        }
    },
    
    # 4. Data Exfiltration (Exfil Detector)
    {
        "highest_layer": "TCP",
        "length": 60 * 1024 * 1024, # 60MB, exceeds 50MB threshold
        "layers": {
            "ip": {"src": "192.168.1.15", "dst": "12.34.56.78"},
            "tcp": {"srcport": "55555", "dstport": "443"}
        }
    },
    
    # 5. Lateral Movement
    *[
        {
            "highest_layer": "TCP",
            "length": 60,
            "layers": {
                "ip": {"src": "192.168.1.20", "dst": f"192.168.1.{100 + i}"},
                "tcp": {"srcport": str(40000 + i), "dstport": "445"} # Sweeping SMB
            }
        } for i in range(10) # Sweep 10 internal hosts
    ],
    # 6. HTTP SQLi Attempt
    {
        "highest_layer": "HTTP",
        "length": 400,
        "layers": {
            "ip": {"src": "192.168.1.50", "dst": "10.0.0.5"},
            "http": {"request_uri": "/login.php?user=admin%27%20OR%201=1--"}
        }
    },
    
    # 7. ICMP Exfil
    {
        "highest_layer": "ICMP",
        "length": 1500, # well above 256
        "layers": {
            "ip": {"src": "192.168.1.15", "dst": "8.8.8.8"},
            "icmp": {"length": 1450}
        }
    },
    
    # 8. Port Scan (1 source -> 1 dest, many ports)
    *[
        {
            "highest_layer": "TCP",
            "length": 60,
            "layers": {
                "ip": {"src": "192.168.1.100", "dst": "192.168.1.254"},
                "tcp": {"srcport": "45678", "dstport": str(p)}
            }
        } for p in range(20, 41) # 21 ports scanned
    ],
    
    # 9. FTP Credentials
    {
        "highest_layer": "FTP",
        "length": 60,
        "layers": {
            "ip": {"src": "192.168.1.50", "dst": "10.0.0.100"},
            "ftp": {"request_command": "USER", "request_arg": "admin"}
        }
    },
    {
        "highest_layer": "FTP",
        "length": 60,
        "layers": {
            "ip": {"src": "192.168.1.50", "dst": "10.0.0.100"},
            "ftp": {"request_command": "PASS", "request_arg": "supersecretpassword1"}
        }
    },
    
    # 10. Tor Exit Node Exfil / C2
    {
        "highest_layer": "TCP",
        "length": 400,
        "layers": {
            "ip": {"src": "192.168.1.15", "dst": "185.220.101.44"}, # Known Tor IP
            "tcp": {"srcport": "45123", "dstport": "443"}
        }
    },
    
    # 11. Custom VPN Tunnel Outbound
    {
        "highest_layer": "UDP",
        "length": 1400,
        "layers": {
            "ip": {"src": "192.168.1.50", "dst": "112.44.55.66"},
            "udp": {"srcport": "40111", "dstport": "51820"} # WireGuard VPN port
        }
    }
]

if __name__ == "__main__":
    from detectors.dns_detector import detect_dns_threats
    from detectors.c2_detector import detect_c2_traffic
    from detectors.tls_detector import detect_tls_anomalies
    from detectors.exfil_detector import detect_exfiltration
    from detectors.lateral_detector import detect_lateral_movement
    from detectors.http_detector import detect_http_threats
    from detectors.icmp_detector import detect_icmp_exfiltration
    from detectors.port_scan_detector import detect_port_scans
    from detectors.victim_detector import identify_victim
    from detectors.credential_detector import detect_credentials
    from detectors.vpn_tor_detector import detect_anonymized_traffic
    from detectors.osint_detector import run_osint_analysis
    from core.timeline_generator import generate_timeline
    from core.behavior_profiler import profile_behavior
    from core.graph_generator import generate_graph
    
    # Inject fake timestamps 1 minute apart for the mock
    from datetime import datetime, timedelta
    base_time = datetime.utcnow() - timedelta(hours=1)
    for i, md in enumerate(mock_data):
        md["timestamp"] = (base_time + timedelta(minutes=i*2)).isoformat()
        
    report = {
        "dns": detect_dns_threats(mock_data),
        "c2": detect_c2_traffic(mock_data),
        "tls": detect_tls_anomalies(mock_data),
        "exfil": detect_exfiltration(mock_data),
        "lateral": detect_lateral_movement(mock_data),
        "http": detect_http_threats(mock_data),
        "icmp": detect_icmp_exfiltration(mock_data),
        "port_scan": detect_port_scans(mock_data),
        "credentials": detect_credentials(mock_data),
        "vpn_tor": detect_anonymized_traffic(mock_data)
    }
    
    report["victim"] = identify_victim(report)
    report["timeline"] = generate_timeline(report)
    report["behavior"] = profile_behavior(report)
    report["graph"] = generate_graph(report)
    
    # We must generate the fake malware payload for OSINT
    carved_files = create_test_pcap()
    report["osint"] = run_osint_analysis(report, carved_files)
    
    scores = [
        report["dns"]["score"],
        report["c2"]["score"],
        report["tls"]["score"],
        report["exfil"]["score"],
        report["lateral"]["score"],
        report["http"]["score"],
        report["icmp"]["score"],
        report["port_scan"]["score"],
        report["credentials"]["score"],
        report["vpn_tor"]["score"],
        report["victim"]["score"],
        report["osint"]["score"]
    ]
    
    total_score = sum(scores) / len(scores) if scores else 0
    
    case_id = "mock-malicious-case-12345"
    final_report = {
        "case_id": case_id,
        "total_score": round(total_score, 1),
        "engines": report,
        "carved_files": [], # Empty list for mock
        "raw_packets": mock_data
    }
    
    report_path = os.path.join("reports", f"{case_id}.json")
    with open(report_path, "w") as f:
        json.dump(final_report, f, indent=4)
        
    print(f"✅ Generated Mock Report: {report_path}")
    print(f"Total Score: {total_score}")
    print(f"Victim: {report['victim']['most_compromised_host']}")
    
    # Test the PDF Generator
    from core.report_generator import generate_pdf_report
    pdf_path = generate_pdf_report(case_id, final_report)
    print(f"✅ Generated Mock PDF: {pdf_path}")

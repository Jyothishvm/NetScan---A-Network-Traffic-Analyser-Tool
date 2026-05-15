import sys
import time
import asyncio
from core.parser import parse_pcap
from detectors.c2_detector import detect_c2_traffic
from detectors.dns_detector import detect_dns_threats
from detectors.tls_detector import detect_tls_anomalies
from detectors.exfil_detector import detect_exfiltration
from detectors.lateral_detector import detect_lateral_movement
from detectors.http_detector import detect_http_threats
from detectors.icmp_detector import detect_icmp_exfiltration
from detectors.port_scan_detector import detect_port_scans
from detectors.credential_detector import detect_credentials
from detectors.vpn_tor_detector import detect_anonymized_traffic

def main():
    pcap_file = "uploads/036ef8d2-bda6-499a-a9ee-f56c4ac493d8.pcap"
    print("Parsing PCAP....")
    t0 = time.time()
    result = parse_pcap(pcap_file)
    packets = result["data"]
    print(f"Parsed {len(packets)} packets in {time.time()-t0:.2f}s")
    
    detectors = [
        ("DNS", detect_dns_threats),
        ("C2", detect_c2_traffic),
        ("TLS", detect_tls_anomalies),
        ("Exfil", detect_exfiltration),
        ("Lateral", detect_lateral_movement),
        ("HTTP", detect_http_threats),
        ("ICMP", detect_icmp_exfiltration),
        ("Port Scan", detect_port_scans),
        ("Credentials", detect_credentials),
        ("VPN/Tor", detect_anonymized_traffic),
    ]
    
    for name, func in detectors:
        t_start = time.time()
        res = func(packets)
        dur = time.time() - t_start
        print(f"[{name}] took {dur:.4f}s. Score: {res.get('score')}")

if __name__ == "__main__":
    main()

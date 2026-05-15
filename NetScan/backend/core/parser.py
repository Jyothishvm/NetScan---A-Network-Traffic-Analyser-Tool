import pyshark
import asyncio
import nest_asyncio
import os

# To prevent event loop conflicts when running under Uvicorn/FastAPI
nest_asyncio.apply()

def get_tshark_path():
    paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"D:\Wireshark\tshark.exe"
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return "tshark"

TSHARK_PATH = os.environ.get("TSHARK_PATH", get_tshark_path())

def dictify_packet(packet):
    """
    Takes a single PyShark packet object and extracts the relevant layers into a dictionary.
    """
    timestamp = getattr(packet, "sniff_time", None)
    time_str = timestamp.isoformat() if timestamp else "Unknown Time"
    
    pkt_dict = {
        "timestamp": time_str,
        "highest_layer": getattr(packet, "highest_layer", "Unknown"),
        "length": getattr(packet, "length", 0),
        "layers": {}
    }
    
    if hasattr(packet, "eth"):
        pkt_dict["layers"]["eth"] = {
            "src": packet.eth.src,
            "dst": packet.eth.dst,
            "type": getattr(packet.eth, "type", "Unknown")
        }
    
    if hasattr(packet, "ip"):
        pkt_dict["layers"]["ip"] = {
            "src": packet.ip.src,
            "dst": packet.ip.dst,
        }
    elif hasattr(packet, "ipv6"):
        pkt_dict["layers"]["ip"] = {
            "src": packet.ipv6.src,
            "dst": packet.ipv6.dst,
        }
    
    if hasattr(packet, "tcp"):
        pkt_dict["layers"]["tcp"] = {
            "srcport": packet.tcp.srcport,
            "dstport": packet.tcp.dstport,
            "seq": getattr(packet.tcp, "seq", ""),
            "ack": getattr(packet.tcp, "ack", ""),
            "flags": getattr(packet.tcp, "flags_str", "") or getattr(packet.tcp, "flags", ""),
            "window_size": getattr(packet.tcp, "window_size", ""),
        }
        
    if hasattr(packet, "udp"):
        pkt_dict["layers"]["udp"] = {
            "srcport": packet.udp.srcport,
            "dstport": packet.udp.dstport,
        }
        
    if hasattr(packet, "arp"):
        pkt_dict["layers"]["arp"] = {
            "opcode": getattr(packet.arp, "opcode", ""),
            "src_mac": getattr(packet.arp, "src_hw_mac", ""),
            "dst_mac": getattr(packet.arp, "dst_hw_mac", ""),
            "src_ip": getattr(packet.arp, "src_proto_ipv4", ""),
            "dst_ip": getattr(packet.arp, "dst_proto_ipv4", ""),
        }
        
    if hasattr(packet, "dns"):
        try:
            qry_name = packet.dns.qry_name
            pkt_dict["layers"]["dns"] = {"qry_name": qry_name}
        except AttributeError:
            pass
            
    if hasattr(packet, "tls"):
        pkt_dict["layers"]["tls"] = {}
        
        # Sni
        sni = getattr(packet.tls, "handshake_extensions_server_name", None)
        if sni:
            pkt_dict["layers"]["tls"]["sni"] = str(sni)
            
        # JA3 properties (Ciphersuites, Extension types)
        ciphers = getattr(packet.tls, "handshake_ciphersuite", None)
        exts = getattr(packet.tls, "handshake_extension_type", None)
        if ciphers:
            # In pyshark, ciphers might be a list or a single string depending on the packet
            pkt_dict["layers"]["tls"]["ciphersuites"] = str(ciphers)
        if exts:
            pkt_dict["layers"]["tls"]["extensions"] = str(exts)
            
        # Certificate properties
        cert_issuer = getattr(packet.tls, "x509af_id_at_commonname", None)
        if cert_issuer:
            pkt_dict["layers"]["tls"]["cert_issuer"] = str(cert_issuer)
            
    if hasattr(packet, "http"):
        pkt_dict["layers"]["http"] = {}
        try:
            for field in ["request_uri", "user_agent", "authorization", "request_method", "host"]:
                val = getattr(packet.http, field, None)
                if val is not None:
                    pkt_dict["layers"]["http"][field] = str(val)
        except AttributeError:
            pass
            
    if hasattr(packet, "icmp"):
        try:
            pkt_dict["layers"]["icmp"] = {"length": int(packet.icmp.length)}
        except AttributeError:
            pass
            
    if hasattr(packet, "ftp"):
        pkt_dict["layers"]["ftp"] = {}
        for field in ["request_command", "request_arg", "response_code", "response_arg"]:
            val = getattr(packet.ftp, field, None)
            if val is not None:
                pkt_dict["layers"]["ftp"][field] = str(val)
                
    if hasattr(packet, "telnet"):
        val = getattr(packet.telnet, "data", None)
        if val is not None:
            pkt_dict["layers"]["telnet"] = {"data": str(val)}

    return pkt_dict


def parse_pcap(filepath, progress_callback=None):
    """
    Parses a PCAP file and returns a list of packet dictionaries containing relevant layers.
    This avoids passing complex PyShark objects to detectors to prevent serialization issues.
    """
    parsed_packets = []
    try:
        # We process in asyncio event loop isolated context 
        capture = pyshark.FileCapture(filepath, keep_packets=False, tshark_path=TSHARK_PATH)
        
        packet_count = 0
        for i, packet in enumerate(capture, 1):
            packet_count = i
            parsed = dictify_packet(packet)
            if parsed:
                parsed_packets.append(parsed)
                
            if progress_callback and i % 100 == 0:
                progress_callback(i)
        
        if progress_callback:
            progress_callback(packet_count)
            
        capture.close()
        return {"status": "success", "data": parsed_packets}
    except Exception as e:
        return {"status": "error", "message": str(e)}

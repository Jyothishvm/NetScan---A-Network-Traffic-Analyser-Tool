import asyncio
import pyshark
import binascii
from core.parser import dictify_packet

def test_hex():
    capture = pyshark.LiveCapture(
        interface="Wi-Fi", 
        tshark_path=r"D:\Wireshark\tshark.exe",
        use_json=True,
        include_raw=True
    )
    capture.sniff(timeout=3.0)
    
    for packet in capture:
        try:
            print("Dictifying...")
            parsed = dictify_packet(packet)
            print(parsed)
            
            raw = packet.get_raw_packet()
            hex_data = binascii.hexlify(raw).decode('utf-8')
            print(f"Hex length: {len(hex_data)}")
        except Exception as e:
            print(f"Error: {e}")
        break  # Just test one packet
    capture.close()

if __name__ == "__main__":
    test_hex()

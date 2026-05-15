import pyshark

def test_live():
    print("Starting sync thread test")
    capture = pyshark.LiveCapture('Wi-Fi', tshark_path=r'D:\Wireshark\tshark.exe')
    try:
        capture.sniff(timeout=3.0)
        for pkt in capture:
            print("Packet captured:", pkt.highest_layer)
    except Exception as e:
        print("Failed:", e)
    finally:
        capture.close()

if __name__ == "__main__":
    test_live()

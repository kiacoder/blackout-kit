with open("blackoutkit/tools.py", "r") as f:
    code = f.read()

pcap_code = '''

# ─────────────────────────── Native PCAP Export ───────────────────

def write_pcap_file(filepath: str, packets_raw: list) -> bool:
    """
    Write raw packet binary payloads to standard Global PCAP format (.pcap).
    Magic Number: 0xa1b2c3d4 (Microsecond resolution)
    Link-Layer Type: 1 (LINKTYPE_ETHERNET) / 101 (LINKTYPE_RAW_IP)
    """
    import struct
    import time

    pcap_hdr = struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,  # Magic number
        2, 4,       # Major version 2, Minor version 4
        0,          # GMT offset
        0,          # Accuracy of timestamps
        65535,      # Max snapshot length
        1           # Link-layer header type (1 = Ethernet)
    )

    try:
        with open(filepath, "wb") as f:
            f.write(pcap_hdr)
            for pkt in packets_raw:
                try:
                    raw_bytes = bytes(pkt)
                    ts = float(getattr(pkt, "time", time.time()))
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)
                    caplen = len(raw_bytes)
                    wirelen = caplen

                    pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, wirelen)
                    f.write(pkt_hdr)
                    f.write(raw_bytes)
                except Exception:
                    continue
        return True
    except Exception as exc:
        _log.error("Failed to write PCAP file %s: %s", filepath, exc)
        return False
'''

if "def write_pcap_file" not in code:
    code += pcap_code
    with open("blackoutkit/tools.py", "w") as f:
        f.write(code)
    print("Added write_pcap_file to blackoutkit/tools.py")

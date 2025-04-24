from scapy.all import sniff, wrpcap

def log_icmp_packets(filename: str, count: int = 50, iface: str = None):
    print(f"[LOGGER] Capturing {count} ICMP packets to {filename}")
    packets = sniff(filter="icmp", count=count, iface=iface)
    wrpcap(filename, packets)
    print(f"[LOGGER] Saved {count} ICMP packets to {filename}")

from scapy.all import sniff, IP, ICMP
from collections import defaultdict, deque
import time

def detect(threshold: int, window: float, iface: str = None):
    counts = defaultdict(lambda: deque())

    def _process(pkt):
        if ICMP in pkt and pkt[ICMP].type == 8:
            src = pkt[IP].src
            now = time.time()
            q = counts[src]
            q.append(now)

            while q and q[0] < now - window:
                q.popleft()

            if len(q) == threshold:
                print(f"[DETECT] High ICMP rate from {src}: {len(q)} pkts in {window}s")

    print(f"[DETECT] Sniffing ICMP... (iface={iface or 'default'})")
    sniff(filter="icmp and icmp[icmptype]==icmp-echo", prn=_process, iface=iface)

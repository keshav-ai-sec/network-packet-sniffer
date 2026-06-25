import argparse
import sys
from typing import Dict, List, Any
from core.capture import PacketCaptureEngine

def cli_callback(packet_info: Dict[str, Any], warnings: List[str], stats: Dict[str, int]) -> None:
    """Handles the UI updates for the command line."""
    proto = packet_info['protocol']
    src = packet_info['src_ip']
    dst = packet_info['dst_ip']
    length = packet_info['length']
    
    sport = f":{packet_info['src_port']}" if packet_info['src_port'] is not None else ""
    dport = f":{packet_info['dst_port']}" if packet_info['dst_port'] is not None else ""
    
    log_msg = f"{proto:4} | {src}{sport} -> {dst}{dport} | Len: {length}"
    print(f"[*] {log_msg}")
    
    for warning in warnings:
        print(f"\033[91m{warning}\033[0m")

def print_statistics(sniffer: PacketCaptureEngine) -> None:
    """Prints a summary table upon sniffer termination."""
    stats = sniffer.stats
    dest_ips = sniffer.dest_ips
    
    print("\n" + "="*50)
    print("                 SNIFFER STATISTICS                 ")
    print("="*50)
    print(f" Total packets captured: {stats['total']}")
    print(f" TCP packets:  {stats['TCP']}")
    print(f" UDP packets:  {stats['UDP']}")
    print(f" ICMP packets: {stats['ICMP']}")
    print(f" Other:        {stats['other']}")
    print("-" * 50)
    print(" Top 5 Destination IPs:")
    
    for ip, count in dest_ips.most_common(5):
        print(f"   {ip:<15} : {count} packets")
    print("="*50)

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer & Security Analyzer (CLI)")
    parser.add_argument("-p", "--protocol", help="Filter by protocol (tcp, udp, icmp)", type=str)
    parser.add_argument("--port", help="Filter by specific port number", type=int)
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 = infinite)", type=int, default=0)
    parser.add_argument("-l", "--log", help="File to log captured packets", type=str, default="packets.log")
    parser.add_argument("--pcap", help="Export captured packets to a PCAP file", type=str, default=None)
    args = parser.parse_args()

    print(f"Starting Network Sniffer (CLI Mode)...")
    if args.protocol:
        print(f" > Protocol Filter: {args.protocol.upper()}")
    if args.port:
        print(f" > Port Filter: {args.port}")
    if args.count > 0:
        print(f" > Target Count: {args.count} packets")
    else:
        print(" > Output Mode: Continuous (Press Ctrl+C to stop)")
        
    print("-" * 60)

    sniffer = PacketCaptureEngine(
        log_file=args.log, 
        protocol_filter=args.protocol, 
        port_filter=args.port, 
        pcap_file=args.pcap,
        on_packet_callback=cli_callback
    )

    try:
        sniffer.start_sniffing(count=args.count)
    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("[*] Note: You must run this script as an Administrator (Windows) or Root (Linux) to sniff traffic.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer gracefully...")
        sniffer.stop_sniffing()
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        print_statistics(sniffer)

if __name__ == "__main__":
    main()

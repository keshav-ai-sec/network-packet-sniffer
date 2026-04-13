import argparse
import sys
import logging
from collections import Counter, defaultdict
import time

# Suppress Scapy IPv6 warning
import logging as scapy_logging
scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

from scapy.all import sniff, IP, TCP, UDP, ICMP

# ----------------------------------------------------------------------
# Setup Logging
# ----------------------------------------------------------------------
# This will log captured packets into a file named 'packets.log'
logging.basicConfig(
    filename='packets.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ----------------------------------------------------------------------
# Global Variables for Statistics & Detection
# ----------------------------------------------------------------------
stats = {
    'total': 0,
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'other': 0
}
dest_ips = Counter()

# Track connections for suspicious activity detection
# connection_attempts: keeps track of recent traffic to specific ports
connection_attempts = defaultdict(list)
# port_scans: keeps track of how many distinct ports a source IP is hitting 
port_scans = defaultdict(set)


def process_packet(packet):
    """
    Extracts relevant information from a packet and returns it as a dictionary.
    """
    packet_info = {}
    
    # Check if the packet has an IP layer (we only care about IP traffic here)
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['length'] = len(packet)
        packet_info['protocol'] = 'Other'
        packet_info['src_port'] = None
        packet_info['dst_port'] = None

        # Check for TCP Protocol
        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
        
        # Check for UDP Protocol
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            
        # Check for ICMP Protocol (Ping requests etc.)
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'
            
        return packet_info
    
    # If not an IP packet, return None
    return None

def detect_suspicious_activity(packet_info):
    """
    Analyzes packet behavior over time to alert on potential suspicious activities.
    """
    now = time.time()
    src_ip = packet_info.get('src_ip')
    dst_ip = packet_info.get('dst_ip')
    dst_port = packet_info.get('dst_port')
    protocol = packet_info.get('protocol')
    
    warnings = []

    # Simple detection logic based on TCP/UDP ports
    if protocol in ['TCP', 'UDP'] and dst_port:
        
        # 1. Detect rapid connection attempts to the same port (e.g., brute-forcing or flooding)
        conn_key = (src_ip, dst_ip, dst_port)
        connection_attempts[conn_key].append(now)
        
        # Retain only attempts from the last 10 seconds
        connection_attempts[conn_key] = [t for t in connection_attempts[conn_key] if now - t < 10]
        
        if len(connection_attempts[conn_key]) > 30: 
            warnings.append(f"[!] Alert: High frequency of connections from {src_ip} to {dst_ip}:{dst_port}")
            connection_attempts[conn_key] = [] # Reset after warning to avoid spamming the terminal

        # 2. Add to distinct port scan tracking
        port_scans[src_ip].add(dst_port)
        
        # If a single IP hits more than 15 unique ports, flag it as a potential port scan
        if len(port_scans[src_ip]) > 15:
            warnings.append(f"[!] Alert: Possible Port Scan detected from Source IP: {src_ip}")
            port_scans[src_ip].clear() # Reset after warning

    return warnings

def display_packet(packet_info, warnings):
    """
    Displays the packet information neatly in the terminal and logs it.
    """
    src = packet_info['src_ip']
    dst = packet_info['dst_ip']
    proto = packet_info['protocol']
    length = packet_info['length']
    
    # Format ports tightly if they exist
    sport = f":{packet_info['src_port']}" if packet_info['src_port'] else ""
    dport = f":{packet_info['dst_port']}" if packet_info['dst_port'] else ""
    
    # Create the log message
    log_msg = f"{proto:4} | {src}{sport} -> {dst}{dport} | Len: {length}"
    
    # Print to console
    print(f"[*] {log_msg}")
    
    # Print any warnings in Red
    for warning in warnings:
        print(f"\033[91m{warning}\033[0m") 
        logging.warning(warning)
        
    # Write to log file
    logging.info(log_msg)

def update_stats(packet_info):
    """
    Updates global statistics summary counters.
    """
    stats['total'] += 1
    proto = packet_info['protocol']
    
    if proto in stats:
        stats[proto] += 1
    else:
        stats['other'] += 1
        
    dest_ips[packet_info['dst_ip']] += 1

def packet_callback(packet, filter_proto=None, filter_port=None):
    """
    Main background callback function executed whenever a packet is sniffed.
    """
    try:
        # Step 1: Process packet and extract metadata
        packet_info = process_packet(packet)
        if packet_info is None:
            return 
            
        # Step 2: Apply Filters
        if filter_proto and packet_info['protocol'].lower() != filter_proto.lower():
            return
            
        if filter_port:
            sp = packet_info.get('src_port')
            dp = packet_info.get('dst_port')
            if filter_port not in (sp, dp):
                return
                
        # Step 3: Analyze against suspicious behavior algorithms
        warnings = detect_suspicious_activity(packet_info)
        
        # Step 4: Display on screen
        display_packet(packet_info, warnings)
        
        # Step 5: Update the background statistics
        update_stats(packet_info)
        
    except Exception as e:
        print(f"[-] Error processing packet: {e}")

def print_statistics():
    """
    Prints a summary table and statistics when the sniffer terminates.
    """
    print("\n\n" + "="*50)
    print("                 SNIFFER STATISTICS                 ")
    print("="*50)
    print(f" Total packets captured: {stats['total']}")
    print(f" TCP packets:  {stats['TCP']}")
    print(f" UDP packets:  {stats['UDP']}")
    print(f" ICMP packets: {stats['ICMP']}")
    print(f" Other:        {stats['other']}")
    print("-" * 50)
    print(" Top 5 Destination IPs:")
    
    # the most_common(5) method returns the 5 highest populated keys in the counter
    for ip, count in dest_ips.most_common(5):
        print(f"   {ip:<15} : {count} packets")
    print("="*50)

def main():
    """
    Entry point of the script which configures arguments and starts sniffing.
    """
    parser = argparse.ArgumentParser(description="Network Packet Sniffer written in Python")
    parser.add_argument("-p", "--protocol", help="Filter by protocol (tcp, udp, icmp)", type=str)
    parser.add_argument("--port", help="Filter by specific port number", type=int)
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 = infinite)", type=int, default=0)
    args = parser.parse_args()

    print(f"Starting Network Sniffer...")
    if args.protocol:
        print(f" > Protocol Filter: {args.protocol.upper()}")
    if args.port:
        print(f" > Port Filter: {args.port}")
    if args.count > 0:
        print(f" > Target Count: {args.count} packets")
    else:
        print(" > Output Mode: Continuous (Press Ctrl+C to stop)")
        
    print("-" * 60)

    try:
        # sniff() is the main Scapy function
        # prn argument expects a function callback -> we use a lambda to pass dynamic parameters
        # store=False keeps memory consumption extremely low!
        sniff(
            prn=lambda pkt: packet_callback(pkt, args.protocol, args.port),
            store=False,  
            count=args.count
        )
    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("[*] Note: You must run this script as an Administrator (Windows) or Root (Linux) to sniff traffic.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer gracefully...")
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
        sys.exit(1)
    finally:
        # Run stats before the program totally quits
        print_statistics()

# This if-statement validates that the file is running directly
if __name__ == "__main__":
    main()

import logging
from collections import Counter
import threading
from typing import Dict, Optional, List, Any, Callable

# Suppress Scapy IPv6 warning
import logging as scapy_logging
scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

from scapy.all import sniff, IP, TCP, UDP, ICMP, Packet
from core.analyzer import ThreatAnalyzer

class PacketCaptureEngine:
    """
    Core engine responsible exclusively for network packet interception.
    Adheres to the Single Responsibility Principle by delegating threat
    analysis to the ThreatAnalyzer class.
    """
    def __init__(self, 
                 log_file: str = 'packets.log', 
                 protocol_filter: Optional[str] = None, 
                 port_filter: Optional[int] = None, 
                 pcap_file: Optional[str] = None,
                 on_packet_callback: Optional[Callable[[Dict[str, Any], List[str], Dict[str, Any]], None]] = None):
        
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.port_filter = port_filter
        self.on_packet_callback = on_packet_callback
        
        # Initialize the dedicated Threat Analyzer
        self.analyzer = ThreatAnalyzer()
        
        # Threading event to stop the sniffer gracefully
        self.stop_event = threading.Event()
        
        # PCAP Setup
        self.pcap_writer = None
        if pcap_file:
            from scapy.utils import PcapWriter
            self.pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
        
        # Setup Separate Telemetry Logging (Alerts can be logged here too, or separated)
        self.logger = logging.getLogger("PacketCaptureEngine")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
            self.logger.addHandler(file_handler)

        # Basic Counters
        self.stats: Dict[str, int] = {
            'total': 0,
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'other': 0
        }
        self.dest_ips: Counter = Counter()

    def process_packet(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Parses a Scapy packet into a structured dictionary."""
        if IP in packet:
            packet_info: Dict[str, Any] = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'length': len(packet),
                'protocol': 'Other',
                'src_port': None,
                'dst_port': None
            }

            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                
            return packet_info
        return None

    def update_stats(self, packet_info: Dict[str, Any]) -> None:
        """Updates internal telemetry counters."""
        self.stats['total'] += 1
        proto = packet_info['protocol']
        
        if proto in self.stats:
            self.stats[proto] += 1
        else:
            self.stats['other'] += 1
            
        self.dest_ips[packet_info['dst_ip']] += 1

    def packet_callback(self, packet: Packet) -> None:
        """Callback invoked by Scapy for each intercepted packet."""
        try:
            packet_info = self.process_packet(packet)
            if packet_info is None:
                return 
                
            # Filter Logic
            if self.protocol_filter and packet_info['protocol'] != self.protocol_filter:
                return
                
            if self.port_filter:
                if self.port_filter not in (packet_info.get('src_port'), packet_info.get('dst_port')):
                    return
                    
            # Delegate to Threat Analyzer
            warnings = self.analyzer.analyze_packet(packet_info)
            self.update_stats(packet_info)
            
            # Log the packet
            sport = f":{packet_info['src_port']}" if packet_info['src_port'] is not None else ""
            dport = f":{packet_info['dst_port']}" if packet_info['dst_port'] is not None else ""
            log_msg = f"{packet_info['protocol']:4} | {packet_info['src_ip']}{sport} -> {packet_info['dst_ip']}{dport} | Len: {packet_info['length']}"
            
            for w in warnings:
                self.logger.warning(w)
            self.logger.info(log_msg)

            # Export to PCAP if enabled
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            # Notify the UI layer via callback
            if self.on_packet_callback:
                self.on_packet_callback(packet_info, warnings, self.stats)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def should_stop_sniffing(self, packet) -> bool:
        """Scapy stop_filter callback. Returns True if stop_event is set."""
        return self.stop_event.is_set()

    def start_sniffing(self, count: int = 0) -> None:
        """Initiates the packet capture loop. Blocks until finished or stopped."""
        self.stop_event.clear()
        try:
            sniff(
                prn=self.packet_callback,
                store=False,  
                count=count,
                stop_filter=self.should_stop_sniffing
            )
        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
            raise e

    def stop_sniffing(self) -> None:
        """Signals the sniffer to stop capturing gracefully."""
        self.stop_event.set()

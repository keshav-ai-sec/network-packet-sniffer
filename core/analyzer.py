import time
from collections import defaultdict
from typing import Dict, List, Any
from config.settings import THREAT_THRESHOLDS

class ThreatAnalyzer:
    """
    Analyzes parsed network packet data to identify heuristic threats.
    Adheres to the Single Responsibility Principle (SRP).
    """
    def __init__(self):
        # Suspicious activity tracking
        self.connection_attempts: dict = defaultdict(list)
        self.port_scans: dict = defaultdict(set)
        
        # Load thresholds from config
        self.time_window = THREAT_THRESHOLDS["TIME_WINDOW_SECONDS"]
        self.brute_force_limit = THREAT_THRESHOLDS["BRUTE_FORCE_ATTEMPTS"]
        self.port_scan_limit = THREAT_THRESHOLDS["PORT_SCAN_UNIQUE_PORTS"]

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[str]:
        """
        Takes a parsed packet dictionary and checks for suspicious activity.
        Returns a list of warning strings if threats are detected.
        """
        warnings = []
        now = time.time()
        
        # Safe extraction of packet properties (Solves the missing IP edge-case bug)
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        
        # If essential data is missing (e.g. malformed IP header), return early safely
        if not src_ip or not dst_ip:
            return warnings

        # Analyze TCP/UDP for scanning / flooding
        if protocol in ['TCP', 'UDP'] and dst_port is not None:
            # 1. High frequency connection attempts (Brute Force / Flooding)
            conn_key = (src_ip, dst_ip, dst_port)
            self.connection_attempts[conn_key].append(now)
            
            # Slide the time window (Keep only attempts within the threshold window)
            self.connection_attempts[conn_key] = [
                t for t in self.connection_attempts[conn_key] 
                if now - t < self.time_window
            ]
            
            if len(self.connection_attempts[conn_key]) > self.brute_force_limit: 
                warnings.append(f"[!] Alert: High frequency connections from {src_ip} to {dst_ip}:{dst_port}")
                self.connection_attempts[conn_key] = [] # Reset after alert to prevent log spam

            # 2. Distinct port scan tracking
            self.port_scans[src_ip].add(dst_port)
            
            if len(self.port_scans[src_ip]) > self.port_scan_limit:
                warnings.append(f"[!] Alert: Possible Port Scan detected from Source IP: {src_ip}")
                self.port_scans[src_ip].clear() # Reset after alert

        return warnings

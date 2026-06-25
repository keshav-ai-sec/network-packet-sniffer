"""
Centralized Configuration for Sentinel Security Analyzer.
Extracting 'Magic Numbers' into a configuration file allows security
analysts to tune detection thresholds without modifying core code.
"""

# Threat Detection Thresholds
THREAT_THRESHOLDS = {
    # Time window (in seconds) to analyze connection frequency
    "TIME_WINDOW_SECONDS": 10,
    
    # Number of connection attempts to the same port within the time window
    # to trigger a "High frequency / Brute Force" alert
    "BRUTE_FORCE_ATTEMPTS": 30,
    
    # Number of distinct ports accessed by a single IP to trigger a "Port Scan" alert
    "PORT_SCAN_UNIQUE_PORTS": 15
}

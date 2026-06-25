import unittest
from core.capture import PacketCaptureEngine
from core.analyzer import ThreatAnalyzer
from scapy.all import IP, TCP, UDP

class TestPacketSniffer(unittest.TestCase):
    def setUp(self):
        self.sniffer = PacketCaptureEngine(log_file='test_packets.log')
        self.analyzer = ThreatAnalyzer()

    def test_process_tcp_packet(self):
        # Craft a fake TCP packet using Scapy
        packet = IP(src="192.168.1.5", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        info = self.sniffer.process_packet(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info['protocol'], 'TCP')
        self.assertEqual(info['src_ip'], '192.168.1.5')
        self.assertEqual(info['dst_ip'], '10.0.0.1')
        self.assertEqual(info['dst_port'], 80)

    def test_process_udp_packet(self):
        # Craft a fake UDP packet using Scapy
        packet = IP(src="10.0.0.2", dst="8.8.8.8") / UDP(sport=54321, dport=53)
        info = self.sniffer.process_packet(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info['protocol'], 'UDP')
        self.assertEqual(info['dst_port'], 53)

    def test_port_scan_detection(self):
        # Simulate a single IP hitting 20 different ports
        for port in range(1, 21):
            packet_info = {
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.5',
                'dst_port': port,
                'protocol': 'TCP'
            }
            # Use the new analyzer module directly!
            warnings = self.analyzer.analyze_packet(packet_info)
            
            # The alert should trigger on the 16th distinct port (default threshold > 15)
            if port == 16:
                self.assertTrue(any("Possible Port Scan" in w for w in warnings))
            elif port < 16:
                self.assertEqual(len(warnings), 0)

if __name__ == '__main__':
    unittest.main()

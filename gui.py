import customtkinter as ctk
import threading
import queue
from typing import Dict, List, Any
from core.capture import PacketCaptureEngine
import sys

# Set default theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # UI Queue for thread-safe updates
        self.ui_queue = queue.Queue()
        self.sniffer = None
        self.sniff_thread = None

        # Configure window
        self.title("Sentinel - Network Security Analyzer")
        self.geometry("1100x700")

        # Configure grid layout (1 row, 2 columns)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ====================
        # LEFT SIDEBAR
        # ====================
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Sentinel Sniffer\n🛡️", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        # Filters
        self.protocol_label = ctk.CTkLabel(self.sidebar_frame, text="Protocol Filter:")
        self.protocol_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.protocol_dropdown = ctk.CTkOptionMenu(self.sidebar_frame, values=["ALL", "TCP", "UDP", "ICMP"])
        self.protocol_dropdown.grid(row=2, column=0, padx=20, pady=(5, 20))

        self.port_label = ctk.CTkLabel(self.sidebar_frame, text="Target Port:")
        self.port_label.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.port_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="e.g. 80 or 443")
        self.port_entry.grid(row=4, column=0, padx=20, pady=(5, 20))
        
        self.pcap_switch = ctk.CTkSwitch(self.sidebar_frame, text="Export to PCAP")
        self.pcap_switch.grid(row=5, column=0, padx=20, pady=(10, 20))

        # Action Buttons
        self.start_btn = ctk.CTkButton(self.sidebar_frame, text="▶ Start Capture", fg_color="green", hover_color="darkgreen", command=self.start_capture)
        self.start_btn.grid(row=7, column=0, padx=20, pady=(10, 10))

        self.stop_btn = ctk.CTkButton(self.sidebar_frame, text="⏹ Stop Capture", fg_color="red", hover_color="darkred", state="disabled", command=self.stop_capture)
        self.stop_btn.grid(row=8, column=0, padx=20, pady=(0, 20))

        # ====================
        # MAIN CONTENT AREA
        # ====================
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # Top Stats Cards
        self.stat_cards = {}
        headers = ["Total Packets", "TCP Traffic", "UDP Traffic", "Security Alerts"]
        for i, header in enumerate(headers):
            card = ctk.CTkFrame(self.main_frame, corner_radius=10)
            card.grid(row=0, column=i, padx=5, pady=(0, 20), sticky="nsew")
            
            lbl_title = ctk.CTkLabel(card, text=header, font=ctk.CTkFont(size=14, weight="bold"))
            lbl_title.pack(pady=(15, 5))
            
            lbl_val = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=28, weight="bold"), text_color="#1f6aa5" if i < 3 else "red")
            lbl_val.pack(pady=(0, 15))
            
            self.stat_cards[header] = lbl_val

        # Alert Counter variable
        self.alert_count = 0

        # Text Consoles Frame
        self.console_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.console_frame.grid(row=1, column=0, columnspan=4, sticky="nsew")
        self.console_frame.grid_columnconfigure(0, weight=7)
        self.console_frame.grid_columnconfigure(1, weight=3)
        self.console_frame.grid_rowconfigure(0, weight=1)

        # Live Traffic Console
        self.live_traffic_frame = ctk.CTkFrame(self.console_frame)
        self.live_traffic_frame.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        ctk.CTkLabel(self.live_traffic_frame, text="Live Traffic Log", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        self.live_traffic_box = ctk.CTkTextbox(self.live_traffic_frame, state="disabled", font=("Consolas", 12))
        self.live_traffic_box.pack(expand=True, fill="both", padx=10, pady=10)

        # Security Alerts Console
        self.alerts_frame = ctk.CTkFrame(self.console_frame)
        self.alerts_frame.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(self.alerts_frame, text="Security Alerts", font=ctk.CTkFont(weight="bold"), text_color="red").pack(pady=5)
        self.alerts_box = ctk.CTkTextbox(self.alerts_frame, state="disabled", font=("Consolas", 12), text_color="red")
        self.alerts_box.pack(expand=True, fill="both", padx=10, pady=10)

        # Start periodic queue checking
        self.check_queue()

    # ====================
    # CORE LOGIC BINDINGS
    # ====================
    def start_capture(self):
        """Initializes the backend sniffer and starts the background thread."""
        proto_val = self.protocol_dropdown.get()
        protocol = proto_val if proto_val != "ALL" else None
        
        port_val = self.port_entry.get().strip()
        port = int(port_val) if port_val.isdigit() else None
        
        pcap_file = "capture.pcap" if self.pcap_switch.get() == 1 else None

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.protocol_dropdown.configure(state="disabled")
        self.port_entry.configure(state="disabled")
        self.pcap_switch.configure(state="disabled")
        
        self.log_traffic("SYSTEM", f"Starting capture. Protocol: {protocol or 'ALL'}, Port: {port or 'ALL'}")

        self.sniffer = PacketCaptureEngine(
            log_file='gui_packets.log',
            protocol_filter=protocol,
            port_filter=port,
            pcap_file=pcap_file,
            on_packet_callback=self.on_packet_intercepted
        )

        self.sniff_thread = threading.Thread(target=self._run_sniffer_safely, daemon=True)
        self.sniff_thread.start()

    def _run_sniffer_safely(self):
        """Runs the sniffer. Catches permission errors."""
        try:
            self.sniffer.start_sniffing()
        except PermissionError:
            self.ui_queue.put({"type": "error", "msg": "Permission Denied. Run as Admin/Root."})
        except Exception as e:
            self.ui_queue.put({"type": "error", "msg": f"Error: {str(e)}"})

    def stop_capture(self):
        """Signals the background thread to stop gracefully."""
        if self.sniffer:
            self.sniffer.stop_sniffing()
            self.log_traffic("SYSTEM", "Capture stopped safely.")

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.protocol_dropdown.configure(state="normal")
        self.port_entry.configure(state="normal")
        self.pcap_switch.configure(state="normal")

    def on_packet_intercepted(self, packet_info: Dict[str, Any], warnings: List[str], stats: Dict[str, int]):
        """This is called by the background thread. We MUST push data to the queue to update UI."""
        self.ui_queue.put({
            "type": "packet",
            "info": packet_info,
            "warnings": warnings,
            "stats": stats
        })

    def check_queue(self):
        """Periodically runs on the main UI thread to process packets from the background thread."""
        # Process a maximum of 50 packets per UI tick to prevent freezing on high traffic
        for _ in range(50):
            if self.ui_queue.empty():
                break
                
            item = self.ui_queue.get()
            
            if item["type"] == "packet":
                info = item["info"]
                stats = item["stats"]
                warnings = item["warnings"]
                
                # Update stats cards
                self.stat_cards["Total Packets"].configure(text=str(stats.get('total', 0)))
                self.stat_cards["TCP Traffic"].configure(text=str(stats.get('TCP', 0)))
                self.stat_cards["UDP Traffic"].configure(text=str(stats.get('UDP', 0)))

                # Log traffic
                sport = f":{info['src_port']}" if info['src_port'] is not None else ""
                dport = f":{info['dst_port']}" if info['dst_port'] is not None else ""
                log_msg = f"{info['protocol']:4} | {info['src_ip']}{sport} -> {info['dst_ip']}{dport} | Len: {info['length']}"
                self.log_traffic("TRAFFIC", log_msg)

                # Handle warnings
                for w in warnings:
                    self.alert_count += 1
                    self.stat_cards["Security Alerts"].configure(text=str(self.alert_count))
                    self.log_alert(w)

            elif item["type"] == "error":
                self.log_alert(item["msg"])
                self.stop_capture()

        # Check queue again in 100 milliseconds
        self.after(100, self.check_queue)

    def log_traffic(self, tag: str, message: str):
        self.live_traffic_box.configure(state="normal")
        self.live_traffic_box.insert("end", f"[{tag}] {message}\n")
        self.live_traffic_box.see("end")
        self.live_traffic_box.configure(state="disabled")

    def log_alert(self, message: str):
        self.alerts_box.configure(state="normal")
        self.alerts_box.insert("end", f"[!] {message}\n")
        self.alerts_box.see("end")
        self.alerts_box.configure(state="disabled")

if __name__ == "__main__":
    app = PacketSnifferGUI()
    app.mainloop()

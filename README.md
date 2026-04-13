# Network Packet Sniffer

A beginner-to-intermediate level Networking and Cybersecurity project built with Python and the Scapy library. This tool captures live network traffic passing through your machine, extracts essential packet metadata, logs it, and offers rudimentary behavioral analysis to detect potential threats.

## 🚀 Features

- **Live Packet Capturing:** Sniffs live traffic from the local machine in real-time.
- **Data Field Extraction:** Securely isolates and extracts Source & Destination IPs, Network Ports, Protocols (`TCP`, `UDP`, `ICMP`), and packet lengths.
- **Dynamic Command-Line Filtering:** You can restrict traffic mapping based on targeted protocols (`--protocol`) or specialized ports (`--port`).
- **Suspicious Activity Detection:** Integrates basic detection algorithms for anomalous situations like repetitive failed port interactions or multi-port scanning loops.
- **Continuous Logging:** All sniffed packets and warnings are silently forwarded to a local `packets.log` file.
- **Statistics Report Generator:** Upon termination, a clean readout displays overall captured volume, protocol distribution, and the top 5 targeted destination IPs.

---

## 💻 Prerequisites & Installation

### 1. Install Required Python Libraries
Ensure you have **Python 3** installed. Use `pip` to install the `scapy` library:

```bash
pip install scapy
```

### 2. Platform-Specific Cap Drivers
Packet sniffing sits deep in the network abstraction layers, meaning standard user-level programs don't natively have permissions to read it. Scapy relies on helper drivers for this.

**For Windows Users:**
- Download and install [Npcap](https://npcap.com/) (Make sure to select **"Install Npcap in WinPcap API-compatible Mode"** during the installation prompt).

**For Linux Users:**
- You will need `libpcap` installed. If you are on an Ubuntu/Debian-based system, run:
```bash
sudo apt-get install libpcap-dev
```

---

## 🏃‍♂️ How to Run the Sniffer

1. Open a new Command Prompt or Terminal.
2. Navigate to the project’s root directory.
3. Run the script! **Important: Accessing networking interfaces requires Administrator/Root privileges.**

**On Windows (Ensure Command Prompt is running as Administrator):**
```cmd
python sniffer.py
```

**On Linux / macOS:**
```bash
sudo python3 sniffer.py
```

### Advanced Run Options (Filtering)
You can directly tell the script what you want to listen to using the terminal configurations below:

```bash
# Filter only TCP traffic
python sniffer.py --protocol tcp

# Filter traffic attempting to reach port 80 (HTTP)
python sniffer.py --port 80

# Capture only exactly 100 packets then kill the execution
python sniffer.py --count 100

# You can even mix them!
python sniffer.py --protocol udp --port 53
```

---

## 📝 How to Write This Project in a Resume Professionally

This project is fantastic for breaking into roles connected to networking, SOC (Security Operations Center) roles, and Junior Penetration Testing jobs. It demonstrates a working knowledge of the OSI Model, Python, and terminal-based tooling.

**Here is an example formatting block you can modify for your resume:**

> ### Network Packet Analyzer | *Python, Scapy, TCP/IP*
> * Developed a dynamic network packet capturing mechanism using Python and the Scapy library to actively sniff, decode, and monitor local machine traffic in real-time.
> * Implemented parsing algorithms to cleanly isolate Source/Destination IP topologies, Transport Layer protocols (TCP/UDP/ICMP), and communication Ports.
> * Designed a suspicious activity heuristic module capable of detecting anomalous behavioral patterns, including active IP port scanning and rapid ping flooding.
> * Built CLI-level controls for dynamic traffic filtering, backed by fully synchronous background logging output streams for long-term telemetry storage.

### Interview Preparation Pro-Tips:
* Make sure you understand the difference between **TCP (connection-oriented)** and **UDP (connectionless)**.
* Understand the fundamentals of why the sniffer needs "Promiscuous Mode" / elevated Admin privileges.
* Be able to confidently explain what `Scapy` is and why you chose it over simply reading Python raw sockets.

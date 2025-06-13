# 🛠️ Network Sniffer (Python + Scapy)

A lightweight and efficient network sniffer built in Python using Scapy. Captures live packets and displays IP headers, protocols, ports, and payload data in real-time.

## 📌 Features

- Captures live network traffic
- Displays:
  - Source/Destination IPs
  - Protocols (TCP/UDP/ICMP)
  - Ports
  - Hex preview of payloads
- Timestamps each packet
- Lightweight and readable

## 🚀 Installation

### 🐍 Requirements
- Python 3.6+
- Scapy
- Npcap (on Windows)

### 💻 Setup (Windows)

1. Install Python: https://www.python.org/downloads  
2. Install Scapy:
    ```bash
    pip install -r requirements.txt
    ```
3. Install Npcap: https://nmap.org/npcap

### ▶️ Run the Sniffer

```bash
python sniffer.py

⚠️ Run CMD as Administrator if required.

📋 Example Output
yaml
Copy
Edit
[2025-06-11 20:00:01] 192.168.0.102 → 8.8.8.8 | Protocol: 17 | UDP 5353 → 53 | Payload: 123abcde...
🛡️ Disclaimer
For educational purposes only. Please do not run this on networks without permission.

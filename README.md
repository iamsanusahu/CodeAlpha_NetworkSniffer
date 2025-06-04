# CodeAlpha_NetworkSniffer

A Python-based network packet sniffer developed as Task 1 for the CodeAlpha Cybersecurity Internship. Captures and analyzes live network traffic to display protocol details, IP addresses, and payload samples.

## Features
- Real-time packet capture (TCP/UDP/IP)
- Displays:
  - Source/Destination IPs and ports
  - Protocol type (TCP/UDP)
  - Sample payload data (first 50 bytes)
- Lightweight (~50 lines of code)

## Requirements
- Python 3.x
- Scapy library (`pip install scapy`)
- Admin/root privileges (for packet capture)

## Usage
```bash
# Install dependencies
pip install scapy

# Run sniffer (requires admin)
sudo python3 network_sniffer.py

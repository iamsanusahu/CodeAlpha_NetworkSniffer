# sniffer.py
"""
Network Sniffer - Captures live packets and displays protocol, IPs, ports, and payload.

Author: Sanu kumar

"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(pkt):
    if IP in pkt:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        proto = pkt[IP].proto
        summary = f"[{timestamp}] {ip_src} → {ip_dst} | Protocol: {proto}"

        if TCP in pkt:
            summary += f" | TCP {pkt[TCP].sport} → {pkt[TCP].dport}"
        elif UDP in pkt:
            summary += f" | UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
        elif ICMP in pkt:
            summary += f" | ICMP Type: {pkt[ICMP].type}"

        # Print first 20 bytes of payload (safely)
        try:
            payload = bytes(pkt[IP].payload)
            if payload:
                summary += f" | Payload: {payload[:20].hex()}..."
        except Exception:
            pass

        print(summary)

if __name__ == "__main__":
    print("=== Network Sniffer Started (Press Ctrl+C to stop) ===")
    sniff(filter="ip", prn=process_packet, store=False)

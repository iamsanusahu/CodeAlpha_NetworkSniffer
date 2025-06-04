from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

def packet_handler(packet):
    # Basic packet information
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"\n[Packet] {src_ip} -> {dst_ip} | Protocol: {proto}")
        
        # TCP information
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP | Ports: {src_port}->{dst_port}")
            
        # UDP information
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP | Ports: {src_port}->{dst_port}")
        
        # Payload data (first 50 bytes)
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:50]
            print(f"Payload (sample): {payload}")

# Start sniffing
print("Starting network sniffer...")
print("Press Ctrl+C to stop\n")
sniff(prn=packet_handler, store=0)
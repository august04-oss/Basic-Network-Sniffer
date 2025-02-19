!pip install scapy

from google.colab import files
from scapy.all import rdpcap, IP, TCP, UDP

uploaded = files.upload()
pcap_file = list(uploaded.keys())[0]  # Get the uploaded file name
print(f" Uploaded file: {pcap_file}")

packets = rdpcap(pcap_file)

def process_packet(packet):
    """Process each packet from the pcap file."""
    if IP in packet:
        print(f"\n Source IP: {packet[IP].src} → Destination IP: {packet[IP].dst}")

        if TCP in packet:
            print(f" TCP: {packet[TCP].sport} → {packet[TCP].dport}")
            if packet[TCP].payload:
                print(f" Payload: {bytes(packet[TCP].payload).decode(errors='ignore')}")

        if UDP in packet:
            print(f" UDP: {packet[UDP].sport} → {packet[UDP].dport}")

print("\n Packet Analysis:")
for pkt in packets[:10]:  
    process_packet(pkt)

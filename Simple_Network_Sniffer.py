!pip install scapy

from scapy.all import *

def packet_callback(packet):

    print(packet.summary())
sniff(prn=packet_callback, iface="eth0", count=10)
from scapy.all import sniff
from scapy.layers.inet import IP
import logging
import os

# Automatically create logs folder
os.makedirs("logs", exist_ok=True)

# Logging setup
logging.basicConfig(
    filename='logs/traffic.log',
    level=logging.INFO
)

def process_packet(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)

        output = f"""
Source IP      : {src}
Destination IP : {dst}
Protocol       : {proto}
Packet Length  : {length}
"""

        print(output)

        logging.info(output)

# Start packet sniffing
sniff(prn=process_packet, store=False)
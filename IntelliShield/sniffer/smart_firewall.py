from scapy.all import sniff
from scapy.layers.inet import IP
from sklearn.ensemble import IsolationForest
import numpy as np
import os
import logging

# Create logs folder automatically
os.makedirs("logs", exist_ok=True)

# Logging setup
logging.basicConfig(
    filename='logs/firewall.log',
    level=logging.INFO
)

# ---------------- AI MODEL ----------------

# Training data
X = np.array([
    [80, 500],
    [443, 450],
    [53, 300],
    [22, 7000]
])

# Train AI model
model = IsolationForest(contamination=0.1)
model.fit(X)

# Already blocked IPs
blocked_ips = set()

# ---------------- BLOCK FUNCTION ----------------

def block_ip(ip):

    if ip in blocked_ips:
        return

    command = (
        f'netsh advfirewall firewall add rule '
        f'name="Block_{ip}" '
        f'dir=in action=block remoteip={ip}'
    )

    os.system(command)

    blocked_ips.add(ip)

    print(f"[BLOCKED] {ip}")

    logging.info(f"Blocked IP: {ip}")

# ---------------- PACKET PROCESSING ----------------

def process_packet(packet):

    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst
        length = len(packet)

        # Feature for AI
        test_data = [[packet.proto, length]]

        result = model.predict(test_data)

        print(f"""
Source IP      : {src}
Destination IP : {dst}
Packet Length  : {length}
AI Result      : {result[0]}
""")

        logging.info(f"{src} -> {dst}")

        # Suspicious traffic detected
        if result[0] == -1:

            print(f"[ALERT] Suspicious traffic from {src}")

            logging.warning(f"Suspicious IP: {src}")

            block_ip(src)

# ---------------- START FIREWALL ----------------

print("AI Smart Firewall Running...")

sniff(prn=process_packet, store=False)
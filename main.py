from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP
from tabulate import tabulate
import logging

print("..................LASITH..................")
print("------------------UCSC-MIS-REG-2023MIS017-----------------------")


def send_port_request():
    userinput_ip_address=input("Enter IP address: ")
    userinput_port=int(input("Enter port range: "))
    port_status = []
    closed_count = 0
    open_count = 0
    for port in range(1,userinput_port+1):
        pkt = sr1(IP(dst=userinput_ip_address)/TCP(dport=port, flags="S"), timeout=4, verbose=0)
        if pkt and pkt.haslayer(TCP) and pkt.getlayer(TCP).flags == "SA":
            port_status.append((port,"open","TCP"))
            open_count += 1
            continue
        pkt_udp = sr1(IP(dst=userinput_ip_address)/UDP(dport=port), timeout=1, verbose=0)
        if pkt_udp and (pkt_udp.haslayer(UDP) or pkt_udp.haslayer(ICMP)):
            if pkt_udp.haslayer(UDP):
                port_status.append((port, "Open", "UDP"))
                open_count += 1
                continue
            elif pkt_udp.haslayer(ICMP):
                icmp_type = pkt_udp[ICMP].type
                if icmp_type == 3:
                    closed_count += 1
                    continue
                else:
                    port_status.append((port, "Open", "ICMP"))
                    open_count += 1
                    continue
    mac_address = get_mac(userinput_ip_address)
    return userinput_ip_address, mac_address, port_status

def get_mac(ip):
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for sent, received in ans:
        return received.hwsrc
    return "MAC address not found"


ip_address, mac_address, port_status=send_port_request()

print("Scan Report", ip_address)
print("Mac Address", mac_address)
for port, state, proto in port_status:
        print(f"{port}\t{state}\t{proto}")


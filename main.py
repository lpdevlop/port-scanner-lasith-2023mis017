from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP
from tabulate import tabulate
import logging

print("..................LASITH..................")
print("------------------2023MIS017-----------------------")


def send_port_request():
    userinput_ip_address=input("Enter IP address: ")
    userinput_port=int(input("Enter port range: "))
    port_status = {}
    for port in range(1,userinput_port+1):
        pkt = sr1(IP(dst=userinput_ip_address)/TCP(dport=port, flags="S"), timeout=4, verbose=0)
        if pkt and pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer.flags == "SA":
               port_status[port] = "port open"
            else:
                port_status[port] = "port close"

    mac_address = get_mac(userinput_ip_address)
    return userinput_ip_address, mac_address, port_status

def get_mac(ip):
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for sent, received in ans:
        return received.hwsrc
    return "MAC address not found"


ip_address, mac_address, port_status=send_port_request()
data = [[port, status] for port, status in port_status.items()]

print("Scan Report", ip_address)
print("Mac Address", mac_address)

print(tabulate(data,headers=["Port","Status"], tablefmt="orgtbl"))


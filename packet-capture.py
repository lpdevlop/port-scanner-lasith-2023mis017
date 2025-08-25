from scapy.all import sniff
from datetime import datetime
import socket
import uuid

from scapy.layers.inet import TCP, UDP, IP, ICMP


def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

def get_mac_address():
    mac = uuid.getnode()
    mac_addr = ':'.join(['{:02x}'.format((mac >> ele) & 0xff)
                         for ele in range(40, -1, -8)])
    return mac_addr

def process_packet(packet):
    time = datetime.now().strftime("%Y/%m/%d %H:%M")
    ip = get_local_ip()
    mac = get_mac_address()

    description = ""

    if packet.haslayer(TCP):
        description = f"TCP Packet. Port: {packet[TCP].dport}"
    elif packet.haslayer(ICMP):
        description = f"ICMP Packet | Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
    elif packet.haslayer(UDP):
        description = f"UDP Packet. Port: {packet[UDP].dport}"
    elif packet.haslayer(IP):
        description = f"IP Packet. Protocol: {packet[IP].proto}"
    else:
        description = "Other Packet Type"

    print(f"Time: {time}, IP: {ip}, Mac Address: {mac},\nRequest: {description}\n")


if __name__ == "__main__":
    print("starting packet capture")
    sniff(prn=process_packet, store=0)

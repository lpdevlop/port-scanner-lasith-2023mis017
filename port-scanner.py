from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import  getmacbyip


def send_port_request(userinput_ip_address, userinput_port):
    mac_address = get_mac(userinput_ip_address)

    port_status = []
    closed_count = 0
    open_count = 0
    for port in range(1,userinput_port+1):
        pkt_tcp = sr1(IP(dst=userinput_ip_address)/TCP(dport=port, flags="S"), timeout=4, verbose=0)
        if pkt_tcp and pkt_tcp.haslayer(TCP) and pkt_tcp.getlayer(TCP).flags == 0x12:  # SYN+ACK
            port_status.append((port, "Open", "TCP"))
            open_count += 1
            send(IP(dst=userinput_ip_address) / TCP(dport=port, flags="R"), verbose=0)
            continue
        elif pkt_tcp and pkt_tcp.haslayer(TCP) and pkt_tcp.getlayer(TCP).flags == 0x14:
            closed_count += 1
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
                    port_status.append((port, "Open", "UDP"))
                    open_count += 1
                    continue
                else:
                    closed_count += 1
                    continue
        pkt_icmp = sr1(IP(dst=userinput_ip_address) / ICMP(), timeout=2, verbose=0)
        if pkt_icmp:
            icmp_type = pkt_icmp[ICMP].type
            icmp_code = pkt_icmp[ICMP].code

            if icmp_type == 3 and icmp_code == 3:
                closed_count += 1
                port_status.append((port, "Closed", "ICMP"))
            else:
                open_count += 1
                port_status.append((port, "Open", "ICMP"))
        else:
            open_count += 1
            port_status.append((port, "Open|Filtered", "No Response"))

    return userinput_ip_address, mac_address, port_status

def get_mac(ip):
    try:
        return getmacbyip(ip) or "MAC address not found (no response)"
    except Exception:
        return "MAC address not found (no response)"



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <target-ip> <max-port>")
        sys.exit(1)

    target_ip = sys.argv[1]
    max_port = int(sys.argv[2])

    ip_address, mac_address, port_status = send_port_request(target_ip, max_port)

    print("Scan Report:", ip_address)
    print("MAC Address:", mac_address)
    for port, state, proto in port_status:
        print(f"{port}\t{state}\t{proto}")


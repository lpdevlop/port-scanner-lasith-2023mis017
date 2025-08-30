import scapy.all as scapy
import datetime

def packet_callback(pkt):
    """Extract relevant details from a captured packet and print it in table format."""
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M")

    # Extract MAC addresses
    if pkt.haslayer(scapy.Ether):
        src_mac = pkt[scapy.Ether].src
        dst_mac = pkt[scapy.Ether].dst
    else:
        src_mac = dst_mac = "-"

    # Extract IP addresses
    if pkt.haslayer(scapy.IP):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
    else:
        src_ip = dst_ip = "-"

    # Determine packet type and details
    if pkt.haslayer(scapy.ICMP):
        icmp_type = pkt[scapy.ICMP].type
        icmp_code = pkt[scapy.ICMP].code
        description = f"ICMP Type {icmp_type} Code {icmp_code}"
        src_port = dst_port = "-"
    elif pkt.haslayer(scapy.TCP):
        description = "TCP Packet"
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP):
        description = "UDP Packet"
        src_port = pkt[scapy.UDP].sport
        dst_port = pkt[scapy.UDP].dport
    else:
        description = "Other Packet"
        src_port = dst_port = "-"

    # Packet size
    packet_size = len(pkt)

    # Print the packet details in a table format
    print("| {:19} | {:15} | {:15} | {:17} | {:17} | {:30} | {:<9} | {:<9} | {:<12} |".format(
        timestamp,
        src_ip,
        dst_ip,
        src_mac,
        dst_mac,
        description,
        str(src_port),
        str(dst_port),
        str(packet_size)
    ))


def sniff_all_interfaces():
    """Capture packets from all available interfaces."""
    interfaces = scapy.get_if_list()
    print(f"Sniffing on interfaces: {', '.join(interfaces)}\n")
    for iface in interfaces:
        scapy.sniff(iface=iface, prn=packet_callback, store=0, timeout=0, promisc=True)


def main():
    # Table header
    print("| {:19} | {:15} | {:15} | {:17} | {:17} | {:30} | {:<9} | {:<9} | {:<12} |".format(
        "Time", "Source IP", "Destination IP", "Source MAC", "Destination MAC",
        "Description", "Src Port", "Dst Port", "Size (Bytes)"
    ))
    print("-" * 170)
    sniff_all_interfaces()


if __name__ == "__main__":
    main()

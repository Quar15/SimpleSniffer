import os, sys
from collections import Counter
from ipaddress import ip_network

from scapy.all import sniff, IP, Raw
from scapy.utils import PcapWriter
import scapy.layers.http as scapy_http

from colorama import init

from config import AP_IP, SUBNET_MASK, COUNT_CONN, \
                    RED, GREEN, RESET, \
                    KEYWORDS

# Get network IP
network_ip = ip_network(f"{AP_IP}/{SUBNET_MASK}", strict=False).network_address
# Initialize counter
packet_counts = Counter()
packet_id = 0
# Initialize writers
http_writer = PcapWriter("http.cap", append=True, sync=True)
keyword_writer = PcapWriter("keyword.cap", append=True, sync=True)
https_writer = PcapWriter("https.cap", append=True, sync=True)


def is_in_network(IP):
    net_ip = ip_network(f"{IP}/{SUBNET_MASK}", strict=False).network_address
    # print(f"@INFO: {net_ip} == {network_ip} -> {net_ip == network_ip}")
    return (net_ip == network_ip)



def handle_package(pkt):
    global packet_id
    # Get source and destination IP from packet
    src_ip = pkt[0][1].src
    dst_ip = pkt[0][1].dst
    if COUNT_CONN:
        packet_counts.update([tuple(sorted([src_ip, dst_ip]))])

    # Save packet if it is source ip is in AP network
    if is_in_network(src_ip):
        # and if packet has HTTPRequest and Raw layer
        if pkt.haslayer(scapy_http.HTTPRequest) and pkt.haslayer(Raw):
            # If packet has not encrypted HTTPRequest it is a HTTP request
            http_writer.write(pkt)

            # Decode basic data from packet
            url = pkt[scapy_http.HTTPRequest].Host.decode() + pkt[scapy_http.HTTPRequest].Path.decode()
            ip = pkt[IP].src
            method = pkt[scapy_http.HTTPRequest].Method.decode()

            print(f"{GREEN}[+] {ip} requested {url} with {method}{RESET}")

            # Load raw data from packet and search if it has any keywords in it
            load = pkt[Raw].load
            for w in KEYWORDS:
                if w in str(load):
                    keyword_writer.write(pkt)
                    print(f"{RED}[!] Keyword found -- {load.decode()}{RESET}")
                    break
        else:
            pkt.show2()
            https_writer.write(pkt)

    packet_id += 1
    return f"Packet #{packet_id}: {src_ip} ==> {dst_ip}"


def main():
    # Initialize colorama
    init()
    # Start sniffing
    sniff(filter=f"ip and ( port 80 or port 443 ) and not ip src {AP_IP}", prn=handle_package)
    if COUNT_CONN:
        # Print out packet count per A <--> Z address pair
        print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
    
    print("@INFO: Sniffer shutdown")


if __name__ == "__main__":
    main()
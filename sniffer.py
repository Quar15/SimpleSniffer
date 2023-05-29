import os, sys
from collections import Counter
from scapy.all import sniff, IP, Raw
from scapy.utils import PcapWriter
import scapy.layers.http as scapy_http

from colorama import init, Fore

COUNT_CONN = False

init()
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

packet_counts = Counter()
packet_id = 0
http_writer = PcapWriter("http.cap", append=True, sync=True)
keyword_writer = PcapWriter("keyword.cap", append=True, sync=True)
https_writer = PcapWriter("https.cap", append=True, sync=True)

WORDS = ["password", "user", "username", "login", "pass", "Username", "Password", "User", "Email"]


def handle_package(pkt):
    global packet_id
    # Create tuple of Src/Dst
    key = tuple(sorted([pkt[0][1].src, pkt[0][1].dst]))
    if COUNT_CONN:
        packet_counts.update([key])

    # pkt.show()

    if pkt.haslayer(scapy_http.HTTPRequest):
        if pkt.haslayer(Raw):
            if pkt.dport == 80:
                http_writer.write(pkt)
            elif pkt.dport == 443:
                https_writer.write(pkt)
            else:
                print("[@INFO] - Weird packet spoofed")

            url = pkt[scapy_http.HTTPRequest].Host.decode() + pkt[scapy_http.HTTPRequest].Path.decode()
            ip = pkt[IP].src
            method = pkt[scapy_http.HTTPRequest].Method.decode()

            print(f"{GREEN}[+] {ip} requested {url} with {method}{RESET}")

            load = pkt[Raw].load
            for w in WORDS:
                if w in str(load):
                    keyword_writer.write(pkt)
                    print(f"{RED}[!] Keyword found in packet -- {load.decode()}{RESET}")
                    break

    packet_id += 1
    return f"Packet #{packet_id}: {key[0]} ==> {key[1]}"


def main():
    # Start sniffing
    sniff(filter="ip and ( port 80 or port 443 )", prn=handle_package)
    # Print out packet count per A <--> Z address pair
    if COUNT_CONN:
        print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
    print("@INFO: Sniffer shutdown")


if __name__ == "__main__":
    main()
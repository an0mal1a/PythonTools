import scapy.all as scapy
import argparse
import signal
import sys

debug = False

def def_handler(sig, frame):
    print("Forcibly Exiting Program", "Error")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser("Tool to detect hosts in a network using ARP")
    parser.add_argument("-t", "--target", required=True, dest="target", help="Specify the host or the hosts range to scan (Ex: 192.168.1.0/24 | 192.168.1.1)")
    return parser.parse_args().target

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_packet = broadcast_packet/arp_packet
    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False)

    response = answered.summary()
    if response:
        print(response)

def main():
    target = get_arguments()
    scan(target)

if __name__ == "__main__":
    main()
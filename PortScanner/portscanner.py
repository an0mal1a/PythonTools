from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import argparse
import socket
import signal
import sys

open_sockets = []

def def_handler(sig, frame):
    print("\n[! Exiting Scanning>] Cleaning threads and open sockets\n")

    for socket in open_sockets:
        socket.close()

    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="IP Addres to scan (Ex: -t 192.168.1.1)")
    parser.add_argument("-p", "--ports", dest="range", help="Specify the port range to scan in the target (Ex: -p 0-65535) - Default: 0-500")
    options = parser.parse_args()

    return options.target, options.range

def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    open_sockets.append(s)
    return s

def port_scanner(host, port):
    s = create_socket()
    try:
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
        r = s.recv(1024)
        #r = r.decode(errors="ignore").split("\n")[0]
        r = r.decode(errors="ignore").split("\n")

        if r:
            print(colored(f"\n[! Scanning >] El puerto {port} está abierto", "green"))
            for line in r:
                print(colored(line, "grey"))

        else:
            print(colored(f"\n[! Scanning >] El puerto {port} está abierto\n", "green"))

    except (socket.timeout, ConnectionRefusedError):
        pass

    finally:
        s.close()

def make_scan(port_list, target):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(target, port), port_list)

def verify_ports(ports_str):
    if not ports_str:
        ports_str = "1-500"

    try:
        if "-" in ports_str:
            start_port, end_port = map(int, ports_str.split("-"))
            if start_port < 0 or end_port > 65535 or start_port > end_port:
                raise ValueError("El rango de puertos es inválido")
            port_list = range(start_port, end_port + 1)
        elif ',' in ports_str:
            port_list = [int(p) for p in ports_str.split(",") if p.isdigit() and 0 <= int(p) <= 65535]
            if not port_list:
                raise ValueError("Lista de puertos inválida o vadia")
        else:
            port_list = [int(ports_str)]
    except ValueError as e:
        print(f"Error al procesar el rango de puertos: {e}")
        return

    return port_list


def main():
    target, ports_str = get_arguments()
    port_list = verify_ports(ports_str)
    make_scan(port_list, target)


if __name__ == "__main__":
    main()
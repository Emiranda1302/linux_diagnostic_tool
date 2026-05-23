from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

print("[*] Capturando 10 paquetes...\n")

sniff(prn=packet_callback, count=10)

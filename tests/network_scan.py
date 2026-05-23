from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

target_ip = "192.168.100.0/24"

arp = ARP(pdst=target_ip)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether / arp

print("[*] Escaneando red...\n")

result = srp(packet, timeout=2, verbose=0)[0]

clients = []

for sent, received in result:

    mac = received.hwsrc

    try:
        vendor = MacLookup().lookup(mac)
    except:
        vendor = "Unknown"

    clients.append({
        "ip": received.psrc,
        "mac": mac,
        "vendor": vendor
    })

print("Dispositivos encontrados:\n")

for client in clients:
    print(
        f"IP: {client['ip']} | "
        f"MAC: {client['mac']} | "
        f"Vendor: {client['vendor']}"
    )

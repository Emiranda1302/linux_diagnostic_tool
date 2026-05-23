# Scapy Implementation Guide

## WiFi Scanning with Scapy

```python
from scapy.all import ARP, Ether, srp

# ARP Scan for network discovery
def scan_network(network_range):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
    answered, _ = srp(arp_request, timeout=2, verbose=False)
    
    devices = []
    for sent, received in answered:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
    return devices
```

## Port Scanning with Scapy

```python
from scapy.all import IP, TCP, sr1

def scan_port(target, port):
    packet = IP(dst=target) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=2, verbose=False)
    
    if response and response[TCP].flags == 0x12:  # SYN-ACK
        return "OPEN"
    return "CLOSED"
```

## Device Classification

Uses MAC vendor lookup + port fingerprinting:
- Printers: ports 9100, 631, 515
- Cameras: ports 554 (RTSP), 8080
- Routers: ports 80, 443
- NAS: ports 445 (SMB), 139


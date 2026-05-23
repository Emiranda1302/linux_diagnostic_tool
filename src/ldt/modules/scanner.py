"""
Port Scanner Module - Detect open ports and services using Scapy
"""

import logging
from typing import List, Dict, Any
from scapy.all import IP, TCP, sr1, conf
import socket
import json

logger = logging.getLogger(__name__)

# Common ports and their services
COMMON_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    5000: 'Flask/Dev',
    3000: 'Node.js',
    27017: 'MongoDB',
    9200: 'Elasticsearch',
    5900: 'VNC',
    139: 'NetBIOS',
    445: 'SMB',
    25: 'SMTP',
    53: 'DNS',
    123: 'NTP',
    67: 'DHCP',
    161: 'SNMP'
}


class PortScanner:
    """Scan for open ports on target host"""
    
    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.results = []
    
    def scan_host(self, target: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """
        Scan target host for open ports
        
        Args:
            target: Target IP address
            ports: List of ports to scan (default: common ports)
        
        Returns:
            List of open ports with service info
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        open_ports = []
        
        print(f"\n🔍 Scanning {target} for open ports...")
        
        for port in ports:
            try:
                # Create TCP SYN packet
                packet = IP(dst=target) / TCP(dport=port, flags="S")
                
                # Send packet and wait for response
                response = sr1(packet, timeout=self.timeout, verbose=False)
                
                if response:
                    if response.haslayer(TCP):
                        tcp_layer = response[TCP]
                        
                        # Check if port is open (SYN-ACK response)
                        if tcp_layer.flags == 0x12:  # SYN-ACK
                            service = COMMON_PORTS.get(port, 'Unknown')
                            
                            # Try to get service version
                            banner = self._get_service_banner(target, port)
                            
                            port_info = {
                                'port': port,
                                'status': 'OPEN',
                                'service': service,
                                'banner': banner
                            }
                            
                            open_ports.append(port_info)
                            print(f"  ✓ Port {port:5d} - {service:<15} - OPEN")
                        
                        # Check if port is closed (RST response)
                        elif tcp_layer.flags == 0x14:  # RST
                            pass  # Port closed, skip
            
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
                continue
        
        self.results = open_ports
        return open_ports
    
    def _get_service_banner(self, target: str, port: int) -> str:
        """Get service banner/version info"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))
            
            # Try to get banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner[:50] if banner else ""
        except:
            return ""
    
    def analyze_vulnerabilities(self, port_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze port for known vulnerabilities"""
        port = port_info['port']
        service = port_info['service']
        banner = port_info.get('banner', '')
        
        analysis = {
            'port': port,
            'service': service,
            'risks': []
        }
        
        # Known vulnerabilities by service
        if port == 23:
            analysis['risks'].append("⚠️  Telnet - unencrypted, use SSH instead")
        elif port == 80 and service == 'HTTP':
            analysis['risks'].append("⚠️  HTTP without encryption - use HTTPS")
        elif port == 3306 and service == 'MySQL':
            analysis['risks'].append("⚠️  MySQL exposed - should be firewalled")
            analysis['risks'].append("💡 Verify authentication is enabled")
        elif port == 5432 and service == 'PostgreSQL':
            analysis['risks'].append("⚠️  PostgreSQL exposed - should be firewalled")
        elif port == 27017 and service == 'MongoDB':
            analysis['risks'].append("⚠️  MongoDB exposed - check if auth enabled")
        elif port == 6379 and service == 'Redis':
            analysis['risks'].append("⚠️  Redis exposed - should be firewalled")
        elif port == 445 and service == 'SMB':
            analysis['risks'].append("⚠️  SMB exposed - high exploitation risk")
        elif port == 139 and service == 'NetBIOS':
            analysis['risks'].append("⚠️  NetBIOS exposed - information disclosure risk")
        
        # Check banner for version info
        if 'Apache' in banner:
            analysis['banner_info'] = f"Apache detected - {banner.split()[2] if len(banner.split()) > 2 else 'version unknown'}"
        elif 'nginx' in banner.lower():
            analysis['banner_info'] = "Nginx detected"
        
        return analysis
    
    def scan_network(self, network_range: str) -> List[Dict[str, Any]]:
        """
        Scan entire network range
        
        Args:
            network_range: Network range (e.g., 192.168.1.0/24)
        
        Returns:
            List of hosts with open ports
        """
        from scapy.all import IP as IP_net
        import ipaddress
        
        results = []
        
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            print(f"\n🌐 Scanning network {network_range}...")
            
            for ip in list(network.hosts())[:254]:  # Limit scan
                ip_str = str(ip)
                
                # Check if host is alive first
                packet = IP(dst=ip_str) / TCP(dport=80, flags="S")
                response = sr1(packet, timeout=1, verbose=False)
                
                if response:
                    open_ports = self.scan_host(ip_str, [22, 80, 443, 3306, 5432])
                    
                    if open_ports:
                        results.append({
                            'host': ip_str,
                            'open_ports': open_ports
                        })
        
        except Exception as e:
            logger.error(f"Network scan error: {e}")
        
        return results


def register_parser(subparsers):
    """Register port scanner subcommand"""
    parser = subparsers.add_parser("ports", help="Port scanner")
    parser.add_argument(
        "target",
        type=str,
        help="Target IP address or network range"
    )
    parser.add_argument(
        "--ports",
        type=str,
        help="Comma-separated ports to scan (default: common ports)"
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze for vulnerabilities"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="Timeout per port in seconds"
    )
    parser.set_defaults(func=run)


def run(args):
    """Execute port scan"""
    scanner = PortScanner(timeout=args.timeout)
    
    # Parse ports if provided
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("❌ Invalid port format. Use: 22,80,443")
            return
    
    print("\n" + "="*70)
    print("🔍 Port Scanner")
    print("="*70)
    
    # Check if target is network or single host
    if '/' in args.target:
        # Network scan
        results = scanner.scan_network(args.target)
        
        print(f"\nFound {len(results)} hosts with open ports:\n")
        print(f"{'Host':<15} {'Open Ports':<30} {'Services':<40}")
        print("-" * 85)
        
        for result in results:
            host = result['host']
            open_ports = [str(p['port']) for p in result['open_ports']]
            services = [p['service'] for p in result['open_ports']]
            
            print(f"{host:<15} {','.join(open_ports):<30} {','.join(services):<40}")
    else:
        # Single host scan
        open_ports = scanner.scan_host(args.target, ports)
        
        print(f"\nScan Results for {args.target}:\n")
        
        if not open_ports:
            print("✓ No open ports detected (host may be down or filtered)")
            return
        
        print(f"{'Port':<8} {'Service':<20} {'Banner':<40}")
        print("-" * 68)
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            banner = port_info.get('banner', '')[:39]
            
            print(f"{port:<8} {service:<20} {banner:<40}")
        
        # Analyze if requested
        if args.analyze:
            print("\n" + "="*70)
            print("🔒 Vulnerability Analysis")
            print("="*70 + "\n")
            
            for port_info in open_ports:
                analysis = scanner.analyze_vulnerabilities(port_info)
                print(f"Port {analysis['port']} - {analysis['service']}")
                
                if analysis['risks']:
                    for risk in analysis['risks']:
                        print(f"  {risk}")
                else:
                    print(f"  ✓ No known vulnerabilities")
                
                if 'banner_info' in analysis:
                    print(f"  ℹ️  {analysis['banner_info']}")
                print()

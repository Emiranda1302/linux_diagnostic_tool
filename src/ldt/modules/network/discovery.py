"""
Device Discovery Module - Detect devices on local network using ARP
"""

import logging
from typing import List, Dict, Any
from scapy.all import ARP, Ether, srp, conf
import subprocess
import re
from mac_vendor_lookup import MacLookup

logger = logging.getLogger(__name__)

# Common device types by port and service
DEVICE_SIGNATURES = {
    'printer': {
        'ports': [9100, 515, 631, 3001],
        'services': ['lpd', 'lpr', 'ipp', 'http'],
        'keywords': ['hp', 'xerox', 'brother', 'ricoh', 'canon', 'printer']
    },
    'router': {
        'ports': [80, 443, 8080, 8443],
        'services': ['http', 'https'],
        'keywords': ['router', 'gateway', 'admin']
    },
    'camera': {
        'ports': [80, 443, 8080, 5000, 554],
        'services': ['http', 'https', 'rtsp'],
        'keywords': ['camera', 'webcam', 'axis', 'dahua', 'hikvision']
    },
    'nas': {
        'ports': [445, 139, 21, 22, 8080],
        'services': ['smb', 'ftp', 'ssh', 'http'],
        'keywords': ['nas', 'synology', 'qnap', 'seagate']
    },
    'iot': {
        'ports': [1883, 8883, 5000, 8000],
        'services': ['mqtt', 'mqtt-s', 'http'],
        'keywords': ['iot', 'smart', 'mqtt', 'zigbee']
    }
}


class DeviceDiscovery:
    """Discover devices on local network"""
    
    def __init__(self):
        self.devices = []
        self.mac_lookup = MacLookup()
    
    def scan_network(self, network_range: str) -> List[Dict[str, Any]]:
        """
        Scan local network for devices using ARP
        
        Args:
            network_range: Network range (e.g., 192.168.1.0/24)
        
        Returns:
            List of discovered devices
        """
        print(f"\n🔍 Scanning network {network_range}...")
        
        # Create ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
        
        try:
            # Send ARP request and get responses
            answered, _ = srp(arp_request, timeout=2, verbose=False)
            
            devices = []
            for sent, received in answered:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._get_vendor(received.hwsrc),
                    'hostname': self._get_hostname(received.psrc),
                    'online': True
                }
                devices.append(device)
            
            self.devices = devices
            return devices
        
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
            return []
    
    def _get_vendor(self, mac: str) -> str:
        """Get device vendor from MAC address"""
        try:
            return self.mac_lookup.lookup(mac)
        except:
            return "Unknown"
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname from IP"""
        try:
            result = subprocess.run(
                ["host", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                # Extract hostname from output
                match = re.search(r'pointer ([\w\-\.]+)', result.stdout)
                if match:
                    return match.group(1)
        except:
            pass
        
        return "Unknown"
    
    def classify_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Classify device type based on ports and services"""
        ip = device['ip']
        vendor = device.get('vendor', '').lower()
        
        device_type = "Generic"
        confidence = 0
        vulnerabilities = []
        
        # Check vendor name
        for dev_type, signature in DEVICE_SIGNATURES.items():
            for keyword in signature['keywords']:
                if keyword in vendor.lower():
                    device_type = dev_type
                    confidence = 0.8
                    break
        
        # Check for default credentials vulnerabilities
        if device_type == 'printer':
            vulnerabilities.append("⚠️  Check for default printer admin credentials")
            vulnerabilities.append("💡 Default: admin/admin or admin/password")
        
        elif device_type == 'router':
            vulnerabilities.append("⚠️  Router exposed - verify strong password")
            vulnerabilities.append("💡 Check for firmware updates")
            vulnerabilities.append("⚠️  Disable WPS if enabled")
        
        elif device_type == 'camera':
            vulnerabilities.append("⚠️  IP Camera detected - high security risk")
            vulnerabilities.append("💡 Verify strong authentication")
            vulnerabilities.append("⚠️  Disable RTSP if not needed")
        
        elif device_type == 'nas':
            vulnerabilities.append("⚠️  NAS exposed - verify access controls")
            vulnerabilities.append("💡 Enable encryption for data transfer")
        
        elif device_type == 'iot':
            vulnerabilities.append("⚠️  IoT device - often has outdated software")
            vulnerabilities.append("💡 Check for security updates")
            vulnerabilities.append("⚠️  Isolate on separate network if possible")
        
        return {
            'device': device,
            'type': device_type,
            'confidence': confidence,
            'vulnerabilities': vulnerabilities
        }
    
    def scan_device_ports(self, device_ip: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Scan specific device for open ports"""
        from scapy.all import IP, TCP
        
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 8080, 9100, 631, 445, 139]
        
        open_ports = []
        
        for port in ports:
            try:
                packet = IP(dst=device_ip) / TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=False)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append({
                            'port': port,
                            'status': 'open'
                        })
            except:
                pass
        
        return open_ports
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate discovery report"""
        report = {
            'total_devices': len(self.devices),
            'devices': [],
            'summary': {}
        }
        
        device_types = {}
        
        for device in self.devices:
            classification = self.classify_device(device)
            device_report = classification['device'].copy()
            device_report['type'] = classification['type']
            device_report['vulnerabilities'] = classification['vulnerabilities']
            
            report['devices'].append(device_report)
            
            # Count device types
            dev_type = classification['type']
            device_types[dev_type] = device_types.get(dev_type, 0) + 1
        
        report['summary'] = device_types
        
        return report


def register_parser(subparsers):
    """Register device discovery subcommand"""
    parser = subparsers.add_parser("discovery", help="Discover devices on network")
    parser.add_argument(
        "network",
        type=str,
        help="Network range (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze device vulnerabilities"
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Scan ports on discovered devices"
    )
    parser.set_defaults(func=run)


def run(args):
    """Execute device discovery"""
    discovery = DeviceDiscovery()
    
    print("\n" + "="*70)
    print("🔎 Device Discovery Scanner")
    print("="*70)
    
    # Scan network
    devices = discovery.scan_network(args.network)
    
    if not devices:
        print("\n❌ No devices found on network")
        return
    
    # Display results
    print(f"\n✓ Found {len(devices)} device(s):\n")
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor':<30} {'Hostname':<20}")
    print("-" * 85)
    
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        vendor = device['vendor'][:29] if device['vendor'] else 'Unknown'
        hostname = device['hostname'][:19] if device['hostname'] else 'Unknown'
        
        print(f"{ip:<15} {mac:<20} {vendor:<30} {hostname:<20}")
    
    # Analyze if requested
    if args.analyze:
        print("\n" + "="*70)
        print("🔒 Device Analysis")
        print("="*70 + "\n")
        
        for device in devices:
            classification = discovery.classify_device(device)
            
            print(f"IP: {device['ip']}")
            print(f"  Vendor: {device['vendor']}")
            print(f"  Type: {classification['type'].upper()}")
            
            if classification['vulnerabilities']:
                print(f"  Vulnerabilities:")
                for vuln in classification['vulnerabilities']:
                    print(f"    {vuln}")
            else:
                print(f"  ✓ No major issues detected")
            
            print()
    
    # Scan ports if requested
    if args.ports:
        print("\n" + "="*70)
        print("🔌 Port Scan Results")
        print("="*70 + "\n")
        
        for device in devices[:5]:  # Limit to first 5 devices
            open_ports = discovery.scan_device_ports(device['ip'])
            
            if open_ports:
                print(f"{device['ip']}: ", end="")
                print(f"Open ports: {[p['port'] for p in open_ports]}")
            else:
                print(f"{device['ip']}: No open ports detected")
    
    # Generate report
    report = discovery.generate_report()
    print(f"\n📊 Summary: {report['summary']}")

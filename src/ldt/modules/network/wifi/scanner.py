"""
WiFi Scanner Module - Detect wireless networks using Scapy
"""

import logging
from typing import List, Dict, Any
from scapy.all import ARP, Ether, srp, sniff, conf
import subprocess
import re

logger = logging.getLogger(__name__)


class WiFiScanner:
    """Scan for WiFi networks and analyze security"""
    
    def __init__(self):
        self.networks = []
    
    def scan_networks(self, interface: str = None) -> List[Dict[str, Any]]:
        """
        Scan for WiFi networks using system tools
        
        Args:
            interface: Network interface (e.g., wlan0)
        
        Returns:
            List of networks with SSID, channel, security, signal strength
        """
        networks = []
        
        try:
            # Use nmcli (NetworkManager CLI) to scan
            result = subprocess.run(
                ["nmcli", "device", "wifi", "list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                networks = self._parse_nmcli_output(result.stdout)
            else:
                logger.warning("nmcli scan failed, trying iwlist")
                networks = self._scan_with_iwlist(interface)
        
        except FileNotFoundError:
            logger.error("nmcli not found. Install with: sudo apt install network-manager")
            return []
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
            return []
        
        self.networks = networks
        return networks
    
    def _parse_nmcli_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmcli output"""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                network = {
                    'ssid': parts[0],
                    'bssid': parts[1] if len(parts) > 1 else 'N/A',
                    'mode': parts[2] if len(parts) > 2 else 'N/A',
                    'channel': parts[3] if len(parts) > 3 else '0',
                    'rate': parts[4] if len(parts) > 4 else '0',
                    'signal': self._extract_signal(line),
                    'bars': self._extract_bars(line),
                    'security': self._extract_security(line)
                }
                networks.append(network)
        
        return networks
    
    def _scan_with_iwlist(self, interface: str = None) -> List[Dict[str, Any]]:
        """Fallback to iwlist for WiFi scanning"""
        networks = []
        
        if not interface:
            interface = self._get_wifi_interface()
        
        if not interface:
            logger.error("No WiFi interface found")
            return []
        
        try:
            result = subprocess.run(
                ["sudo", "iwlist", interface, "scan"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                networks = self._parse_iwlist_output(result.stdout)
        
        except Exception as e:
            logger.error(f"iwlist scan error: {e}")
        
        return networks
    
    def _parse_iwlist_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse iwlist scan output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            if 'SSID:' in line:
                if current_network:
                    networks.append(current_network)
                ssid = re.search(r'SSID:"([^"]*)"', line)
                current_network = {
                    'ssid': ssid.group(1) if ssid else 'Hidden',
                    'channel': 'N/A',
                    'signal': 'N/A',
                    'security': 'N/A'
                }
            elif 'Frequency:' in line:
                current_network['frequency'] = line.split(':')[1].strip()
            elif 'Signal level' in line:
                signal = re.search(r'(-\d+) dBm', line)
                current_network['signal'] = signal.group(1) if signal else 'N/A'
            elif 'Encryption key:' in line:
                current_network['encryption'] = 'Yes' if 'on' in line else 'No'
        
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def _get_wifi_interface(self) -> str:
        """Get WiFi interface name"""
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                if 'wlan' in line or 'wlp' in line:
                    return re.search(r'(wlan\d+|wlp\d+\w\d+)', line).group(1)
        except:
            pass
        
        return None
    
    def _extract_signal(self, line: str) -> str:
        """Extract signal strength from line"""
        match = re.search(r'(\d+)%', line)
        return match.group(1) if match else 'N/A'
    
    def _extract_bars(self, line: str) -> str:
        """Extract signal bars from line"""
        match = re.search(r'(▂▄▆█)', line)
        return match.group(1) if match else '▂'
    
    def _extract_security(self, line: str) -> str:
        """Extract security type from line"""
        if 'WPA2' in line or 'WPA3' in line:
            return 'WPA2/3'
        elif 'WPA' in line:
            return 'WPA'
        elif 'WEP' in line:
            return 'WEP'
        else:
            return 'Open'
    
    def analyze_security(self, network: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security of a network"""
        security = network.get('security', 'Open')
        
        analysis = {
            'ssid': network.get('ssid'),
            'security_type': security,
            'vulnerabilities': []
        }
        
        # Check for vulnerabilities
        if security == 'Open':
            analysis['vulnerabilities'].append("⚠️  No encryption - CRITICAL")
        elif security == 'WEP':
            analysis['vulnerabilities'].append("⚠️  WEP is weak - use WPA2/3")
        elif security == 'WPA':
            analysis['vulnerabilities'].append("⚠️  WPA v1 is deprecated - upgrade to WPA2/3")
        
        # Check for weak SSID
        ssid = network.get('ssid', '').lower()
        if 'admin' in ssid or 'default' in ssid or 'test' in ssid:
            analysis['vulnerabilities'].append("⚠️  SSID reveals device type")
        
        # Check signal strength
        try:
            signal = int(network.get('signal', '0'))
            if signal > -50:
                analysis['signal_strength'] = "Strong"
            elif signal > -70:
                analysis['signal_strength'] = "Good"
            else:
                analysis['signal_strength'] = "Weak"
        except:
            analysis['signal_strength'] = "Unknown"
        
        return analysis


def register_parser(subparsers):
    """Register WiFi scanner subcommand"""
    parser = subparsers.add_parser("wifi", help="WiFi network scanner")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan for WiFi networks"
    )
    parser.add_argument(
        "--interface",
        type=str,
        help="WiFi interface (e.g., wlan0)"
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze security of networks"
    )
    parser.set_defaults(func=run)


def run(args):
    """Execute WiFi scan"""
    scanner = WiFiScanner()
    
    print("\n" + "="*70)
    print("📡 WiFi Network Scanner")
    print("="*70 + "\n")
    
    # Scan networks
    networks = scanner.scan_networks(args.interface)
    
    if not networks:
        print("❌ No WiFi networks found or scan failed")
        print("   Make sure you have permission and correct interface")
        return
    
    # Display results
    print(f"Found {len(networks)} WiFi network(s):\n")
    print(f"{'SSID':<30} {'BSSID':<20} {'Channel':<10} {'Signal':<10} {'Security':<15}")
    print("-" * 85)
    
    for net in networks:
        ssid = net.get('ssid', 'Hidden')[:29]
        bssid = net.get('bssid', 'N/A')[:19]
        channel = str(net.get('channel', 'N/A'))[:9]
        signal = str(net.get('signal', 'N/A'))[:9]
        security = net.get('security', 'Unknown')[:14]
        
        print(f"{ssid:<30} {bssid:<20} {channel:<10} {signal:<10} {security:<15}")
    
    # Analyze if requested
    if args.analyze:
        print("\n" + "="*70)
        print("🔒 Security Analysis")
        print("="*70 + "\n")
        
        for net in networks:
            analysis = scanner.analyze_security(net)
            print(f"SSID: {analysis['ssid']}")
            print(f"  Security Type: {analysis['security_type']}")
            print(f"  Signal Strength: {analysis.get('signal_strength', 'Unknown')}")
            
            if analysis['vulnerabilities']:
                print(f"  Vulnerabilities:")
                for vuln in analysis['vulnerabilities']:
                    print(f"    {vuln}")
            else:
                print(f"  ✓ No major vulnerabilities detected")
            print()

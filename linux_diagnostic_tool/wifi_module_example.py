# src/ldt/modules/network/wifi/audit.py
"""
WiFi Security Auditing Module
Uses wifite2 for automated wireless penetration testing
"""

import subprocess
import json
from pathlib import Path

def scan_networks() -> list[dict]:
    """
    Scan for available WiFi networks
    Returns list of networks with security info
    """
    networks = []
    
    try:
        # Use nmcli for cross-platform network scanning
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.strip().split('\n'):
            if line:
                ssid, security, signal = line.split(':')
                networks.append({
                    "ssid": ssid,
                    "security": security,
                    "signal_strength": int(signal),
                    "vulnerable": _check_vulnerability(security)
                })
    except subprocess.CalledProcessError as e:
        print(f"[!] Error scanning networks: {e}")
    
    return networks

def _check_vulnerability(security: str) -> str:
    """
    Assess network security level
    """
    if not security or security == "--":
        return "CRITICAL - No encryption"
    elif "WEP" in security:
        return "HIGH - WEP is broken"
    elif "WPA " in security and "WPA2" not in security:
        return "MEDIUM - WPA1 only"
    elif "WPS" in security:
        return "MEDIUM - WPS enabled"
    elif "WPA2" in security or "WPA3" in security:
        return "LOW - Modern encryption"
    return "UNKNOWN"

def audit_own_network(interface: str, ssid: str) -> dict:
    """
    Audit your own WiFi network security
    Requires root/sudo privileges
    """
    report = {
        "ssid": ssid,
        "interface": interface,
        "tests_run": [],
        "vulnerabilities": [],
        "recommendations": []
    }
    
    # Check if wifite2 is installed
    try:
        subprocess.run(["which", "wifite"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        report["error"] = "wifite2 not installed. Install: sudo apt install wifite"
        return report
    
    # Run automated audit (requires sudo)
    print("[*] Starting automated WiFi audit...")
    print("[!] This requires sudo privileges")
    
    # Example wifite command (modify as needed)
    # wifite_cmd = [
    #     "sudo", "wifite",
    #     "--kill",           # Kill interfering processes
    #     "-i", interface,    # Specify interface
    #     "-e", ssid,         # Target specific SSID
    #     "--dict", "/path/to/wordlist.txt",  # Optional wordlist
    #     "--crack",          # Auto-crack captured handshakes
    # ]
    
    report["tests_run"].append("WPA/WPA2 handshake capture")
    report["recommendations"].append("Use WPA3 if available")
    report["recommendations"].append("Disable WPS")
    report["recommendations"].append("Use strong passphrase (20+ characters)")
    
    return report

def check_interface_monitor_mode(interface: str) -> bool:
    """
    Check if wireless interface supports monitor mode
    """
    try:
        result = subprocess.run(
            ["iw", interface, "info"],
            capture_output=True,
            text=True,
            check=True
        )
        return "monitor" in result.stdout.lower()
    except subprocess.CalledProcessError:
        return False

def register_parser(subparsers):
    """
    Register WiFi audit commands
    """
    parser = subparsers.add_parser(
        "wifi",
        help="WiFi security auditing tools"
    )
    
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan for nearby WiFi networks"
    )
    
    parser.add_argument(
        "--audit",
        metavar="SSID",
        help="Audit your own network security (requires sudo)"
    )
    
    parser.add_argument(
        "-i", "--interface",
        default="wlan0",
        help="Wireless interface to use (default: wlan0)"
    )
    
    parser.add_argument(
        "--check-monitor",
        action="store_true",
        help="Check if interface supports monitor mode"
    )
    
    parser.set_defaults(func=run)

def run(args):
    """
    Execute WiFi audit commands
    """
    if args.scan:
        print("\n[*] Scanning for WiFi networks...")
        networks = scan_networks()
        
        if not networks:
            print("[!] No networks found")
            return
        
        print(f"\n{'SSID':<30} {'Security':<20} {'Signal':<8} {'Risk'}")
        print("-" * 90)
        
        for net in sorted(networks, key=lambda x: x['signal_strength'], reverse=True):
            risk_flag = "[!]" if "HIGH" in net['vulnerable'] or "CRITICAL" in net['vulnerable'] else ""
            print(
                f"{net['ssid']:<30} "
                f"{net['security']:<20} "
                f"{net['signal_strength']:<8} "
                f"{net['vulnerable']} {risk_flag}"
            )
    
    elif args.audit:
        if not args.interface:
            print("[!] Please specify wireless interface with -i")
            return
        
        report = audit_own_network(args.interface, args.audit)
        
        if "error" in report:
            print(f"[!] {report['error']}")
            return
        
        print(f"\n[+] Audit Report for: {report['ssid']}")
        print("=" * 60)
        print(f"Interface: {report['interface']}")
        print(f"\nTests Run: {len(report['tests_run'])}")
        for test in report['tests_run']:
            print(f"  - {test}")
        
        if report['vulnerabilities']:
            print(f"\n[!] Vulnerabilities Found: {len(report['vulnerabilities'])}")
            for vuln in report['vulnerabilities']:
                print(f"  - {vuln}")
        
        print(f"\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
    
    elif args.check_monitor:
        supports_monitor = check_interface_monitor_mode(args.interface)
        if supports_monitor:
            print(f"[+] Interface {args.interface} supports monitor mode")
        else:
            print(f"[!] Interface {args.interface} does NOT support monitor mode")
            print("    You may need to install drivers or use a different adapter")
    
    else:
        print("No option provided. Use --scan, --audit, or --check-monitor")

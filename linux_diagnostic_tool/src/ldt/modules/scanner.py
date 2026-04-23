import itertools
import threading
import sys
import time


import json
from datetime import datetime
from pathlib import Path
import socket
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


"""IMPORT ALL FUNCTIONS FROM LDT"""

from ldt.modules.system import (
    get_running_processes,
    get_cpu_info,
    get_memory_info,
    get_listening_ports,
    get_failed_logins
)
from ldt.modules.network.interfaces import get_inter
from ldt.modules.network.connections import get_active_conec
from ldt.modules.forensics import (
    check_cron_persistence,
    check_bashrc_persistence,
    find_suid_binaries
)
from ldt.utils.whitelist import (
    is_suid_suspicious,
    is_cron_suspicious,
    is_bashrc_suspicious,
    is_connection_suspicious,
    SUSPICIOUS_PATHS,
    CRITICAL_BINARIES
)

logger=logging.getLogger(__name__)

class AdvancedScanner:
    """System scanner with multithreading and filtering"""
    
    def __init__(self, max_workers=4):
        self.max_workers = max_workers
        self.baseline_dir = Path("baselines")
        self.hash_dir = Path("hashes")
        self.baseline_dir.mkdir(exist_ok=True)
        self.hash_dir.mkdir(exist_ok=True)
        self.loading=False
    
    def spiner_task(self,mensaje="Procesing"):
        ciclo = itertools.cycle(["|", "/", "-", "\\"])
        while self.loading:
            char = next(ciclo)
            sys.stdout.write(f"\r[*] {mensaje}... {char}")
            sys.stdout.flush()
            time.sleep(0.1)
        
        # Limpieza al terminar
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.write(f"[+] {mensaje} completado.\n")
        sys.stdout.write("\a") # Sonido final (fuera del bucle)
        sys.stdout.flush()

    def _scan_system(self):
        """Scan system metrics"""
        try:
            return {
                "processes": get_running_processes(),
                "cpu": get_cpu_info(),
                "memory": get_memory_info(),
            }
        except Exception as e:
            logger.error(f"System scan failed: {e}")
            return {}
    
    def _scan_network(self):
        """Scan network info"""
        try:
            return {
                "connections": get_active_conec(),
                "interfaces": get_inter(),
            }
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return {}
    
    def _scan_forensics(self):
        """Scan forensics with whitelist filtering"""
        try:
            suid = find_suid_binaries()
            cron = check_cron_persistence()
            bashrc = check_bashrc_persistence()
            
            # Filter through whitelist
            suid_filtered = [s for s in suid if is_suid_suspicious(s.get("path", ""))]
            cron_filtered = [c for c in cron if is_cron_suspicious(c.get("content", ""), c.get("user"))]
            bashrc_filtered = [b for b in bashrc if is_bashrc_suspicious(b.get("content", ""))]
            
            return {
                "suid_binaries": suid_filtered,
                "cron_jobs": cron_filtered,
                "bashrc_entries": bashrc_filtered,
            }
        except Exception as e:
            logger.error(f"Forensics scan failed: {e}")
            return {}
    
    def _scan_security(self):
        """Scan security events"""
        try:
            return {
                "failed_logins": get_failed_logins(),
            }
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            return {}
    
    def run_full_scan(self):
        """Run all scans in parallel"""
        timestamp = datetime.now().isoformat()
        hostname = socket.gethostname()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_system): "system",
                executor.submit(self._scan_network): "network",
                executor.submit(self._scan_forensics): "forensics",
                executor.submit(self._scan_security): "security",
            }
            
            results = {}
            for future in as_completed(futures):
                scan_type = futures[future]
                try:
                    results[scan_type] = future.result()
                except Exception as e:
                    logger.error(f"{scan_type} scan failed: {e}")
                    results[scan_type] = {}
    
        
        report = {
            "timestamp": timestamp,
            "hostname": hostname,
            "system": results.get("system", {}),
            "network": results.get("network", {}),
            "forensics": results.get("forensics", {}),
            "security": results.get("security", {}),
        }
        
        return report
    def save_baseline(self,report):
        baseline_file=self.baseline_dir/"baseline_latest.json"
        with open(baseline_file,"w") as f:
            json.dump(report,f,indent=2,default=str)

        return str(baseline_file)
    def load_baseline(self):
        """Load saved baseline"""
        baseline_file = self.baseline_dir / "baseline_latest.json"
        
        if not baseline_file.exists():
            return None
        
        with open(baseline_file, 'r') as f:
            return json.load(f)

    def compare_baseline(self, current_report):
        """Compare current scan with baseline"""
        baseline = self.load_baseline()
        
        if not baseline:
            return {"error": "No baseline found"}
        
        changes = {
            "new_suid": [],
            "removed_suid": [],
            "new_connections": [],
            "removed_connections": [],
        }
        
        # Compare SUID
        current_suid = {s["path"] for s in current_report["forensics"].get("suid_binaries", [])}
        baseline_suid = {s["path"] for s in baseline["forensics"].get("suid_binaries", [])}
        
        changes["new_suid"] = list(current_suid - baseline_suid)
        changes["removed_suid"] = list(baseline_suid - current_suid)
        
        # Compare connections
        current_conns = {(c["local_ip"], c["local_port"]) for c in current_report["network"].get("connections", [])}
        baseline_conns = {(c["local_ip"], c["local_port"]) for c in baseline["network"].get("connections", [])}
        
        changes["new_connections"] = list(current_conns - baseline_conns)
        changes["removed_connections"] = list(baseline_conns - current_conns)
        
        return changes
    def calculate_hash(self,filepath):
        try:
            sha256=hashlib.sha256()
            with open(filepath,"rb") as f:
                for chunk in iter(lambda:f.read(4096),b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (FileNotFoundError,PermissionError):
            return None
    
    def hash_critical_binaries(self):

        hashes={}
        for binary in CRITICAL_BINARIES:
            hash_value=self.calculate_hash(binary)
            if hash_value:
                hashes[binary]=hash_value
        return hashes
    def save_hashes(self,hashes):
        hash_file=self.hash_dir/"hashes_critical.json"
        with open(hash_file,"w") as f:
            json.dump(hashes,f,indent=2)

        return str(hash_file)
    
    def load_hashes(self):
        file=self.hash_dir/"hashes_critical.json"
        try :   
            with open(file) as f:
                return json.load(f)
        except (FileNotFoundError ,PermissionError,json.JSONDecodeError):
            return {} 
    def verify_hashes(self):
        saved_hashes=self.load_hashes()
        current_hashes=self.hash_critical_binaries()
        changes={
            "modified_binaries":[],
            "new_binaries":[],
            "missing_binaries":[]
        }
        for binary, hash_value in current_hashes.items():
            if binary in saved_hashes:
                if saved_hashes[binary] != hash_value:
                    changes["modified_binaries"].append(binary)
            else:
                changes["new_binaries"].append(binary)
        for binary in saved_hashes:
            if binary not in current_hashes:
                changes["missing_binaries"].append(binary)
            
        return changes





def register_parser(subparsers):
    parser = subparsers.add_parser(
        "scan",
        help="Run comprehensive system security scan"
    )
    
    parser.add_argument("--all", action="store_true", help="Full scan")
    parser.add_argument("--save-baseline",action="store_true",help="save currente scan as baseline")
    parser.add_argument("--compare-baseline",action="store_true",help="compare with saved baseline")
    parser.add_argument("--hash-binaries",action="store_true",help="hash critical system binaries")
    parser.add_argument("--verify-hashes",action="store_true",help="Verify hashes against saved")
    parser.set_defaults(func=run)


def run(args):
    if args.all:
        scanner = AdvancedScanner()
        report = scanner.run_full_scan()
        
        print(f"\n[+] Scan completed: {report['hostname']}")
        print(f"[+] Timestamp: {report['timestamp']}")
        print(f"[+] Forensics findings: {len(report['forensics'].get('suid_binaries', []))}")
    elif args.save_baseline:
        scanner=AdvancedScanner()
        report=scanner.run_full_scan()
        baseline_file=scanner.save_baseline(report)
        print(f"\n[+] Baseline saved to: {baseline_file}")
    elif args.compare_baseline:
        scanner=AdvancedScanner()
        report=scanner.run_full_scan()
        changes=scanner.compare_baseline(report)

        if "error"in changes:
            print(f"\n[+]{changes['error']}")
        else:
            scanner.loading=True
            msg="COmparing whith baseline..."
            hilo_spiner=threading.Thread(target=scanner.spiner_task,args=(msg,))
            hilo_spiner.start()
            time.sleep(5)
            print("\n")
            print(f"New SUID binaries: {len(changes['new_suid'])}")
            print(f"Removed SUID binaries: {len(changes['removed_suid'])}")
            print(f"New connections: {len(changes['new_connections'])}")
            print(f"Removed connections: {len(changes['removed_connections'])}")
            scanner.loading=False
            hilo_spiner.join()
    elif args.hash_binaries:
        scanner=AdvancedScanner()
        hashes=scanner.hash_critical_binaries()
        hash_file=scanner.save_hashes(hashes)

        print(f"\n [+0 Hashes saved to : {hash_file}")
    elif args.verify_hashes:
        scanner = AdvancedScanner()
        saved = scanner.load_hashes()
        current = scanner.hash_critical_binaries()

        

        scanner.loading=True
        changes=scanner.verify_hashes()
        msg="Verifying hashes..."
        hilo_spiner=threading.Thread(target=scanner.spiner_task,args=(msg,))
        hilo_spiner.start() 
        time.sleep(5)
        
        print("\n")
        print(f"\nModified Binaries : {len(changes['modified_binaries'])}")
        print(f"\nNew Binaries : {len(changes['new_binaries'])}")
        print(f"\nMissing Binaries : {len(changes['missing_binaries'])}")
        
        if changes['modified_binaries']:
            print(f"\n[!]ALERT: MODIFIED BINARIES DETECTED : ")
            for binary in changes['modified_binaries']:
                print(f" - {binary}")
        scanner.loading=False
        hilo_spiner.join()    
        


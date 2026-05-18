import subprocess
import os
import pwd
import hashlib
import logging

from datetime import datetime

from ldt.utils.whitelist import (
    SUID_WHITELIST,
    SUSPICIOUS_PATHS,
    is_suid_suspicious
)

# ============================================================================
# LOGGER
# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# MITRE MAPPINGS
# ============================================================================

MITRE = {
    "suid":    "T1548.001 - Setuid and Setgid",
    "cron":    "T1053.003 - Cron",
    "bashrc":  "T1546.004 - Unix Shell Config Modification",
    "hidden":  "T1564.001 - Hidden Files",
    "ssh_keys":"T1098.004 - SSH Authorized Keys",
}

# ============================================================================
# CONFIG
# ============================================================================

SEARCH_PATHS = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
]

IGNORED_PATHS = [
    "/proc",
    "/sys",
    "/run",
    "/snap",
]

# ============================================================================
# HELPERS
# ============================================================================

def sha256_file(path: str) -> str:

    sha256 = hashlib.sha256()

    with open(path, "rb") as f:

        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def classify_suid(binary_path: str) -> tuple:

    if binary_path in SUID_WHITELIST:

        return (
            False,
            "INFO",
            0,
            "Known legitimate SUID binary"
        )

    elif any(
        binary_path.startswith(path)
        for path in SUSPICIOUS_PATHS
    ):

        return (
            True,
            "CRITICAL",
            95,
            "SUID binary located in suspicious path"
        )

    else:

        return (
            True,
            "MEDIUM",
            50,
            "Unknown SUID binary not present in whitelist"
        )

# ============================================================================
# CRON PERSISTENCE
# ============================================================================

def check_cron_persistence() -> list[dict]:

    cron_findings = []

    suspicious_keywds = [
        "curl",
        "wget",
        "bash -i",
        "base64",
        "/tmp"
    ]

    files_to_scan = ["/etc/crontab"]

    target_dir = "/etc/cron.d/"

    if os.path.exists(target_dir):

        for root, dirs, files in os.walk(target_dir):

            for name in files:

                fullpath = os.path.join(root, name)

                files_to_scan.append(fullpath)

    for path in files_to_scan:

        try:

            with open(path, "r") as f:

                for num_lin, linea_original in enumerate(f, 1):

                    info = linea_original.split()

                    if not info or info[0].startswith("#"):
                        continue

                    if len(info) >= 6:

                        user = info[5]
                        command = " ".join(info[6:])

                    else:

                        user = "unknown"
                        command = linea_original.strip()

                    matches = [
                        kw for kw in suspicious_keywds
                        if kw in linea_original
                    ]

                    if matches:

                        cron_findings.append({
                            "category": "persistence",
                            "file": path,
                            "line": num_lin,
                            "content": linea_original.strip(),
                            "command": command,
                            "match": matches,
                            "user": user,
                            "severity": "HIGH" if user == "root" else "MEDIUM",
                            "confidence": 85 if user == "root" else 60,
                            "mitre": MITRE["cron"]
                        })

        except PermissionError:

            logger.warning(f"Permission denied reading: {path}")

        except Exception as e:

            logger.error(f"Unexpected error in {path}: {e}")

    return cron_findings

# ============================================================================
# BASHRC PERSISTENCE
# ============================================================================

def check_bashrc_persistence() -> list[dict]:

    users = pwd.getpwall()

    files_to_scan = []

    bashrc_findings = []

    suspicious_keywds = [
        "curl",
        "wget",
        "bash -i",
        "base64",
        "/tmp"
    ]

    for u in users:

        home_user = u.pw_dir

        if u.pw_uid >= 1000 or u.pw_uid == 0:

            fullpath = os.path.join(home_user, ".bashrc")

            if os.path.exists(fullpath):

                files_to_scan.append(fullpath)

    for path in files_to_scan:

        user = path.split('/')[2] if "home" in path else "root"

        try:

            with open(path, "r") as f:

                for num_lin, linea_original in enumerate(f, 1):

                    lin = linea_original.strip()

                    if not lin or lin.startswith("#"):
                        continue

                    matches = [
                        kw for kw in suspicious_keywds
                        if kw in lin
                    ]

                    if matches:

                        bashrc_findings.append({

                            "category": "persistence",
                            "user": user,
                            "file": path,
                            "line": num_lin,
                            "content": lin,
                            "match": matches,
                            "severity": "HIGH" if user == "root" else "MEDIUM",
                            "confidence": 90 if user == "root" else 65,
                            "mitre": MITRE["bashrc"]
                        })

        except Exception as e:

            logger.error(f"Error reading {path}: {e}")

    return bashrc_findings

# ============================================================================
# SUID ANALYSIS
# ============================================================================

def find_suid_binaries() -> list[dict]:

    reporte = []

    cmd = [
        "find",
        *SEARCH_PATHS,
        "-perm",
        "-4000",
        "-type",
        "f"
    ]

    resultado = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    bin_find = resultado.stdout.splitlines()

    for binari in bin_find:

        try:

            if any(
                binari.startswith(path)
                for path in IGNORED_PATHS
            ):
                continue

            stats = os.stat(binari)

            origin = pwd.getpwuid(stats.st_uid).pw_name

            suspicious, severity, confidence, reason = classify_suid(binari)

            logger.debug(
                f"SUID detected: {binari} "
                f"severity={severity} "
                f"confidence={confidence}"
            )

            info_binari = {

                "category": "privilege_escalation",

                "path": binari,

                "owner": origin,

                "permissions": oct(stats.st_mode)[-4:],

                "suspicious": suspicious,

                "severity": severity,

                "confidence": confidence,

                "reason": reason,

                "sha256": sha256_file(binari),

                "modified": datetime.fromtimestamp(
                    stats.st_mtime
                ).isoformat(),

                "created": datetime.fromtimestamp(
                    stats.st_ctime
                ).isoformat(),

                "mitre": MITRE["suid"]
            }

            if suspicious:

                reporte.append(info_binari)

        except (
            FileNotFoundError,
            PermissionError,
            KeyError
        ):

            reporte.append({

                "category": "privilege_escalation",

                "path": binari,

                "owner": "unknown",

                "permissions": "unknown",

                "severity": "UNKNOWN",

                "confidence": 30,

                "mitre": MITRE["suid"],

                "reason": (
                    "Could not read file — "
                    "possible evasion or protected file"
                )
            })

            continue

    return reporte

# ============================================================================
# ARGPARSE
# ============================================================================

def register_parser(subparsers):

    parser = subparsers.add_parser(
        "forensics",
        help="Forensics and persistence detection"
    )

    parser.add_argument(
        "--suid",
        action="store_true",
        help="Audit the system for suspicious SUID binaries"
    )

    parser.add_argument(
        "--cron",
        action="store_true",
        help="Audit the system for scheduled tasks and cron persistence"
    )

    parser.add_argument(
        "--bashrc",
        action="store_true",
        help="Audit the system for bash persistence"
    )

    parser.set_defaults(func=run)

# ============================================================================
# RUNNER
# ============================================================================

def run(args):

    if args.suid:

        result = find_suid_binaries()

        if not result:

            print("\n[+] No suspicious SUID binaries were found")

        else:

            print(f"\n[!] DETECTED {len(result)} SUSPICIOUS SUID BINARIES")
            print("=" * 80)

            for h in result:

                severity = h.get("severity", "LOW")

                if severity == "CRITICAL":

                    severity_flag = "[CRITICAL]"

                elif severity == "MEDIUM":

                    severity_flag = "[WARNING]"

                else:

                    severity_flag = "[INFO]"

                print(f"FILE:        {h['path']}")
                print(f"OWNER:       {h['owner']}")
                print(f"PERMISSIONS: {h['permissions']}")
                print(f"SEVERITY:    {severity} {severity_flag}")
                print(f"CONFIDENCE:  {h['confidence']}%")
                print(f"REASON:      {h['reason']}")
                print(f"SHA256:      {h['sha256']}")
                print(f"MODIFIED:    {h['modified']}")
                print(f"MITRE:       {h['mitre']}")

                print("-" * 80)

    elif args.cron:

        print("\n[*] Auditing Cron Persistence Mechanisms...")

        results = check_cron_persistence()

        if not results:

            print("[+] No suspicious cron jobs were detected.")

        else:

            print(f"[!] DETECTED {len(results)} SUSPICIOUS CRON ENTRIES")
            print("=" * 80)

            for h in results:

                sev_label = (
                    "[CRITICAL]"
                    if h['severity'] == "HIGH"
                    else "[WARNING]"
                )

                print(f"STATUS:      {h['severity']} {sev_label}")
                print(f"FILE:        {h['file']} (Line: {h['line']})")
                print(f"USER:        {h['user']}")
                print(f"CONFIDENCE:  {h['confidence']}%")
                print(f"MATCHES:     {', '.join(h['match'])}")
                print(f"COMMAND:     {h['content']}")
                print(f"MITRE:       {h['mitre']}")

                print("-" * 80)

    elif args.bashrc:

        print("\n[*] Auditing shell config files...")

        result = check_bashrc_persistence()

        if not result:

            print("[+] No suspicious activity found in .bashrc files")

        else:

            print(f"[!] DETECTED {len(result)} SUSPICIOUS BASHRC ENTRIES")
            print("=" * 80)

            for alert in result:

                sev_label = (
                    "[CRITICAL]"
                    if alert['severity'] == "HIGH"
                    else "[WARNING]"
                )

                print(f"STATUS:      {alert['severity']} {sev_label}")
                print(f"FILE:        {alert['file']}")
                print(f"COMMAND:     {alert['content']}")
                print(f"USER:        {alert['user']}")
                print(f"CONFIDENCE:  {alert['confidence']}%")
                print(f"MATCHES:     {', '.join(alert['match'])}")
                print(f"MITRE:       {alert['mitre']}")

                print("=" * 80)

    else:

        print("[!] No forensics option provided.")


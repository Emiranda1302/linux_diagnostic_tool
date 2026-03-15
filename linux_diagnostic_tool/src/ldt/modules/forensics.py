import subprocess
import os
import pwd



def find_suid_binaries()->list[dict]:
    reporte=[]
    resultado=subprocess.run(
        ["find","/","-perm","-4000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
        )
    
    
    bin_find=resultado.stdout.splitlines()
    
    SUID_WHITELIST = [
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
    "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/lib/openssh/ssh-keysign"
    ]
    SUSPICIOUS_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/run/user"]

    for binari in bin_find:
        try:
            stats=os.stat(binari)
            origin=pwd.getpwuid(stats.st_uid).pw_name

            if binari not in SUID_WHITELIST:
                if any(binari.startswith(ruta) for ruta in SUSPICIOUS_PATHS):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                info_binari={
                    "ruta":binari,
                    "dueno":origin,
                    "permisos":oct(stats.st_mode)[-4:],
                    "sospechosos":True,
                    "mitre": "T1548.001 - Setuid and Setgid",
                    "severity":severity
                }
                reporte.append(info_binari)
        except (FileNotFoundError, PermissionError, KeyError):
            reporte.append({
                "ruta":     binari,
                "dueno":    "unknown",
                "permisos": "unknown",
                "severity": "UNKNOWN",
                "mitre":    "T1548.001 - Setuid and Setgid",
                "nota":     "No se pudo leer — posible evasión o archivo protegido"
            })
            continue
    
    return reporte
    

def register_parser(subparsers):

    parser = subparsers.add_parser( 
        "forensics",
        help="System diagnostic tools"
    )

    parser.add_argument(
        "--suid",
        action="store_true",
        help="Audit the system for suspicious SUID binaries"
    )

    parser.set_defaults(func=run)



def run(args):
    if args.suid:
        result = find_suid_binaries()
        if not result:
            print("\n No suspicious SUID binaries were found ")
        else:            
            print(f"\n [!] Hve been detected {len(result)} SUSPICIOUS SUID BINARIES FOUND")
            print("-" * 80)
            for h in result:
                severity = h.get('severity', 'LOW')
                severity_flag = "[!!!]"*9 if severity == "HIGH" else ""
                print(f"FILE:    {h['ruta']}")
                print(f"OWNER:   {h['dueno']} (Perms: {h['permisos']})")
                print(f"SEVERITY:   {severity}{severity_flag}")
                print(f"MITRE:   {h['mitre']}")
                                
                print("-" * 60)
        




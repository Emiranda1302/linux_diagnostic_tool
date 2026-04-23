import subprocess
import os
import pwd

MITRE = {
    "suid":    "T1548.001 - Setuid and Setgid",
    "cron":    "T1053.003 - Cron",
    "bashrc":  "T1546.004 - Unix Shell Config Modification",
    "hidden":  "T1564.001 - Hidden Files",
    "ssh_keys":"T1098.004 - SSH Authorized Keys",
}

def check_cron_persistence() -> list[dict]:
    cron_findings=[]
    suspicious_keywds=["curl","wget","bash -i","base64","/tmp"]

    files_to_scan=["/etc/crontab"]
    target_dir = "/etc/cron.d/"
    if os.path.exists(target_dir):
        for root, dirs, files in os.walk(target_dir):
            for name in files:
                fullpath = os.path.join(root, name)
                files_to_scan.append(fullpath)
    

    for path in files_to_scan:
        try:
            with open(path,"r") as f:
                for num_lin,linea_original in enumerate(f,1):
                    info=linea_original.split()
                    if len(info)>=6:
                        user=info[5]
                        comand=" ".join(info[6:])
                    else:
                        user="unknown"
                        comand=info
                    if not info or info[0]=="#":
                        continue
                    
                    matches=[kw for kw in suspicious_keywds if kw in linea_original]
                    if matches:
                        
                        
                        cron_findings.append({
                            "file":path,
                            "line":num_lin,
                            "content":linea_original,
                            "match":matches,
                            "user":user,
                            "severity":"HIGH" if user =="root" else "MEDIUM",
                            "mitre":MITRE["cron"]
                        })
        except PermissionError:
            print(F"[!] Cannot read file [permission denied]: {path}")
        except Exception as e:
            print(f"[!] Error inesperado en {path}: {e}")
    return cron_findings

def check_bashrc_persistence()->list[dict]:
    users=pwd.getpwall()
    files_to_scan,bashrc_findings=[],[]
    suspicious_keywds=["curl","wget","bash -i","base64","/tmp"]
    
    for u in users:
        home_user=u.pw_dir
        if u.pw_uid >=1000 or u.pw_uid==0:
            fullpath=os.path.join(home_user,".bashrc")
            if os.path.exists(fullpath):
                files_to_scan.append(fullpath)

    for path in files_to_scan:
        user=path.split('/')[2]if "home" in path else "root"
        try:
            with open(path,"r") as f:
                for num_lin,linea_original in enumerate(f,1):
                    lin=linea_original.strip()
                    if not lin or linea_original.startswith("#"):
                        continue
                    matches=[kw for kw in suspicious_keywds if kw in lin]
                    if matches:
                        bashrc_findings.append({
                            "user":user,
                            "file":path,
                            "content":lin,
                            "match":matches,
                            "severity":"HIGH" if user=="root" else "MEDIUM",
                            "mitre":MITRE["bashrc"]
                        })
        except Exception as e:
            print(f"Error reading {path}: {e}")

    return bashrc_findings

    




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
                if any(binari.startswith(path) for path in SUSPICIOUS_PATHS):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                info_binari={
                    "path":binari,
                    "owner":origin,
                    "permissions":oct(stats.st_mode)[-4:],
                    "suspicious":True,
                    "mitre":MITRE["suid"],
                    "severity":severity
                }
                reporte.append(info_binari)
        except (FileNotFoundError, PermissionError, KeyError):
            reporte.append({
                "path":     binari,
                "owner":    "unknownn",
                "permissions": "unknownn",
                "severity": "UNKNOWN",
                "mitre":    "T1548.001 - Setuid and Setgid",
                "nota":     "Could not read — possible evasion or protected file"
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
    parser.add_argument(
        "--cron",
        action="store_true",
        help="Audit the system for scheduled taks and cron persistence"
    )
    parser.add_argument(
        "--bashrc",
        action="store_true",
        help="Audit the system for bash persistence"
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
                print(f"FILE:    {h['path']}")
                print(f"OWNER:   {h['owner']} (Perms: {h['permissions']})")
                print(f"SEVERITY:   {severity}{severity_flag}")
                print(f"MITRE:   {h['mitre']}")
                                
                print("-" * 60)
    elif args.cron:
        print("\n[*] Auditing Cron Persistence Mechanisms...")
        results = check_cron_persistence()
        
        if not results:
            print("[+] No suspicious cron jobs were detected.")
        else:
            print(f"[!] DETECTED {len(results)} SUSPICIOUS CRON ENTRIES")
            print("=" * 80)

            for h in results:
                # Definimos una pequeña bandera visual para la severidad
                sev_label = "[!!!]" if h['severity'] == "HIGH" else "[!]"
                
                print(f"STATUS:    {h['severity']} {sev_label}")
                print(f"FILE:      {h['file']} (Line: {h['line']})")
                print(f"USER:      {h['user']}")
                print(f"MATCHES:   {', '.join(h['match'])}") # Une ['wget', '/tmp'] -> "wget, /tmp"
                print(f"COMMAND:   {h['content']}")
                print(f"MITRE:     {h['mitre']} - Scheduled Task: Cron")
                print("-" * 80)
    elif args.bashrc:
        print("\n[*] Auditing shell config files...")
        result=check_bashrc_persistence()
        if not result:
            print("[+]NO suspicious activity found in .bashrc files")
        else:
            print(f"DETECTED {len(result)} SUSPICIOUS BASHRC ENTRIES")
            print("="*80)
            for alert in result:
                sev_label="[!] [!]"if alert['user']=="root" else "[!]"


                print(f"STATUS:    {alert['severity']} {sev_label}")
                print(f"FILE:      {alert['file']}")
                print(f"COMMAND:   {alert['content']}")
                print(f"USER:      {alert['user']}")
                print(f"MATCHES:   {', '.join(alert['match'])}") 
                
                print(f"MITRE:     {alert['mitre']}")
                print("="*80)


        
    else:
        print("No system option provided.")
    




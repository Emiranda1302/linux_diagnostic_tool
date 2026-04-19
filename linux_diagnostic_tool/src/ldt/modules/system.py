"""
Módulo de sistema.
"""
import psutil
import time
import re
import subprocess
from datetime import datetime

def get_running_processes() -> list[dict]:
    processes = []

    current_time=time.time()

    for proc in psutil.process_iter(['pid', 'name', 'username',
                                      'cmdline','create_time']):
        try:
            info = proc.info
            
            """calc uptime if there creattime exist"""
            create_time=info.get('create_time')
            uptime_s= None
            start_datetime=None
            
            if create_time:
                uptime_s=round(current_time - create_time,2)
                start_datetime=datetime.fromtimestamp(create_time)



            processes.append({
                "pid": info.get('pid'),
                "name": info.get('name'),
                "username": info.get('username'),
                "cmdline": " ".join(info.get('cmdline') or []),
                "crated_time_e":create_time,
                "start_time":start_datetime,
                "uptime_s":uptime_s

            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            name=getattr(proc,"info",{}).get("name","UNKNOW")
            pid=getattr(proc,"info",{}).get("pid","UKNOW")
            print(f"[WARN] Proceso terminado durante escaneo -> PID : {pid} NAME: {name}")
            continue

    return processes

def get_cpu_info()->list[dict]:
    
    proces=list(psutil.process_iter(['pid','name','username','status','cpu_percent'
    ,'memory_percent']))
    for proc in proces:
        proc.cpu_percent(interval=None)
    
    time.sleep(0.5)
    result=[]
    for proc in proces:
        try:
            cpu=proc.info
            result.append({
                "pid":cpu.get("pid"),
                "name":cpu.get("name"),
                "username":cpu.get("username"),
                "status":cpu.get("status"),
                "cpu_percent":proc.cpu_percent(interval=None),
                "memory_percent":cpu.get("memory_percent")
                
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            name=getattr(proc,"info",{}).get("name","UNKNOW")
            pid=getattr(proc,"info",{}).get("pid","UKNOW")
            print(f"[WARN] Proceso terminado durante escaneo -> PID : {pid} NAME: {name}")
            continue

    return result

def get_memory_info()-> dict:
    virtual=psutil.virtual_memory()
    swap=psutil.swap_memory()

    GB=1024**3

    return{
        "ram_total":round(virtual.total/GB,2),
        "ram_used":round(virtual.used/GB,2),
        "ram_free":round(virtual.available/GB,2),
        "ram_percent":virtual.percent,
        "swap_total":round(swap.total/GB,2),
        "swap_used":round(swap.used/GB,2),
        "swap_percent":swap.percent
    }

def get_listening_ports()->list[dict]:
    conections=[]
    for conn in psutil.net_connections(kind='inet'):
        if conn.status=='LISTEN':
            try:
                p=psutil.Process(conn.pid)
                process_name=p.name()if conn.pid else "sytemkernelproces"            
                conections.append({
                  "process":process_name,
                  "ip":conn.laddr.ip,
                  "port":conn.laddr.port,
                  "states":conn.status
                })
            except (psutil.NoSuchProcess,psutil.AccessDenied):
                process_name="unknown"
                print("no hay mai")
    return conections
def get_failed_logins()->list[dict]:
    result=subprocess.run(
        ["journalctl","-u","ssh","--no-pager"],
        capture_output=True,
        text=True,
        check=True
    )
    log_patern=r"([A-Z][a-z]{2}\s\d{2}\s\d{2}:\d{2}:\d{2}).*?(\w+)\spassword.*?user\s(\S+)\sfrom\s(\S+)\sport\s(\d+)"
    log_root_patern=r"([A-Z][a-z]{2}\s\d{2}\s\d{2}:\d{2}:\d{2}).*?(\w+)\spassword.*?for\s(\S+)\sfrom\s(\S+)\sport\s(\d+)"
    
    failed_attempts=[]
    for line in result.stdout.splitlines():
        match=re.search(log_patern,line)
        if not match:
            match=re.search(log_root_patern,line)
        if match:   
            timestamp,status,username,ip_address,port_num =match.groups()
            failed_attempts.append({
                    "timestamp":timestamp,
                    "username":username,
                    "status":status,
                    "remote_ip":ip_address,
                    "port":port_num
                })
            
    return failed_attempts


def register_parser(subparsers):

    parser = subparsers.add_parser( 
        "system",
        help="System diagnostic tools"
    )

    parser.add_argument(
        "--cpu",
        action="store_true",
        help="Show CPU info"
    )

    parser.add_argument(
        "--memory",
        action="store_true",
        help="Show memory usage"
    )
    parser.add_argument(
        "--logins",
        action="store_true",    
        help="show falied login attempts"
    )
    parser.add_argument(
        "--ports",
        action="store_true",    
        help="show listening ports "
    )
    

    parser.set_defaults(func=run)

def run(args):

    if args.cpu:
        procs=get_cpu_info()
        procs_sorted=sorted(procs,key=lambda x:x['cpu_percent'] or 0,
                            reverse=True )[:10]
        print(f"\n{'PID':<8}{'NAME':<25}{'USUARIO':<15}{'CPU %':<10}{'MEM%':<10}{'sTATUS':^12}")
        print("-"*80)
        for p in procs_sorted:
            flag="[!]" if (p['cpu_percent'] or 0)> 50 else ""
            print(
                f"{str(p['pid']):<8}"
                f"{str(p['name']):<25}"
                f"{str(p['username']):<15}"
                f"{str(p['cpu_percent']):<10}"
                f"{str(round(p['memory_percent'] or 0,2)):<10}"
                f"{str(p['status']):^12}{flag}"
            ) 
    elif args.memory:
        info=get_memory_info()

        ram_flag  = " [!]" if info['ram_percent'] > 80 else ""
        swap_flag = " [!]" if info['swap_percent'] > 50 else ""

        FORMATO = "{:^8}{:^22}{:^12}{:^20}{:^12}{:^12}{:^10}"
        print("\n"+FORMATO.format("ram_total","ram_used","ram_free","ram_percent",
                                  "swap_total","swap_used","swap_percent"))
        print("-"*100)
        print(FORMATO.format(
            str(info['ram_total']),
            str(info['ram_used']),
            str(info['ram_free']),
            str(info['ram_percent'])+ram_flag,
            str(info['swap_total']),
            str(info['swap_used']),
            str(info['swap_percent'])+swap_flag
        ))
        # Al final de la función run
        if ram_flag or swap_flag:
            print(f"\n[ALERTA] El sistema está bajo presión de memoria.")
    elif args.logins:
        failed_attempts=get_failed_logins()  
        FORMAT_SECURITY = "{:<18} {:<10} {:<15} {:<20} {:<8}"  
        print("SECURITU LOGS -FAILEDER SSH ATETEMPTS".center(65,"="))
        print(FORMAT_SECURITY.format("TIMESTAMP","STATUS","USERNAME","REMOTE_IP","PORT"))
        print("-"*80)

        if not failed_attempts:
            print("NO failed attempts ","<3"*55)
        else:
            for attempts in failed_attempts:
                print(FORMAT_SECURITY.format(
                    attempts['timestamp'],
                    attempts['status'],
                    attempts['username'],
                    attempts["remote_ip"],
                    attempts['port']
                ))    
        if len(failed_attempts)>5:
            print(f"\n[!] ALERT: {len(failed_attempts)} unauthorized access attempts detected.")
    elif args.ports:
        listening_sockets=get_listening_ports()
        FORMAT_ports="{:<18}{:^15}{:<10}{:<18}"
        print("ALL ACTIVE NETWORK SERVICES LINTENING FOR CONECTIONS ".center(65,"="))
        print(FORMAT_ports.format("PROcces","ip","port","status"))
        print("-"*80)
        if not get_listening_ports:
            print("NO LISTENING SOCKETS")
        else:
            for ports in listening_sockets:
                  print(FORMAT_ports.format(
                    ports['process'],
                    ports['ip'],
                    ports['port'],
                    ports["states"]
                ))
    else:
        print("No system option provided.")

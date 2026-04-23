import psutil


def get_active_conec() -> list[dict]:
    conections=[]
    for conn in psutil.net_connections(kind='inet'):
        try:
            process_name=psutil.Process(conn.pid).name() if conn.pid else "unknown"
            
            process_user=psutil.Process(conn.pid).username() if conn.pid else "unknown"
             
        except (psutil.NoSuchProcess,psutil.AccessDenied):
            process_name="unknown"
            process_user="unknown"
        
        remote_ip=conn.raddr.ip if conn.raddr else None
        is_public=_is_public_ip(remote_ip) if remote_ip else False

        conections.append({
            "pid":         conn.pid,
            "process":     process_name,
            "user":        process_user,
            "local_ip":    conn.laddr.ip,
            "local_port":  conn.laddr.port,
            "remote_ip":   remote_ip,
            "remote_port": conn.raddr.port if conn.raddr else None,
            "status":      conn.status,
            "is_public":   is_public,
            "root_and_public":True if process_user =="root" and is_public==True else False, 
        })
    
    return conections

def _is_public_ip(ip:str)->bool:
    import ipaddress
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def register_parser(subparsers):
    parser = subparsers.add_parser("connections", help="Show active connections")
    parser.add_argument("--active", action="store_true", help="List active connections")
    parser.set_defaults(func=run)
def run(args):
    if args.active:
        conns = get_active_conec()
        print(f"\n{'PID':<8} {'PROCESS':<20} {'USER':<15} {'REMOTE IP':<20} {'PORT':<8} {'STATE':<15} {'PUBLIC':<10}{"ROOT+PUBLIC"}")
        print("-" * 95)
        for c in conns:
            print(
                f"{str(c['pid']):<8} "
                f"{str(c['process']):<20} "
                f"{str(c['user']):<15} "
                f"{str(c['remote_ip']):<20} "
                f"{str(c['remote_port']):<8} "
                f"{str(c['status']):<15} "
                f"{'[!]' if c['is_public'] else '':<10}"
                f"{'[ROOT]' if c['root_and_public'] else ''}"
            )


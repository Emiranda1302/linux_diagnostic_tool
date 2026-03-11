# src/ldt/modules/network/interfaces.py
import psutil



def get_inter()->list[dict]:
    interfaces=[]
    adrs=psutil.net_if_addrs()
    stats=psutil.net_if_stats()

    for name,addr_list in adrs.items():
        stat=stats.get(name)
        ipv4 = next((a.address for a in addr_list if a.family.name == "AF_INET"), None)
        ipv6 = next((a.address for a in addr_list if a.family.name == "AF_INET6"), None)
        mac  = next((a.address for a in addr_list if a.family.name == "AF_PACKET"), None)

        interfaces.append({
            "Name":name,
            "status":"UP" if stat and stat.isup else "DOWN",
            "Ipv4":ipv4,
            "Ipv6":ipv6,
            "mac":mac,
            "speed":stat.speed if stat else 0
        })

    return interfaces


def register_parser(subparsers):
    parser = subparsers.add_parser("interfaces", help="Show network interfaces")
    parser.add_argument("--list", action="store_true", help="List interfaces and IPs")
    parser.set_defaults(func=run)

def run(args):
    if args.list:
        ifaces=get_inter()
        print(f"\n{'INTERFAZ':<15}{'STATUS':<8}{'IPV4':<18}{'IPV6':<20}{'MAC':<20}{'SPEED'}")
        print("-"*75)
        for i in ifaces:
            print(
                f"{i['Name']:<20}"
                f"{i['status']:<8}"
                f"{str(i['Ipv4']):<18}"
                f"{str(i['mac']):<20}"
                f"{i['speed']} Mbps"               
            )
    else:
        print("no option provided. use --list")





from ldt.modules.network import interfaces, connections

def register_parser(subparsers):
    parser = subparsers.add_parser("network", help="Network analysis tools")
    sub = parser.add_subparsers(dest="net_cmd", required=True)
    interfaces.register_parser(sub)
    connections.register_parser(sub)
# src/ldt/modules/network/__init__.py
from ldt.modules.network import interfaces

def register_parser(subparsers):
    parser = subparsers.add_parser("network", help="Network analysis tools")
    sub = parser.add_subparsers(dest="net_cmd", required=True)
    interfaces.register_parser(sub)
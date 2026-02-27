"""
Módulo de sistema.
"""

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

    parser.set_defaults(func=run)


def run(args):

    if args.cpu:
        print("Showing CPU info...")

    elif args.memory:
        print("Showing memory usage...")

    else:
        print("No system option provided.")
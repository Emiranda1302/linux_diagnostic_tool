"""
Módulo de red.
Contiene:
- Registro del subcomando.
- Definición de argumentos propios.
- Lógica de ejecución.
"""

def register_parser(subparsers):
    """
    Registra el subcomando 'network'
    dentro del parser principal.
    """

    # Crear subparser llamado "network"
    parser = subparsers.add_parser(
        "network",
        help="Network diagnostic tools"
    )

    # Argumentos específicos de este módulo
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan local network"
    )

    parser.add_argument(
        "--ping",
        type=str,
        help="Ping specific host"
    )

    # Asociar función de ejecución
    # Esto elimina necesidad de if en main
    parser.set_defaults(func=run)


def run(args):
    """
    Función que ejecuta la lógica del módulo.
    """

    if args.scan:
        print("Scanning network...")

    elif args.ping:
        print(f"Pinging host {args.ping}")

    else:
        print("No network option provided.")
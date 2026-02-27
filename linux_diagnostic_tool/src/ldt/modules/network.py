"""
Módulo de red.
Contiene:
- Registro del subcomando.
- Definición de argumentos propios.
- Lógica de ejecución.
"""

import subprocess
import sys
import threading
import time
import itertools


def register_parser(subparsers):
    """   Registra el subcomando 'network'  """

    parser = subparsers.add_parser(
        "network",
        help="Network diagnostic tools"
    )

    # Argumentos específicos de este módulo

    parser.add_argument(
        "--interfaces",
        action="store_true",
        help="show the net interfaces and their ips"

    )


    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan local network"
    )

    parser.add_argument(
        "--ping",
        metavar="HOST",
        type=str,
        help="Ping specific host"
    )

    # Asociar función de ejecución

    parser.set_defaults(func=run)

def run(args):
    """
    lógica del módulo.
    """
    if args.interfaces:
        print("\n[*] Obteniendo informacion de interfacces...   ")
        try:
            result = subprocess.run(
                ["ip", "-br", "addr"],
                capture_output=True,
                text=True,
                check=True
            )
            print(result.stdout)
        except subprocess.CalledProcessError:
            print(" \n [!] ERROR: NO SE PUDO EJECUTAR EL COMANDO 'IP' ")

    elif args.scan:
        print("\n Scanning network...")
        try:
            print("[!] Nota: Este comando suele requerir privilegios de ROOT. \n")
            subprocess.run(["sudo","arp-scan","--localnet"])
            print("\n")
        except FileNotFoundError:
            print("[!] Eroor: 'arp-scan' no esta instalado. \n" \
            "prueba: sudo apt install arp-scan")

    elif args.ping:
        host = args.ping
        print(f"\n[*] Enviando 3 paquetes de prueba a: {host} ...")

        terminado = False

        def spinner():
            animacion = itertools.cycle(["|", "/", "-", "\\"])
            while not terminado:
                sys.stdout.write(f"\r[*] Haciendo ping {next(animacion)}")
                sys.stdout.flush()
                time.sleep(0.1)

        hilo = threading.Thread(target=spinner)
        hilo.start()

        resultado = subprocess.run(
            ["ping", "-c", "3", host],
            capture_output=True,
            text=True
        )

        terminado = True
        hilo.join()
        print("\r", end="")  # limpia línea del spinner

        if resultado.returncode == 0:
            print("[+] El host está vivo:\n")
            print(resultado.stdout)
        else:
            print(f"[-] El host {host} no responde o es inalcanzable.")

    else:
        print("No network option provided.")
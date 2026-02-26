#!/usr/bin/env python3
"""
main.py

Punto de entrada del Linux Diagnostic Tool.
Define la interfaz CLI usando argparse y despacha
cada subcomando a su función correspondiente.
"""

import argparse

# Importamos los módulos reales
# (ajusta la ruta si tu estructura cambia)
from linux_diagnostic_tool.modules import network, system 


# ==========================================================
# FUNCIONES DE EJECUCIÓN (Despachadores)
# ==========================================================

def run_network(args):
    """
    Ejecuta el módulo de diagnóstico de red.
    """
    network.run(args)


def run_system(args):
    """
    Ejecuta el módulo de diagnóstico del sistema.
    """
    system.run(args)


def run_all(args):
    """
    Ejecuta todos los diagnósticos disponibles.
    """
    network.run(args)
    system.run(args)


# ==========================================================
# FUNCIÓN PRINCIPAL
# ==========================================================

def main():
    """
    Configura la interfaz CLI y ejecuta el subcomando elegido.
    """

    # 1️⃣ Creamos el parser principal
    parser = argparse.ArgumentParser(
        prog="linux_diagnostic_tool",
        description="Linux Diagnostic Toolkit - Herramienta de Triaje de Seguridad"
    )

    # 2️⃣ Creamos los subparsers (subcomandos)
    subparsers = parser.add_subparsers(
        dest="command",   # Nombre del atributo donde se guardará el subcomando
        required=True     # Obliga a elegir uno
    )

    # ------------------------------------------------------
    # Subcomando: network
    # ------------------------------------------------------
    network_parser = subparsers.add_parser(
        "network",
        help="Ejecuta diagnóstico de red"
    )

    # Ejemplo de argumento opcional exclusivo de network
    network_parser.add_argument(
        "--deep",
        action="store_true",
        help="Realiza un escaneo profundo"
    )

    # Asociamos este subcomando con su función
    network_parser.set_defaults(func=run_network)

    # ------------------------------------------------------
    # Subcomando: system
    # ------------------------------------------------------
    system_parser = subparsers.add_parser(
        "system",
        help="Ejecuta diagnóstico del sistema"
    )

    system_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra información detallada"
    )

    system_parser.set_defaults(func=run_system)

    # ------------------------------------------------------
    # Subcomando: all
    # ------------------------------------------------------
    all_parser = subparsers.add_parser(
        "all",
        help="Ejecuta diagnóstico completo"
    )

    all_parser.set_defaults(func=run_all)

    # 3️⃣ Parseamos argumentos
    args = parser.parse_args()

    # 4️⃣ Ejecutamos la función asociada al subcomando
    args.func(args)


# ==========================================================
# Protección estándar
# ==========================================================

if __name__ == "__main__":
    main()

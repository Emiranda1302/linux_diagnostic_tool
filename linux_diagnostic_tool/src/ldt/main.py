#!/usr/bin/env python3

"""
Main del CLI con descubrimiento automático
de módulos dentro de ldt.modules
"""

import argparse
import pkgutil
import importlib
import ldt.modules


def main():

    # -------------------------------
    # 1) Crear parser principal
    # -------------------------------
    parser = argparse.ArgumentParser(
        prog="ldt",
        description="Linux Diagnostic Toolkit"
    )

    subparsers = parser.add_subparsers(
        title="modules",
        dest="module",
        required=True
    )

    # -------------------------------
    # 2) Descubrir módulos automáticamente
    # -------------------------------
    for loader, module_name, is_pkg in pkgutil.iter_modules(ldt.modules.__path__):

        #  nombre completo
        full_module_name = f"ldt.modules.{module_name}"

        # Importar dinámicamente
        module = importlib.import_module(full_module_name)

        # Si el módulo tiene register_parser, lo registramos
        if hasattr(module, "register_parser"):
            module.register_parser(subparsers)

    # -------------------------------
    # 3) Parsear argumentos
    # -------------------------------
    args = parser.parse_args()

    # -------------------------------
    # 4) Ejecutar función asociada
    # -------------------------------
    args.func(args)


if __name__ == "__main__":
    main()
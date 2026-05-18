#!/usr/bin/env python3

"""
CLI main with automatic module discovery
of modules inside  ldt.modules
"""

import argparse
import pkgutil
import importlib
import ldt.modules


def main():

    # -------------------------------
    # 1) Create main parser
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
    # 2) Auto-discover modules
    # -------------------------------
    for loader, module_name, is_pkg in pkgutil.iter_modules(ldt.modules.__path__):

        #  full module nam
        full_module_name = f"ldt.modules.{module_name}"

        # import dynamically
        module = importlib.import_module(full_module_name)

        # if module has register_parser, register it
        if hasattr(module, "register_parser"):
            module.register_parser(subparsers)

    # -------------------------------
    # 3) Parse arguments
    # -------------------------------
    args = parser.parse_args()

    # -------------------------------
    # 4) Execute associated function
    # -------------------------------
    args.func(args)


if __name__ == "__main__":
    main()
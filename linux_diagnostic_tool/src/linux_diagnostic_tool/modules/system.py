"""
system.py

Módulo de diagnóstico del sistema.
"""

def run(args):
    print("[+] Ejecutando auditoría de sistema")

    if getattr(args, "verbose", False):
        print("[+] Modo detallado activado")
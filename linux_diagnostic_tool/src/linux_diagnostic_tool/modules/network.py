"""
network.py

Módulo de diagnóstico de red.
"""

def run(args):
    print("[+] Ejecutando auditoría de red")

    if getattr(args, "deep", False):
        print("[+] Escaneo profundo activado")
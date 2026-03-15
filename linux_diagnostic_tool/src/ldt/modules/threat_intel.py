import os
import requests
from dotenv import load_dotenv
from pathlib import Path
import threading
import itertools
import sys
import time



dotenv_path = Path(__file__).resolve().parents[3] / ".env"
load_dotenv(dotenv_path)

api_key = os.getenv("ABUSEIPDB_API_KEY")

def check_ip(ip:str)-> dict :
    resultado={}
    terminado=False
    
    def spinner():
        ciclo=itertools.cycle(["|", "/", "-", "\\"])   # cicla los caracteres
        while not terminado:
            char=next(ciclo)
            sys.stdout.write(f"\r Consultando API {char}")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write("\r" + " " * 25 + "\r")
            
            """"SOUND FINALLY PROCcEES"""
            sys.stdout.write("\a")
            sys.stdout.flush()
    
    hilo=threading.Thread(target=spinner)
    hilo.start()
    
    try:
        response=requests.get(" https://api.abuseipdb.com/api/v2/check",
                headers={"Key":api_key,
                "Accept":"application/json"},
                params={"ipAddress":ip} )
        data=response.json()["data"]
        resultado={
        "ip":           data["ipAddress"],
        "abuse_score":  data["abuseConfidenceScore"],
        "total_reports":data["totalReports"],
        "country":      data["countryCode"],
        "isp":          data["isp"],
        "is_tor":       data["isTor"],
        "is_malicious": data["abuseConfidenceScore"] > 50
        }
    except Exception as e :
        resultado={"error":str(e)}
    finally:
        terminado=True
        hilo.join()

    return resultado



def register_parser(subparsers):

    parser = subparsers.add_parser( 
        "threat_intel",
        help="System diagnostic tools"
    )

    parser.add_argument(
        "--ip",
        type=str,
        help="Query IP threat intelligence form AbuseIPDB "
    )

    parser.set_defaults(func=run)



def run(args):
    if args.ip:
        result = check_ip(args.ip)
        
        if "error" in result:
            print(f"[!] Error: {result['error']}")
            return
        
        print(f"\n{'IP':<20} {'SCORE':<8} {'REPORTS':<10} {'COUNTRY':<10} {'TOR':<6} {'ISP'}")
        print("-" * 80)
        flag = "[!]" if result['is_malicious'] else ""
        print(
            f"{result['ip']:<20} "
            f"{result['abuse_score']:<8} "
            f"{result['total_reports']:<10} "
            f"{result['country']:<10} "
            f"{str(result['is_tor']):<6} "
            f"{result['isp']} {flag}"
        )

        if result['is_malicious'] or result['is_tor']:
            print("\n" + "!" * 30)
            print("⚠️  ALERTA DE SEGURIDAD  ⚠️")
            if result['is_tor']:
                print("- Conexión anónima TOR detectada")
            if result['is_malicious']:
                print(f"- IP reportada: score {result['abuse_score']}%")
            sys.stdout.write("\a")
            print("!" * 30 + "\n")
        else:
            print("\n[+] IP aparentemente legítima.")
    else:
        print("Usa: ldt threat_intel --ip <dirección IP>")
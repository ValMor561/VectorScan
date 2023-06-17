import subprocess
from termcolor import cprint
import xml.etree.ElementTree as ET

def StartScan(ip,port,scripts,filename):
    process=subprocess.run(f'''nmap --script {scripts} -p {port} -oX {filename} {ip}''', capture_output=True, text=True,shell=True)
    stdout = process.stdout
    if process.returncode != 0:
        cprint("[!] Возникли ошибки при вызове nmap", "yellow")
        return False
    return stdout


def ParseXML(filename):
    tree = ET.parse(f"{filename}")
    root = tree.getroot()
    for host in root.iter('host'):
        for port in host.iter('port'):
                count = 0
                for script in port.iter('script'):
                    count += 1
                    scriptid = script.get('id')
                    res = script.get('output')
                    cprint(f'\t[I] Выполнен скрипт: {scriptid}',"magenta")
                    print(f'\t[+] Результат: {res}')
                if count == 0:
                    print("[-] Не удалось получить дополнительную информацию")

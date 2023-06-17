import subprocess
import os 
import xml.etree.ElementTree as ET
from termcolor import cprint
class PreScan:

    def __init__(self, ip):
        self.ip = ip
        if not os.path.exists("scanresult/" + self.ip):
            os.makedirs("scanresult/" + self.ip)
        self.resfilname = "scanresult/" + self.ip + "/portscan.xml"
        self.openport = []

    def ParseXml(self):
        tree = ET.parse(self.resfilname)
        root = tree.getroot()
        for host in root.iter('host'):
        # получаем IP адрес хоста
            ip = host.find('address').get('addr')
            cprint("[I] Открытые порты:", "magenta")
            # проходим по всем сервисам на хосте
            for port in host.iter('port'):
                if port.find('state').get('state') == 'open':
                    portid = port.get('portid')
                    self.openport.append(portid)
                    name = port.find('service').get('name')
                    product = port.find('service').get('product') if port.find('service').get('product') != None else "Неизвестно" 
                    version = port.find('service').get('version') if port.find('service').get('version') != None else "Неизвестно" 
                    # выводим информацию о сервисе
                    cprint(f'[+] Порт: {portid}, Протокол: {name}, Служба: {product}, Версия службы: {version}', 'green')
#-p 21,22,23,25,80,110,139,143,443,445,3389,5900
    def Scan(self):
        cprint(f"\n[I] Начало сканирования портов хоста: {self.ip}", "cyan")
        process=subprocess.run(f'''nmap -sV {self.ip} -oX {self.resfilname}''', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if process.returncode != 0:
            cprint("[!] Возникли ошибки при вызове nmap", "yellow")
        else:
            self.ParseXml()
            cprint(f"[I] Результаты были записаны в файл: {self.resfilname}", "magenta")
            
if __name__ == "__main__":
    PS = PreScan('127.0.0.1')
    PS.Scan()
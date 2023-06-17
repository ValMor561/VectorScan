import subprocess
import xml.etree.ElementTree as ET
import os
import re
from termcolor import cprint

class NmapScan():

    def __init__(self,src, port):
        self.port = port
        self.ip = src
        self.resdir = f"scanresult/{self.ip}/web/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)

    def PrintResult(self,filename):
        tree = ET.parse(f"{self.resdir}{filename}")
        root = tree.getroot()
        for host in root.iter('host'):
            for port in host.iter('port'):
                    for script in port.iter('script'):
                        scriptid = script.get('id')
                        res = script.get('output')
                        cprint(f'\t[I] Выполнен скрипт: {scriptid}',"magenta")
                        print(f'\t[+] Результат: {res}')

    def NmapScriptScan(self, scripts, filename):
        process=subprocess.run(f'''nmap -sV --script {scripts} -p {self.port} -oX {self.resdir}{filename} {self.ip}''', capture_output=True, text=True,shell=True)
        stdout = process.stdout
        if process.returncode != 0:
            cprint("[!] Возникли ошибки при вызове nmap", "yellow")
        return stdout

    def ScriptScan(self):
        cprint("\n[I] Запуск сканирования nmap с использованием скриптов", "magenta")
        script = "http-methods,http-title,http-trace"
        filename = "scriptscan.xml"
        data = self.NmapScriptScan(script,filename)
        self.PrintResult(filename)
    
    def CmsScan(self):
        cprint("\n[I] Попытка определить CMS с помощью nmap", "magenta")
        script = "http-devframework"
        filename = "cmsscan.xml"
        data = self.NmapScriptScan(script,filename)
        if "Couldn't determine the underlying framework or CMS." in data or script not in data:
            print("[-] Не удалось определить используемую CMS с помощью nmap ")
            return False
        match = re.search(r'http-devframework:\s*(.*?)\s*detected.\s(.*?)\n', data)
        if match:
            framework = match.group(1)
            cprint(f"[+] Получилось опередить исплозуемую CMS: {framework}", "green")
            sign = match.group(2)
            cprint(f"[+] По признаку: {sign}", "green")
            return True
    
    def HttpEnum(self):
        cprint("\n[I] Попытка найти важные дирректории с помощью nmap", "magenta")
        script = "http-enum"
        filename = "enumscan.xml"
        res_dir = set()
        data = self.NmapScriptScan(script,filename)
        if script not in data:
            print("[-] Не удалось найти важные дирректории с помощью nmap ")
            return False
        res = re.findall(r'((?<=\|   )\/\S*):(.*?)\n', data)
        for dir in res:
            cprint(f"[+] Найдена директория: {dir[0]} которая является: {dir[1]}", "green")
            res_dir.add(f"http://{self.ip}:{self.port}{dir[0]}")
        cprint(f"[+] Всего: {len(res)} дирректорий", "green")
        return res_dir

if __name__ == '__main__':
    NS = NmapScan("127.0.0.1")
    NS.WPEnum()
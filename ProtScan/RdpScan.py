from termcolor import cprint
from ProtScan.MyNmap import *
import os
import re

class RdpScan:

    def __init__(self, src, port):
        self.src = src
        self.port = port
        self.resdir = f"scanresult/{self.src}/rdp/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)
    
    def ScriptScan(self):
        cprint("\n[I] Сканирование с использованием скриптов", "magenta")
        script = "rdp-enum-encryption,rdp-ntlm-info"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptscan.xml") != False:
            ParseXML(f"{self.resdir}scriptscan.xml")

    def CheckMS12020(self):
        cprint("\n[I] Попытка определить уязвима ли система к MS12-020", "magenta")
        script = "rdp-vuln-ms12-020"
        data = StartScan(self.src,self.port,script,f"{self.resdir}ms12020.xml")
        state = re.search(r'State:\s(.*?)\n', data)
        if state and state[1] == "VULNERABLE":
            cprint("[+] Система уязвима к MS12-020", "green")
        else:
            print("[-] Система не уязвима к MS12-020")

    
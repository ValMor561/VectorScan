from termcolor import cprint
from ProtScan.MyNmap import *
import os
import re

class VncScan:

    def __init__(self, src, port):
        self.src = src
        self.port = port
        self.resdir = f"scanresult/{self.src}/vnc/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)
    
    def ScriptScan(self):
        cprint("\n[I] Запуск других скриптов nmap", "magenta")
        script = "vnc-info,vnc-title"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptres.xml") != False:
            ParseXML(f"{self.resdir}scriptres.xml")

    def CheckAuthByPass(self):
        cprint("\n[I] Попытка определить уязвима ли система CVE-2006-2369", "magenta")
        script = "smtp-vuln-cve2011-1764"
        data = StartScan(self.src,self.port,script,f"{self.resdir}eternalblue.xml")
        state = re.search(r'State:\s(.*?)\n', data)
        if state and state[1] == "VULNERABLE":
            cprint("[+] Система уязвима к CVE-2006-2369", "green")
        else:
            print("[-] Система не уязвима к CVE-2006-2369")

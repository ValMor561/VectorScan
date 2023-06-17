from termcolor import cprint
from ProtScan.MyNmap import *
import os

class TelnetScan:

    def __init__(self, src, port):
        self.src = src
        self.port = port
        self.resdir = f"scanresult/{self.src}/telnet/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)
    
    def ScriptScan(self):
        cprint("\n[I] Запуск других скриптов nmap", "magenta")
        script = "telnet-ntlm-info,telnet-encryption"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptres.xml") != False:
            ParseXML(f"{self.resdir}scriptres.xml")

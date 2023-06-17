from smb.SMBConnection import SMBConnection
from termcolor import cprint
from ProtScan.MyNmap import *
import os
import re

class SmbScan:

    def __init__(self, src, port):
        self.src = src
        self.port = port
        self.resdir = f"scanresult/{self.src}/smb/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)
    
    def ScriptScan(self):
        cprint("\n[I] Сканирование с использованием скриптов", "magenta")
        script = "smb-enum-users,smb-enum-shares"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptscan.xml") != False:
            ParseXML(f"{self.resdir}scriptscan.xml")


    def OsDiscovery(self):
        cprint("\n[I] Попытка определить операционную систему", "magenta")
        script = "smb-os-discovery"
        data = StartScan(self.src,self.port,script,f"{self.resdir}osdiscovery.xml")
        
        os = re.search(r'OS:\s(.*?)\n', data)
        if os:
            cprint(f"[+] Получилось определить операционную систему: {os[1]}", "green")
        else:
            print("[-] Не удалось определить оперционную систему")
        
        oscpe = re.search(r'OS\sCPE:\s(.*?)\n', data)
        if oscpe:
            cprint(f"[+] Получилось определить ядро операционной системы: {oscpe[1]}", "green")
        else:
            print("[-] Не удалось определить ядро оперционной системы")
        
        domain = re.search(r'Domain\sname:\s(.*?)\n', data)
        if domain:
            cprint(f"[+] Получилось определить имя домена: {domain[1]}", "green")
        else:
            print("[-] Не удалось определить имя домена")
            
        computer = re.search(r'Computer\sname:\s(.*?)\n', data)
        if computer:
            cprint(f"[+] Получилось определить имя компьтера: {computer[1]}", "green")
        else:
            print("[-] Не удалось определить имя компьютера")
            
    def CheckEternalBlue(self):
        cprint("\n[I] Попытка определить уязвима ли система к Eternal Blue", "magenta")
        script = "smb-vuln-ms17-010"
        data = StartScan(self.src,self.port,script,f"{self.resdir}eternalblue.xml")
        state = re.search(r'State:\s(.*?)\n', data)
        if state and state[1] == "VULNERABLE":
            cprint("[+] Система уязвима к Eternal Blue", "green")
        else:
            print("[-] Система не уязвима к Eternal Blue")

    def SmbBrute(self):
        cprint("\n[I] Начало перебора учетных данных к серверу SMB", "magenta")
        with open(os.path.join("dict","user-test.txt"), 'r') as file:
            userlist = [line.strip() for line in file]
        with open(os.path.join("dict","password-test.txt"), 'r') as file:
            passlist = [line.strip() for line in file]       
        
        for user in userlist:
            for passwd in passlist:
                try:
                    conn = SMBConnection(user, passwd, "client", self.src,  use_ntlm_v2 = True)
                    result = conn.connect(self.src, self.port)
                    if result:
                        cprint(f"[+] Успешный вход с данными: {user} {passwd}", "green")
                        conn.close()
                        return True
                except:
                    cprint("[!] Не удалось установить подключение", "yellow")
                    conn.close()
                    return False
        conn.close()
        print("[-] Не удалось подобрать учетные данные")
        return False


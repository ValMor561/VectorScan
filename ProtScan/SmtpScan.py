import smtplib 
from termcolor import cprint
from ProtScan.MyNmap import *
import os
import re

class SmtpScan:

    def __init__(self, src, port):
        self.src = src
        self.port = port
        self.resdir = f"scanresult/{self.src}/smtp/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)
    
    def ScriptScan(self):
        cprint("\n[I] Запуск других скриптов nmap", "magenta")
        script = "smtp-enum-users,smtp-ntlm-info,smtp-commands"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptres.xml") != False:
            ParseXML(f"{self.resdir}scriptres.xml") 

    def CheckOpenRelay(self):
        cprint("\n[I] Попытка определить уязвим ли сервер к ретрансляции почты", "magenta")
        script = "smtp-open-relay"
        data = StartScan(self.src,self.port,script,f"{self.resdir}openrelay.xml")
        if "Server is an open relay" in data:
            cprint("[+] Система уязвим к ретрансляции", "green")
        else:
            print("[-] Система не уязвим к ретрансляции")

    def CheckCVE1764(self):
        cprint("\n[I] Попытка определить уязвима ли система CVE-2011-1764", "magenta")
        script = "smtp-vuln-cve2011-1764"
        data = StartScan(self.src,self.port,script,f"{self.resdir}eternalblue.xml")
        state = re.search(r'State:\s(.*?)\n', data)
        if state and state[1] == "VULNERABLE":
            cprint("[+] Система уязвима к CVE-2011-1764", "green")
        else:
            print("[-] Система не уязвима к CVE-2001-1764")


    def SmtpBrute(self):
        cprint("\n[I] Начало перебора учетных данных к почтовому клиенту", "magenta")
        with open(os.path.join("dict","user-test.txt"), 'r') as file:
            userlist = [line.strip() for line in file]
        with open(os.path.join("dict","password-test.txt"), 'r') as file:
            passlist = [line.strip() for line in file]       
        try:
            smtp = smtplib.SMTP(self.src)
        except smtplib.SMTPConnectError:
            print("[-] Не удалось подключиться к почтовому серверу")
            return False
        for user in userlist:
            for passwd in passlist:
                try:
                    smtp.login(user, passwd)
                    print("[+] Успешный вход с данными: ", user, passwd)
                    smtp.quit()
                    return True
                except smtplib.SMTPAuthenticationError: 
                    smtp.quit()
                    continue
                except:
                    break
        print("[-] Не удалось подобрать учетные данные")
        return False

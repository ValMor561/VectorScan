import sys
import argparse
import socket
from urllib.parse import urlparse
import PreScan
from ProtScan import FtpScan
from ProtScan import SshScan
from ProtScan import SmtpScan
from ProtScan import RdpScan
from ProtScan import SmbScan
from ProtScan import TelnetScan
from ProtScan import VncScan
from WebScan import WebScan
import re
from termcolor import cprint



def arg_parse():
    parser = argparse.ArgumentParser(description='Приложение для построение вектора атаки')
    parser.add_argument('-a','--adress', help="IP адресс на который проводится атака")
    parser.add_argument('-u','--url', help="URL адресс на который проводится атака")
    parser.add_argument('-w','--web', help="Запустить только сканирование веб", action="store_true")
    parser.add_argument('-p','--ports', help="Запустить только сканирование открытых портов", action="store_true")
    parser.add_argument('-wb','--withoutbrute', help="Не запускать перебор паролей", action="store_true")
    return parser.parse_args(sys.argv[1:])

def valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_ip(namespace):
    if namespace.adress:
        ip_addr = namespace.adress
        cprint("[I] Сканируется Ip " + namespace.adress, "magenta")
    elif namespace.url:
        if not valid_url(namespace.url):
            cprint("[!] Ошибка! Ваша ссылка в неверном формате, пример ссылки http://example.com.", "yellow")
            sys.exit(1)
        ip_addr = CheckIp(namespace.url)
        cprint("[I] Сканируется ссылка " + namespace.url, "magenta")
        cprint("[I] Ip: " + ip_addr, "magenta")
    return ip_addr

def CheckIp(url):
        match = re.search(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)',url)
        if match:
            return match.group(1)
        domain_name = urlparse(url).netloc
        try:
            ip = socket.gethostbyname(domain_name)
        except socket.gaierror as e:
           cprint('[!] Ошибка! Проверьте правильность вашей ссылки', "yellow")
        return ip
def main():
    namespace = arg_parse()
    ip_addr = get_ip(namespace)
    #ip_addr = "10.10.123.243"
    url_addr = None
    if namespace.url:
        url_addr = namespace.url
    wbflag = False
    if namespace.withoutbrute:
        wbflag = True
    if namespace.web and url_addr != None:
        WB = WebScan.HttpScan(url_addr)
        WB.Scan()
        return
    elif namespace.web and url_addr == None:
        WB = WebScan.HttpScan(ip_addr)
        WB.Scan()
        return
    PS = PreScan.PreScan(ip_addr)
    PS.Scan()
    if namespace.ports:
        return
    for port in PS.openport:
        match port:
            case "21":
                cprint("\n[I] Начало сканирования FTP", "cyan")
                FT = FtpScan.FtpScan(ip_addr)
                FT.SctipScan()
                FT.CheckAnon()
                FT.FtpSyst()
                if not wbflag:
                    FT.FtpBrute()
            case "22":
                cprint("\n[I] Начало сканирования SSH", "cyan")
                SH = SshScan.SshScan(ip_addr)
                SH.ScriptScan()
                if not wbflag:
                    SH.SshBrute()
            case "23":
                cprint("\n[I] Начало сканирования Telnet", "cyan")
                TN = TelnetScan.TelnetScan(ip_addr, port)
                TN.ScriptScan()
            case "25" | "110" | "143":
                cprint(f"\n[I] Начало сканирования SMTP - {port} порт", "cyan")
                SM = SmtpScan.SmtpScan(ip_addr, port)
                SM.ScriptScan()
                SM.CheckCVE1764()
                SM.CheckOpenRelay()
                if not wbflag:
                    SM.SmtpBrute()
            case "80" | "443":
                WB = WebScan.HttpScan(ip_addr)
                WB.Scan()
            case "139" | "445":
                cprint(f"\n[I] Начало сканирования SMB - {port} порт", "cyan")
                SMB = SmbScan.SmbScan(ip_addr, port)
                SMB.ScriptScan()
                SMB.CheckEternalBlue()
                SMB.OsDiscovery()
                if not wbflag: 
                    SMB.SmbBrute()
            case "3389":
                cprint("\n[I] Начало сканирования RDP", "cyan")
                RD = RdpScan.RdpScan(ip_addr, port)
                RD.ScriptScan()
                RD.CheckMS12020()
            case "5900":
                cprint("\n[I] Начало сканирования VNC", "cyan")
                VC = VncScan.VncScan(ip_addr, port)
                VC.ScriptScan()
                VC.CheckAuthByPass()

        if  url_addr != None:
            WB = WebScan.HttpScan(url_addr)
            WB.Scan()

if __name__ == "__main__":
    main()
from urllib.parse import urlparse
from WebScan.GetInternalLink import GetInternalLinks
from WebScan.VulnScan import VulnScan
from WebScan.MetaScan import MetaScan
from WebScan.CMSScan import CMSScan
from WebScan.NmapScan import NmapScan
from termcolor import cprint
import re
import socket

class HttpScan:
    def __init__(self,src,depth = 5) -> None:
        self.src = src
        self.ip = ""
        self.url = ""
        self.port = self.GetPort(self.src)
        self.PrepareSrc()
        self.depth = depth
        self.url_set = set()
    
    
    def GetPort(self, src):
        parsed_url = urlparse(src)
        if parsed_url.port is None:
            return '80'
        else:
            return str(parsed_url.port)

    def CheckIp(self,src):
        match = re.search(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b)',src)
        if match:
            return match.group(1)
        self.port = self.GetPort(src)
        domain_name = urlparse(src).netloc
        try:
            ip = socket.gethostbyname(domain_name)
        except socket.gaierror as e:
           cprint('[!] Ошибка! Проверьте правильность вашей ссылки', "yellow")
        return ip

    def PrepareSrc(self):
        parsed = urlparse(self.src)
        if bool(parsed.netloc) and bool(parsed.scheme):
            self.url = self.src
            self.ip = self.CheckIp(self.src)
        else:
            self.ip = self.src
            self.url = f"http://{self.src}/"

    def Scan(self):
        cprint(f"\n[I] Начало сканирования: {self.url}", "cyan")
        CMS_known = False
        GI = GetInternalLinks(self.url, self.depth)
        self.url_set = GI.Scan()
        self.url_set = self.url_set.union(GI.DirSearch())
        NM = NmapScan(self.ip, self.port)
        self.url_set = self.url_set.union(NM.HttpEnum())
        NM.ScriptScan()
        for urls in self.url_set:
            MS = MetaScan(urls)
            MS.Scan()
            VS = VulnScan(urls)
            VS.ScanAll()
            CMS_known = NM.CmsScan()
            if not CMS_known:
                CS = CMSScan(urls, self.port)
                CMS_known = CS.Scan()

if __name__ == "__main__":
    WB = HttpScan("10.10.123.243")
    WB.Scan()
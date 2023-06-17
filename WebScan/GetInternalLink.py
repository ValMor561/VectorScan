from urllib.parse import urlparse, urljoin
import re
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from termcolor import cprint
import os

#производится рекурсивный обход сайта и поиск всех подсылок
class GetInternalLinks:
    
    def __init__(self, url, depth = 5):
        self.url = url
        self.depth = depth
        self.url_set = set()
        self.url_set.add(url)
        self.visited_urls = 0
        self.user_agent = {
            'User-Agent': UserAgent().random
        }

    def getHtml(self, url):
        try:
            result = requests.get(url, headers=self.user_agent)
            return result

        except(requests.RequestException, ValueError):
            cprint('[!] Не удалось получить html код страницы', "yellow")
            return False
        
    
    
    def valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def website_links(self, url):
        urls = set()
        domain_name = urlparse(url).netloc
        response = self.getHtml(url)
        soup = BeautifulSoup(response.content, "html.parser")
        if soup == False or soup.html is None:
            return
        if not(soup.html.findAll("a") is None):
            for a_tag in soup.html.findAll("a"):
                href = a_tag.attrs.get("href")
                if href == "" or href is None:
                    continue
                href = urljoin(url, href)
                parsed_href = urlparse(href)
                href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
                if re.search("/\S*[.]",parsed_href.path) != None:
                    continue
                if domain_name != parsed_href.netloc:
                    continue
                if not self.valid_url(href):
                    continue
                if href in self.url_set:
                    continue
                self.url_set.add(href)
                urls.add(href)
        return urls
    
                
    def check_all_links(self, url):
        self.visited_urls += 1
        links = self.website_links(url)
        if not(links is None):
            for link in links:
                if self.visited_urls > self.depth:
                    break
                self.check_all_links(link)

    def DirSearch(self):
        cprint("\n[I] Начало перебора директорий", "magenta")
        with open("dict\dir-small.txt", 'r') as file:
            dirlist = [line.strip() for line in file]
        res_dir = set()
        self.url = os.path.dirname(self.url)
        for dir in dirlist:
            if self.url.endswith('/'):
                url = self.url.strip('/')
            else:
                url = self.url
            url = url + "/" + dir
            response = self.getHtml(url)
            if response == False:
                continue
            if response.status_code == 200:
                res_dir.add(url)
                cprint("[+] Найдена директория: " + url, "green")
        if len(res_dir) == 0:
            print("[-] Не найдено директорий")
        return res_dir

    def Scan(self):
        cprint(f"[I] Рекурсивный обход по ссылки с глубиной: {self.depth}", "magenta")
        self.check_all_links(self.url)
        cprint(f"[+] Найдено: {len(self.url_set)} ссылок", "green")
        return self.url_set
    
if __name__ == "__main__":
    GT = GetInternalLinks("https://ru.wikipedia.org/wiki/")
    #GT.Scan()
    GT.DirSearch()
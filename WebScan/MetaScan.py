import requests
from bs4 import BeautifulSoup
import re
import json
from fake_useragent import UserAgent
from termcolor import cprint


class MetaScan:
    def __init__(self, src):
        self.user_agent = {
            'User-Agent': UserAgent().random
        }
        self.src = src
        self.response = requests.get(src, headers=self.user_agent)
        self.soup = BeautifulSoup(self.response.content, 'html.parser')

    def EmailScan(self):
        cprint("\n[I] Поиск email на странице", "magenta")
        emails = re.findall(r'\b[\S]+@[\S]+\.[A-Z|a-z]{2,}\b', self.response.text)
        if len(emails) != 0:
            cprint("[+] Найдены следующие email:","green")
            for email in emails:
                cprint(f"[+] {email}", "green")
            cprint(f"[+] Всего: {len(emails)}", "green")
        else:
            print("[-] Не найдено email на странице")
        
    def PhoneInfo(self, phone):
        cprint(f"[I] Поиск информации о номере {phone}", "magenta")
        url = "https://api.veriphone.io/v2/verify?phone={}&key=31229C1A53E5498E92B9C368675A8FC0"
        phone = phone.replace(" ", "")
        req = requests.get(url.format(phone))
        if req.status_code != 200:
            cprint("[!] Не удалось получить информацию о номере", "yellow")
            return
        res = json.loads(req.text)
        if res['status'] == "error":
            cprint("[!] Не удалось получить информацию о номере", "yellow")
            return
        cprint(f"\t[I] Тип номера: {res['phone_type']}", "cyan")
        cprint(f"\t[I] Страна: {res['country']}", "cyan")
        cprint(f"\t[I] Провайдер: {res['carrier']}", "cyan")

    def PhoneScan(self):
        cprint("\n[I] Поиск номеров телефона на странице", "magenta")
        phones = re.findall(r'\+?\d{1,3}\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}', self.response.text)
        if len(phones) != 0:
            cprint("[+] Найдены следующие номера:", "green")
            for phone in phones:
                cprint(f"[+] {phone}", "green")
                self.PhoneInfo(phone)
            cprint(f"[+] Всего: {len(phones)}", "green")
        else:
            print("[-] Не найдено номеров телефона на странице")

    def CommentScan(self):
        cprint("\n[I] Поиск комментариев на странице", "magenta")
        comments = re.findall(r'<!--[\s\S]*?-->', self.response.text)
        if len(comments) != 0:
            cprint("[+] Найдены следующие комментарии:", "green")
            for comment in comments:
                cprint(f"[+] {comment}", "green")
            cprint(f"[+] Всего: {len(comments)}", "green")
        else:
            print("[-] Не найдено комментариев на странице")

    def VersionsScan(self):
        cprint("\n[I] Поиск упоминаний версий чего-либо", "magenta")
        versions = re.findall(r'(?i)\w+\b\s+version\s+[^\s]+', self.response.text)
        if len(versions) != 0:
            cprint("[+] Найдены следующие упоминания:", "green")
            for version in versions:
                cprint(f"[+] {version}", "green")
            cprint(f"[+] Всего: {len(versions)}", "green")
        else:
            print("[I] Не найдено упоминаний версий на странице")

    def PasswordScan(self):
        cprint("\n[I] Поиск упоминаний каких-либо паролей", "magenta")
        passwords = re.findall(r'(?i)pass[\S]*:?-?\s+\b\w+', self.response.text)
        if len(passwords) != 0:
            cprint("[+] Найдены следующие упоминания:", "green")
            for password in passwords:
                cprint(f"[+] {password}", "green")
            cprint(f"[+] Всего: {len(passwords)}", "green")
        else:
            print("[-] Не найдено упоминаний паролей на странице")


    def EmailGenerator(self,username):
        cprint("\t[I] Попытка определить почту по имени пользователя", "magenta")
        with open("/dict/email.json") as file:
            edomains = json.load(file)
        listuser = [
        username.replace(" ",""),
        username.replace(" ","")+"123",
        username.replace(" ","")+"1234",
        username.replace(" ","")+"321",
        username.replace(" ","").upper()
        ]
        count = 0
        for user in listuser:
            for domain in edomains:
                email = user + "@" + domain
                api = "gnG5y5Oh"
                response = requests.post(
                    "https://app.mailvalidation.io/a/validate/api/validate/",
                    json={'email': email},
                    headers={
                            'content-type': 'application/json',
                            'accept': 'application/json',
                            'Authorization': 'Api-Key ' + api,
                            },
                )
                valid = response.json()['is_valid']
                if valid:
                    count += 1
                    cprint(f"\t[+] Найдена возможная почта пользователя: {username} - {email}", "green")
        if count == 0:
            print("\t[-] Не удалось определить почту по имени пользователя")

    def FindUsersConnections(self, username):
        cprint("\t[I] Попытка найти аккаунт пользователя на других сайтах", "magenta")
        with open("/dict/sites.json") as file:
            urllist = json.load(file)
        count = 0
        for url in urllist:
            try:
                req = requests.get(url.format(username), headers=self.user_agent)
                if req.status_code == 200:
                    cprint(f"\t[+] Найден возможный аккаунт пользователя: {url.format(username)}", "green")
                    count += 1
            except requests.exceptions.ConnectionError: continue
        if count == 0:
            print("\t[-] Не удалось найти аккаунт пользователя на других сайтах")

    def UsernamesScan(self):
        cprint("\n[I] Поиск имен пользователей на странице", "magenta")
        #поиск класcов с именем username
        usernames =  self.soup.find_all('a', class_='username')
        if len(usernames) != 0:
            cprint("[+] Найдены следующие имена пользователей:", "green")
            for username in usernames:
                cprint(f"[+] {username}", "green")
                self.EmailGenerator(username)
                self.FindUsersConnections(username)
            #поиск строчек содержащих login
            logins = re.findall(r'(?i)login]=?:?\s?[\S]+', self.response.text)
            if len(logins) != 0:
                for login in logins:
                    cprint(f"[+] {login}", "green")
                    login = login.split(" ")
                    self.EmailGenerator(login[1])
                    self.FindUsersConnections(login[1])
            cprint(f"[+] Всего: {len(usernames) + len(logins)}", "green")
        else:
            print("[-] Не найдено упоминаний имен пользователей на странице")
    
    def Scan(self):
        cprint(f"\n[I] Поиск чувствительной информации по адресу: {self.src}", "cyan")
        self.CommentScan()
        self.PhoneScan()
        self.EmailScan()
        self.UsernamesScan()
        self.VersionsScan()
        self.PasswordScan()

if __name__ == "__main__":
    self = MetaScan("https://valmor561.github.io/MosDom-Expert/")
    self.Scan()
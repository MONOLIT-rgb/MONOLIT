import sys

def clear():
    sys.stdout.write('\033[H\033[J')
    sys.stdout.flush()

try:
    from colorama import init, Fore, Style
    import time
    import os
    import socket
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from datetime import datetime
    import concurrent.futures
    import webbrowser
    import platform
    import struct
    import pyfiglet
    import subprocess
except ImportError as e:
    print("Скачай библиотеки pip install colorama rich requests pyfiglet scapy")
    
def text(text):
    print("")
    return pyfiglet.figlet_format(text, font="ansi_shadow")
 

api_key = "at_gXluvsZNGXUchVzcGWvTTZ3zQOFDA"

init()
        
c = Console()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
purpl = Fore.MAGENTA

reset = Fore.RESET

menu_text = f"""{purpl}│{reset}{green}1.пробив по IP(Полная инфа)                 2.пробив IP(Рашифровка){reset}{purpl}   │{reset}
{purpl}│{reset}{green}3.Поиск открытых портов                     4.Информация об MAC{reset}{purpl}       │{reset}
{purpl}│{reset}{red}Для вихода - exit                           Для фикса меню - fix{reset}{purpl}      │{reset}
{purpl}│{reset}{blue}Калькутор - calc                      Проверка rich - colors{reset}{purpl}          │{reset}
{purpl}│{reset}{blue}Мой IP адресс - myip                        Информация - info {reset}{purpl}        │{reset}
{purpl}│{reset}{yellow}О создателе - creator                       О проекте - project{reset}{purpl}       │{reset}
{purpl}│{reset}{purpl}                          servers - sv                                │{reset}
{purpl}│{reset}{purpl}                        console - console                             │{reset}"""
   
   
def keyboard():
    if os.name == "nt":
        import msvcrt
        def get_char():
            return msvcrt.getch().decode('utf-8')
        char = get_char()
    else:
        import tty
        import termios
        def get_char():
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
        char = get_char()
    return char

def window(w_name, texts, weight, height, t_color="#FFFFFF", w_color="#FFFFFF"):
    console = Console()
    w = len(w_name)
    weight_n = weight - 1 - w
    tx_cl_lines = []
    for text in texts:
        t = len(text)
        if t > weight:
            text = text[:weight] 
            t = weight
        weight_t = weight - t
        text_line = f"[{t_color}]│[/][{t_color}]{text}[/][{w_color}]{' ' * weight_t}│[/]"
        tx_cl_lines.append(text_line)
    
    empty_line = f"[{w_color}]│[/]{' ' * weight}[{w_color}]│[/]"
    while len(tx_cl_lines) < height:
        tx_cl_lines.append(empty_line)
    
    window_lines = "\n".join(tx_cl_lines)
    window_text = f"[{w_color}]\n┌{w_name}{'─' * weight_n}[red]x[/]┐[/]\n{window_lines}\n[{w_color}]└{'─' * weight}┘[/]"
    
    console.print(window_text)
   
   
def ip_1(ip):
    def get_hostname_by_ip(ip_address):
        try:
            hostname, alias, ip = socket.gethostbyaddr(ip_address)
            return hostname
        except socket.herror as e:
            return f"Не удалось определить имя хоста для IP-адреса {ip_address}: {e}"

    def get_whois_info(ip_address):
        try:
            response = requests.get(f"https://rdap.arin.net/registry/ip/{ip_address}")
            return response.json()
        except Exception as e:
            return f"Не удалось получить информацию WHOIS для IP-адреса {ip_address}: {e}"

    def get_geoip_info(ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            return response.json()
        except Exception as e:
            return f"Не удалось получить информацию GeoIP для IP-адреса {ip_address}: {e}"

    def ip_info(ip):
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                print(data)
                return data
            else:
                return f"Не удалось получить информацию об IP: {ip}"
        except requests.exceptions.RequestException as e:
            return f"Произошла ошибка при запросе: {e}"
        
    hostname = get_hostname_by_ip(ip)
    whois_info = get_whois_info(ip)
    geoip_info = get_geoip_info(ip)
    print(f"Имя устройства для IP-адреса {ip}: {hostname}")
    print(f"Информация WHOIS для IP-адреса {ip}: {whois_info}")
    print(f"Информация GeoIP для IP-адреса {ip}: {geoip_info}")

def ip_2(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    c = Console()
    table = Table(title="Информация о IP-адресе")

    table.add_column("Параметр", style="cyan", no_wrap=True)
    table.add_column("Значение", style="magenta")

    for key, value in data.items():
        table.add_row(key, str(value))
    c.print(table)
    

def public_ip():
    response = requests.get('https://api.ipify.org?format=json')
    data = response.json()
    return data['ip']

def local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def color(text, color):
    print(color + text + reset)
def rich(text, color):
    c.print(text, style=color)

mlogo = text("monolit")   
def start():
    def logo():
        print("")
        rich(mlogo, "#205670")
        color("    CODE BY TIMONO", yellow)
        color("""    Github: https://github.com/TimonoTV
    """, red)
        
    def menu():
        color("┌" + "─" * 70 + "┐", purpl)
        print(menu_text)
        color("└" + "─" * 70 + "┘", purpl)
        print("")
    
    clear()
    logo()
    menu()
    
start()

def q():
    q = input(blue + "Для вихода в меню нажмите Enter..." + reset)
    start()
    
def creator():
    m = """
Слава Монолиту!
Во славу Монолита!
Монолит зовет нас!
Мы едины с Монолитом!
Монолит, направь нас!
Монолит, защити нас!
Во имя Монолита!
Смерть врагам Монолита!
Монолит ведет нас к победе!
Монолит — наша вера и сила!

amd fx6300 6cores, gigabyte gtx750
"""
    rich(m, "#fa8d07")
    
def project():
    project = """О проекте:
проект создан как инструмент для Termux
написан на язике Python
использовать моожно как хотите
"""
    rich(project, "#9907fa")
    color("Удачи вам)", purpl)



def wifi():
    import pywifi
    from pywifi import PyWiFi, const, Profile
    
    clear()
    wifi.logo = text("wifi-tools")
    rich(wifi.logo, "#16ebfa")
    def wifi_scan():
        wifi = PyWiFi()
        iface = wifi.interfaces()[0]     
        iface.scan()
        time.sleep(4)
        results = iface.scan_results()
        networks = {}  
        for network in results:
            ssid = network.ssid
            bssid = network.bssid
            signal = network.signal
            freq = network.freq
            network_info = (ssid, bssid, signal, freq)
            networks[bssid] = network_info           
        for bssid, network_info in networks.items():
            ssid, bssid, signal, freq = network_info
            window("wifi", [f"Названия: {ssid}", f"MAC: {bssid}", f"Сигнал: {signal}", f"Радиочастота: {freq}"], 118, 4, t_color="#ad05f5", w_color="#f505cd")
            mac_info = get_mac_full(bssid, api_key)
            window("Mac", [f"Названия: {ssid}", f"MAC-адрес: {mac_info['macAddressDetails']['searchTerm']}", f"Компания: {mac_info['vendorDetails']['companyName']}", f"Страна: {mac_info['vendorDetails']['countryCode']}", f"Тип устройства: {mac_info['blockDetails']['blockFound']}", f"Начало блока: {mac_info['blockDetails']['borderLeft']}", f"Конец блока: {mac_info['blockDetails']['borderRight']}"], 118, 5, t_color="#20f52a", w_color="#0e41e8")

    wifi_scan()
    
    
def cr_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, int(port)))
    server_socket.listen(5)
    print(f"Server started on IP {ip} and port {port}")
    
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Подключен клиент: {client_address}")
        data = client_socket.recv(1024)
        print(f"Получено: {data.decode('utf-8')}")
        client_socket.close()

def client(ip, port, r):
    try:
        for _ in range(r):
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((ip, port))
            print(f"Подключено к серверу {ip}:{port}")
            message = input(red + "message: " + reset)
            client_socket.sendall(message.encode())
            response = client_socket.recv(1024)
            print(f"Ответ от сервера: {response.decode()}")
            client_socket.close()
    except Exception as e:
        print(f"Ошибка: {e}")

def DOS_client(ip, port, sms, r):
    for i in range(r):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        message = sms
        print(sms)
        client_socket.sendall(message.encode())
        response = client_socket.recv(1024)
        client_socket.close()


def servers():
    clear()
    rich("beta obcidian.on", "#790987")
    menu = """
server 
  |_ 1.server create
      |_ 1.system
      |_ 2.local

client
  |_ 1.client connect
      |_ 1.client connect(message)
      |- 2 client connect(messages)
  |_ 2.client attack
      |_ 1.DOS client"""
    rich(menu, "#019880")
    op = input(purpl + "Вибрать опцию: " + reset)
    if op == "menu":
        q()
    if op == "server":
        server = input(blue + "Действие с сервером: " + reset)
        if server == "1":
            type_server = input(yellow + "Тип сервера: " + reset)
            if type_server == "1":
                port = int(input(green + "server port: "))
                print(reset)
                cr_server("127.0.0.1", port)
            if type_server == "2":
                ip = input(green + "server ip: ")
                port = input("server port: ")
                print(reset)
                cr_server(ip, port)
    if op == "client":
        type_client = input(blue + "Тип клиента: " + reset)
        if type_client == "1":
            con = input(yellow + "Настройки подлючения:" + reset)
            if con == "1":
                ip = input(green + "server ip: ")
                port = int(input("server port: "))
                print(reset)
                client(ip, port, 1)
            if con == "2":
                ip = input(green + "server ip: ")
                port = int(input("server port: "))
                print(reset)
                client(ip, port, 1000)
        if type_client == "2":
                atk = input(yellow + "Настройки подлючения:" + reset)
                if atk == "1":
                    ip = input(green + "server ip: ")
                    port = int(input("server port: "))
                    sms = input("Передай серверу привет): ")
                    print(reset)
                    r = int(input(red + "сколько DOS сообшений: " + reset))
                    DOS_client(ip, port, sms, r)
        
    q()


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)
    try:
        sock.connect((ip, port))
        return port
    except:
        return None
    finally:
        sock.close()
def scan_ports(ip, start_port, end_port):
    open_ports = []
    print(green + f"Начало сканирования {ip}..." + reset)
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Ошибка при сканировании порта {port}: {e}")

    end_time = datetime.now()
    total_time = end_time - start_time
    print(blue + f"Сканирование завершено за {total_time}" + reset)
    if open_ports:
        print(yellow + "Открытые порты:" + reset)
        for port in open_ports:
            print(yellow + f"Порт {port} открыт" + reset)
    else:
        print(red + "Открытых портов не найдено" + reset)

    return open_ports

def get_mac(mac):
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return "Информация не найдена"
def get_mac_full(mac, api_key):
    url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={mac}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
    
def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=1)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def print_all_colors():
    for color_code in range(256):
        block = "■"
        c.print(block, end=" ", style=f"color({color_code})")
        if (color_code + 1) % 16 == 0:
            c.print()
        time.sleep(0.01)
        
def debug():
    clear()
    while True:
        a = input()
        rich("print", f"#{a}")

def unistaller():
    global wind
    print(red + "Для удаления нажмите y" + reset)
    key = keyboard()
    if key == "y":
        print("Удачи ):")
        time.sleep(0.5)
        os.remove("MONOLIT.py")
        wind = False
        clear()
def update():
    global wind
    print(red + "Для удаления нажмите y" + reset)
    key = keyboard()
    if key == "y":
        rich("Обновления...", "#ed0c53")
        time.sleep(0.5)
        os.remove("MONOLIT.py")  
        url = 'https://github.com/MONOLIT-rgb/MONOLIT/MONOLIT.py'
        response = requests.get(url)
        with open("MONOLIT.py", "wb") as file:
            file.write(response.content)
        wind = False
        rich("Все скачано запуск...", "#0ced84")
        clear()
        os.system("MONOLIT.py")
    

wind = True
while wind:
    vod = input(green + "MONOLIT: " + reset)
    if vod == "1":
        clear()
        ip = input(yellow + "Веддите IP: " + reset)
        print(green + "Пробив..." + reset)
        time.sleep(0.5)
        if ip == "":
            print(red + "Пустой IP" + reset)
            q()
        else:
            ip_1(ip)
            q()
    elif vod == "2":
        clear()
        ip = input(yellow + "Веддите IP: " + reset)
        print(green + "Пробив..." + reset)
        time.sleep(0.5)
        if ip == "":
            print(red + "Пустой IP" + reset)
            q()
        else:
            ip_2(ip)
            q()
    elif vod == "3":
        clear()
        ip = input(yellow + "Веддите IP: " + reset)
        if ip == "":
            print(red + "Пустой IP" + reset)
            q()
        else:
            start_port = int(input(blue + "start_port: " + reset))
            end_port = int(input(purpl + "end_port: " + reset))
            scan_ports(ip, start_port, end_port)
            q()
    elif vod == "4":
        clear()
        mac = input(yellow + "Веддите MAC: " + reset)
        if mac == "":
            print(red + "Пустой MAC" + reset)
            q()
        else:
            mac_info = get_mac_full(mac, api_key)

            if mac_info:
                rich(f"MAC-адрес: {mac_info['macAddressDetails']['searchTerm']}", "#386975")
                rich(f"Компания: {mac_info['vendorDetails']['companyName']}", "#388294")
                rich(f"Адрес компании: {mac_info['vendorDetails']['companyAddress']}", "#2fa0bd")
                rich(f"Страна: {mac_info['vendorDetails']['countryCode']}", "#1dadd1")
                rich(f"Тип устройства: {mac_info['blockDetails']['blockFound']}", "#05c1f0")
                rich(f"Начало блока: {mac_info['blockDetails']['borderLeft']}", "#0576f0")
                rich(f"Конец блока: {mac_info['blockDetails']['borderRight']}", "#0351a3")
            else:
                color("Информация не найдена или произошла ошибка при запросе.", red)
            q()
    elif vod == "inst":
        webbrowser.open("https://telegra.ph/Probivaem-informaciyu-po-IP-adresu-07-23")
    elif vod == "exit":
        wind = False
        clear()
    elif vod == "calc":
        clear()
        calc = input(yellow + "Пример: " + reset)
        print(eval(calc))
        q()
    elif vod == "fix":
        start()
    elif vod == "creator":
        creator()
        q()
    elif vod == "project":
        project()
        q()
    elif vod == "colors":
        print_all_colors()
        q()
    elif vod == "myip":
        rich("Локальний: " + local_ip(), "#300456")
        rich("Публичний: " + public_ip(), "#406900")
        q()
    elif vod == "info":
        clear()
        rich(f"Названия: {os.name}", "#4f1c91")
        rich(f"Система: {platform.system()}", "#5e18ba")
        rich(f"Название узла: {platform.node()}", "#6b18d9")
        rich(f"Версия: {platform.version()}", "#700af5")
        rich(f"Платформа: {platform.platform()}", "#9b0af5")
        rich(f"Архитектура: {platform.architecture()}", "#8a17d1")
        rich(f"Процессор: {platform.processor()}", "#801ebd")
        rich(f"Python версия: {platform.python_version()}", "#621d8c")
        rich(f"Построен на: {platform.python_build()}", "#7f1d8c")
        rich(f"Компилятор: {platform.python_compiler()}", "#9516a6")
        rich(f"Текущий каталог: {os.getcwd()}", "#b917cf")
        rich(f"Имя пользователя: {os.getlogin()}", "#d907f5")
        q()
    elif vod == "sv":
        servers()
    elif vod == "console":
        print(blue + "Для вихода - exit" + reset)
        con = True
        while con:
            console = input(yellow + "CONSOLE: ")
            if console == "exit":
                q()
                con = False
            else:
                os.system(console)
    elif vod == "wifi":
        wifi()
    elif vod == "text":
        clear()
        textvod = input(blue + "Текст которий хотите увеличить: ")
        print(text(textvod))
        q()
        
    elif vod == "ttl":
        update()
    else:
        print(red + "Команда не найдена" + reset)

#https://macaddress.io/login
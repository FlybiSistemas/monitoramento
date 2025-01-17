import time
import win32evtlog
import os
import subprocess
import threading
import ctypes
import sys
from unidecode import unidecode

processed_events = []
scan = False

def get_ips(lista_ips = []):
    r = os.popen('netstat -ano | findstr ESTABLISHED').read()
    linhas = r.split('TCP')
    for linha in linhas:
        if('443' in linha):
            ip = linha.split(':443')[0].split(' ')[-1]
            lista_ips.append(ip)
    return lista_ips

def read_security_log():
    # Esta função requer privilégios elevados, então, vamos verificar se temos permissões
    if not is_admin():
        print("Este processo precisa de permissões de administrador para ler o log de segurança.")
        return

    server = 'localhost'
    log_type = 'Security'
    event_id_to_watch = 5061
    
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        events = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        
        while events:
            for event in events:
                if event.EventID == event_id_to_watch and event.TimeGenerated not in processed_events:
                    processed_events.append(event.TimeGenerated)
                    if(scan):
                        lista = get_ips()
                        time.sleep(5)
                        lista = get_ips(lista)
                        lista = list(set(lista))
                        print('iniciando tokenservice ' + os.getcwd() + '\\TokenService.exe')
                        try:
                            subprocess.Popen([os.getcwd() + '\\TokenService.exe', 'SC', event.StringInserts[6], str(lista)])
                        except:
                            r = os.popen('"' + os.getcwd() + '\\TokenService.exe SC ' + event.StringInserts[6] + ' ' + str(lista)).read()
                        with open('C:\\monitoramento.txt', 'a') as f:
                            f.write(f"{r}\n")
                            f.write(f"{event.TimeGenerated}\n")
                            f.write('ips usados\n')
                            f.write(f"{lista}\n")
                            f.write('========================\n')
                            f.write('certificado\n')
                            f.write(f"{event.StringInserts[6]}\n")
                            f.write('========================\n')
                        print(r)
                        print(event.TimeGenerated)
                        print('ips usados\n')
                        print(lista)
                        print('========================\n')
                        print('certificado\n')
                        print(event.StringInserts[6])
                        print('========================\n')

            events = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        
        win32evtlog.CloseEventLog(handle)
    except Exception as e:
        print(f"Erro ao ler o log de eventos: {e}")

def start_scan_after_delay():
    global scan
    time.sleep(10)  # Aguarda 10 segundos
    scan = True  # Após 10 segundos, altera a variável scan para True
    print("Scan ativado após 10 segundos!")

def is_admin():
    """ Verifica se o script está sendo executado como administrador. """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """ Executa o script com privilégios de administrador. """
    if is_admin():
        return True
    else:
        script = sys.argv[0]
        params = " ".join(sys.argv[1:])
        # Reexecuta o script com privilégios elevados
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        return False

def create_schedule(tarefa, tipo, tempo, exe, admin=False):
    tarefa = unidecode(tarefa).lower() 
    admin_flag = ' /RL HIGHEST' if admin else ''
    if tipo == 1:
        comando = f'schtasks /create /sc hourly /mo {tempo} /tn "{tarefa}" /tr "\'{exe}\'"{admin_flag} /ru "SYSTEM" /np /f' 
    elif tipo == 2: 
        comando = f'schtasks /create /sc daily /tn "{tarefa}" /tr "\'{exe}\'" /st {tempo}{admin_flag} /ru "SYSTEM" /np /f' 
    elif tipo == 3: 
        comando = f'schtasks /create /sc minute /mo {tempo} /tn "{tarefa}" /tr "\'{exe}\'"{admin_flag} /ru "SYSTEM" /np /f' 
    elif tipo == 4:
        comando = f'schtasks /create /sc onlogon /tn "{tarefa}" /tr "\'{exe}\'"{admin_flag} /ru "SYSTEM" /np /f'
    print('Comando:', comando)
    r = os.popen(comando).read()
    print('Retorno:', r)
    return True

def check_schedule(tarefa):
    tarefa = unidecode(tarefa).lower()
    r = os.popen("schtasks /query").read()
    if(tarefa in r):
        return True
    return False

def check_monitor():
    r = os.popen("tasklist").read()
    if(r.count("bytokenmonitor.exe") > 2 or r.count("ByTokenMonitor.exe") > 2):
        return True
    return False

def get_user():
    try:
        user_dir = os.path.expanduser('~')
        username = os.path.basename(user_dir)
        if(username != None):
            return username
        user_dir = os.getenv('USERPROFILE')
        username = os.path.basename(user_dir)
        if(username != None):
            return username
    except (IndexError, FileNotFoundError):
        try:
            user_dir = os.getenv('USERPROFILE')
            username = os.path.basename(user_dir)
            if(username != None):
                return username
        except:
            return os.getlogin()

usuario = get_user()

if __name__ == '__main__':
    if(check_monitor()):
        sys.exit()
    if not run_as_admin():
        # Se o script não for executado como admin, só executa a parte não privilegiada
        print("Este script requer privilégios de administrador para funcionar corretamente.")
        sys.exit(0)  # Encerra o programa se não tiver permissões elevadas
    if 'install' in sys.argv:
        if not check_schedule("TokenMonitor"):
            retorno = create_schedule("TokenMonitor", 3, 2, 'C:/Program Files/ByToken/ByTokenMonitor.exe', True)
            if type(retorno) == list:
                sys.exit()
        if not check_schedule("LogonMonitor"):
            retorno = create_schedule("LogonMonitor", 4, 2, 'C:/Program Files/ByToken/ByTokenMonitor.exe', True)
            if type(retorno) == list:
                sys.exit()
        sys.exit()
    # Cria a thread para iniciar a verificação após um delay
    scan_thread = threading.Thread(target=start_scan_after_delay)
    scan_thread.start()

    while True:
        # Função que vai rodar normalmente
        read_security_log()
        time.sleep(5)

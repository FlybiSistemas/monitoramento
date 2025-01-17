from src.monitor import Monitor
import subprocess
import threading
import sys
from datetime import datetime

data_atual = datetime.now()
data_expiracao = datetime(2024, 12, 20)

if data_atual > data_expiracao:
    print('Aplicação expirada em:', data_expiracao.strftime('%d/%m/%Y'))
    exit()

def main():
    capture_thread = threading.Thread(target=m.capture_packets)
    capture_thread.start()
    capture_thread.join()
    
if __name__ == '__main__':
    m = Monitor()
    main()
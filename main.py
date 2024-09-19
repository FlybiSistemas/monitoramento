from src.function import Funciton
from src.monitor import Monitor
from src.tunel import Tunel
import threading
import sys

def main():
    data = f.decrypt_data('db.txt')
    if('perfil' in data): t.usuario = data['perfil']
    m.send_certificate = t.send_certificate
    capture_thread = threading.Thread(target=m.capture_packets)
    capture_thread.start()

    capture_thread.join()
    
if __name__ == '__main__':
    m = Monitor()
    t = Tunel()
    f = Funciton()
    f.check_monitoramento()
    main()
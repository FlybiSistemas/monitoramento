from src.function import Funciton
from src.monitor import Monitor
from src.tunel import Tunel
import threading
import sys

def main():
    data = f.decrypt_data('db.txt')
    if('perfil' in data): t.usuario = data['perfil']
    m.send_certificate = t.send_certificate
    m.read_message = t.read_message
    capture_thread = threading.Thread(target=m.capture_packets)
    capture_thread.start()

    message_thread = threading.Thread(target=m.process_messages)
    message_thread.start()

    capture_thread.join()
    message_thread.join()
    
if __name__ == '__main__':
    m = Monitor()
    t = Tunel()
    f = Funciton()
    if(f.check_monitoramento()):
        sys.exit()
    main()
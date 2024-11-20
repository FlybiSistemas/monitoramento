from src.function import Funciton
from src.monitor import Monitor
import subprocess
import threading
import sys

def main():
    capture_thread = threading.Thread(target=m.capture_packets)
    capture_thread.start()
    capture_thread.join()
    
if __name__ == '__main__':
    m = Monitor()
    f = Funciton()
    if(f.check_monitoramento()):
        sys.exit()
    main()
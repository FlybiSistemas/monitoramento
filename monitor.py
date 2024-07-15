import base64
import json
import os
import threading
import pyautogui as pg
from Cryptodome.Cipher import AES
from scapy.all import *
from tunel import Tunel

class Monitor:
    def decrypt_data(filename):
        with open(filename, 'r') as file_in:
            key = base64.b64decode(file_in.readline().strip())
            nonce = base64.b64decode(file_in.readline().strip())
            tag = base64.b64decode(file_in.readline().strip())
            ciphertext = base64.b64decode(file_in.readline().strip())

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

        data_str = cipher.decrypt_and_verify(ciphertext, tag).decode()
        data = json.loads(data_str)

        return data

    def get_object_certificates(self):
        cont = 0
        certificates = os.popen('certutil -user -store "MY"').read()
        lines = certificates.split("\n")
        certificados = []
        for line in lines:
            try:
                if ('Requerente' not in line and "Número de Série" not in line and "Emissor" not in line and "NotAfter" not in line):
                    continue

                if ("Emissor" in line):
                    emissor = line.split(",")[0].split('=')[1]

                if ("NotAfter" in line):
                    data_validade = line.split(":")[1].strip().split(' ')[0]

                if ("Número de Série" in line):
                    numero_serie = line.split(":")[1].strip()

                if ('Requerente' in line):
                    requerente = line.split(',')[0].split(': CN=')[1].split(':')
                    if len(requerente) == 1:
                        continue
                    cnpj = requerente[1].strip()
                    razao_social = requerente[0].strip()
                    certificados.append(
                        {
                            "cnpj": cnpj,
                            "razao_social": razao_social,
                            "num_serie": numero_serie,
                            "data_validade": data_validade,
                            "emissor": emissor
                        }
                    )
                    cont = cont + 1
            except:
                continue
        return certificados

    def packet_handler(self, packet):
        if packet.haslayer(TCP):
            raw = bytes(packet[TCP].payload)
            if len(raw) > 0 and raw[0] == 22:  # TLS Content Type 22 (Handshake)
                subject_name = self.parse_tls_handshake(packet)
                # if subject_name:
                #     print(f"{packet.time} - Captured HTTPS request with certificate subject: {subject_name}")
                #     resolve_ip(packet)

    def parse_tls_handshake(self, packet):
        try:
            raw = bytes(packet[TCP].payload)
            if len(raw) > 5 and (raw[0:3] == b'\x16\x03\x01' or raw[0:3] == b'\x16\x03\x03'):
                handshake_type = raw[5]
                if handshake_type == 0x0b:  # Certificate
                    total_certificates_length = int.from_bytes(raw[6:9], 'big')
                    certificates_data = raw[9:9 + total_certificates_length]
                    index = 0
                    while index < total_certificates_length:
                        if index + 3 > len(certificates_data):
                            break
                        cert_length = int.from_bytes(certificates_data[index:index + 3], 'big')
                        if index + 3 + cert_length > len(certificates_data):
                            break
                        cert_bytes = certificates_data[index + 3:index + 3 + cert_length]
                        for certificado in self.get_object_certificates():
                            if (certificado['cnpj'] in str(cert_bytes)):
                                t.send_message('{"certificado": "'+certificado['cnpj']+'"}')
                                break
                        break
            return False
        except Exception as e:
            print(f"Error parsing TLS handshake: {e}")
            return None

    def capture_packets(self):
        sniff(filter="tcp port 443", prn=self.packet_handler)

    def process_messages(self):
        while True:
            message = t.read_message()
            if message is None:
                break
            try:
                if 'function' in message:
                    message_dict = eval(message)  # Use eval apenas se tiver certeza da segurança do input
                    if isinstance(message_dict, dict) and 'function' in message_dict:
                        # coloque as aspas simples por fora
                        t.send_message('{"function": "' + message_dict["function"] + '"}')
            except Exception as e:
                pg.alert(str(e))
                continue

    def main(self):
        capture_thread = threading.Thread(target=self.capture_packets)
        capture_thread.start()

        message_thread = threading.Thread(target=self.process_messages)
        message_thread.start()

        capture_thread.join()
        message_thread.join()

if __name__ == '__main__':
    m = Monitor()
    t = Tunel()
    m.main()

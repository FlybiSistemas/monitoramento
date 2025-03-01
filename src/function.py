import base64
from Cryptodome.Cipher import AES
import json
import os

class Funciton:
    def getUserDb(self):
        data = self.decrypt_data('db.txt')
        return data['perfil']

    def decrypt_data(self, filename):
        filename = os.path.expanduser("~")+'/arquivos_bytoken/'+filename
        with open(filename, 'r') as file_in:
            key = base64.b64decode(file_in.readline().strip())
            nonce = base64.b64decode(file_in.readline().strip())
            tag = base64.b64decode(file_in.readline().strip())
            ciphertext = base64.b64decode(file_in.readline().strip())

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

        data_str = cipher.decrypt_and_verify(ciphertext, tag).decode()
        data = json.loads(data_str)

        return data

    def check_monitoramento(self):
        r = os.popen("tasklist").read()
        if(r.count("mon.exe") > 2 ):
            return True
        return False

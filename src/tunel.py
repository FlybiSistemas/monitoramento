import sys
import json
import struct

class Tunel:
    usuario = []

    # def __init__(self, user):
    #     self.send_message(user)

    def send_message(self, message_content):
        encoded_content = json.dumps(message_content).encode("utf-8")
        encoded_length = struct.pack('=I', len(encoded_content))
        sys.stdout.buffer.write(encoded_length)
        sys.stdout.buffer.write(encoded_content)
        sys.stdout.buffer.flush()

    def send_certificate(self, certificado):
        data = self.usuario
        data['certificado'] = certificado
        self.send_message(json.dumps(data))

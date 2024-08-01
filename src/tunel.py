import sys
import json
import struct

class Tunel:
    usuario = []

    # def __init__(self, user):
    #     self.send_message(user)

    def read_message(self):
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            return None
        message_length = struct.unpack('=I', raw_length)[0]
        message = sys.stdin.buffer.read(message_length).decode("utf-8")
        return json.loads(message)

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

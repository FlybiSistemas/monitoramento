import sys
import json
import struct
import pyautogui as pg

pg.alert('app iniciado')

def read_message():
    pg.alert("Lendo a mensagem...")
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('=I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode("utf-8")
    return json.loads(message)

def send_message(message_content):
    pg.alert("Enviando a mensagem...")
    encoded_content = json.dumps(message_content).encode("utf-8")
    encoded_length = struct.pack('=I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def main():
    while True:
        pg.alert("Esperando a próxima mensagem...")
        message = read_message()
        if message is None:
            break
        pg.alert(f"Mensagem recebida do Chrome: {message}")
        response = {"response": "Mensagem recebida com sucesso!"}
        send_message(response)

if __name__ == '__main__':
    pg.alert("Iniciando o programa...")
    main()

import socket
import threading
from crypto_utils import encrypt_message, decrypt_message

# Server configuration
HOST = '127.0.0.1'  # Change to server IP if needed
PORT = 12345

def receive_messages(client):
    while True:
        try:
            enc_message = client.recv(1024).decode('utf-8')
            if enc_message:
                message = decrypt_message(enc_message)
                if message is None:
                    print("Failed to decrypt message")
                else:
                    print(f"Received: {message}")
            else:
                break
        except:
            print("An error occurred!")
            client.close()
            break

def send_messages(client):
    while True:
        message = input()
        if message.lower() == 'exit':
            client.close()
            break
        try:
            enc_message = encrypt_message(message)
            client.send(enc_message.encode('utf-8'))
        except:
            print("Failed to send message")
            client.close()
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")

    receive_thread = threading.Thread(target=receive_messages, args=(client,))
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages, args=(client,))
    send_thread.start()

if __name__ == "__main__":
    main()

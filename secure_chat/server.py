import socket
import threading
from crypto_utils import decrypt_message, encrypt_message

# Server configuration
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345

clients = []
nicknames = []

def broadcast(message, _client):
    for client in clients:
        if client != _client:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                if client in clients:
                    clients.remove(client)

def handle_client(client):
    while True:
        try:
            enc_message = client.recv(1024).decode('utf-8')
            if not enc_message:
                break
            message = decrypt_message(enc_message)
            if message is None:
                print("Failed to decrypt message")
                continue
            print(f"Decrypted message: {message}")
            enc_broadcast = encrypt_message(message)
            broadcast(enc_broadcast, client)
        except:
            clients.remove(client)
            client.close()
            break

def receive_connections():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server started on {HOST}:{PORT}")

    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        clients.append(client)

        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    receive_connections()

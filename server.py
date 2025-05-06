import socket
import threading
import hashlib
import os
import logging
import json
from datetime import datetime
from packet_capture import PacketCapture

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

HOST = '0.0.0.0'
PORT = 65434

# Virus signature database file
VIRUS_DB_FILE = 'virus_signatures.txt'

# User credentials file
USERS_FILE = 'users.json'

# Load virus signature database
def load_virus_db():
    db = {}
    if not os.path.exists(VIRUS_DB_FILE):
        return db
    with open(VIRUS_DB_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t', 1)
            if len(parts) == 2:
                sig, info = parts
                db[sig] = info
    return db

# Save virus signature database
def save_virus_db(db):
    with open(VIRUS_DB_FILE, 'w', encoding='utf-8') as f:
        for sig, info in db.items():
            f.write(f"{sig}\t{info}\n")

# Load users
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

# Check user credentials
def check_user_credentials(username, password):
    users = load_users()
    if username not in users:
        return False
    stored_hash = users[username].get('password_hash', '')
    password_hash = hashlib.sha1(password.encode()).hexdigest()
    return stored_hash == password_hash

# Add or update virus signatures in the database
def update_virus_db(new_signatures):
    db = load_virus_db()
    updated = False
    for sig, info in new_signatures.items():
        if sig not in db:
            db[sig] = info
            updated = True
    if updated:
        save_virus_db(db)
        logging.info("Virus signature database updated with new signatures.")

# Check if a signature is in the virus database
def check_signature(signature):
    db = load_virus_db()
    if signature in db:
        return True, db[signature]
    return False, None

# Generate detailed report entry
def generate_report(client_addr, file_name, signature, detected, virus_info):
    report = {
        'timestamp': datetime.now().isoformat(),
        'client': client_addr,
        'file_name': file_name,
        'signature': signature,
        'detected': detected,
        'virus_info': virus_info
    }
    return report

packet_capture = PacketCapture()

# Thread to handle each client connection
def handle_client(conn, addr):
    logging.info(f"Connected by {addr}")
    try:
        while True:
            try:
                data = conn.recv(65536)
                if not data:
                    break
                decoded = data.decode()
                logging.debug(f"Received from {addr}: {decoded}")

                # Handle authentication
                if decoded.startswith("AUTH|"):
                    parts = decoded.split('|')
                    if len(parts) == 3:
                        username = parts[1]
                        password = parts[2]
                        if check_user_credentials(username, password):
                            logging.info(f"Authentication success for user {username} from {addr}")
                            conn.sendall(b"AUTH_SUCCESS")
                        else:
                            logging.info(f"Authentication failed for user {username} from {addr}")
                            conn.sendall(b"AUTH_FAIL")
                    else:
                        conn.sendall(b"AUTH_FAIL")
                    continue

                # Handle packet capture commands
                if decoded == "START_PACKET_CAPTURE":
                    logging.info(f"Starting packet capture for {addr}")
                    start_packet_capture()
                    conn.sendall(b"PACKET_CAPTURE_STARTED")
                    continue
                elif decoded == "STOP_PACKET_CAPTURE":
                    logging.info(f"Stopping packet capture for {addr}")
                    stop_packet_capture()
                    conn.sendall(b"PACKET_CAPTURE_STOPPED")
                    continue
                elif decoded == "GET_CAPTURED_PACKETS":
                    packets = get_captured_packets()
                    logging.debug(f"Sending {len(packets)} packets to {addr}")
                    packets_json = json.dumps(packets)
                    conn.sendall(packets_json.encode())
                    continue

                # Expecting data as a string: "file_name|signature|hash_algo"
                parts = decoded.split('|')
                if len(parts) < 2:
                    raise ValueError("Invalid request format")
                file_name = parts[0]
                signature = parts[1]
                hash_algo = parts[2] if len(parts) > 2 else 'sha256'

                detected, virus_info = check_signature(signature)

                # Log the scan request
                logging.info(f"Scan request from {addr}: file={file_name}, signature={signature}, detected={detected}")

                # Generate report entry
                report_entry = generate_report(addr[0], file_name, signature, detected, virus_info)
                # Append to report file
                with open('scan_reports.txt', 'a') as report_file:
                    report_file.write(str(report_entry) + '\\n')

                # Prepare response string: "status|message|recommendation"
                if detected:
                    status = 'infected'
                    message = virus_info
                    recommendation = 'Delete or quarantine the file immediately.'
                else:
                    status = 'clean'
                    message = 'No virus detected.'
                    recommendation = ''

                response = f"{status}|{message}|{recommendation}"
                conn.sendall(response.encode())
            except ConnectionAbortedError:
                logging.warning(f"Connection aborted by {addr}")
                break
            except Exception as e:
                logging.error(f"Invalid request from {addr}: {e}")
                error_response = f"error|{str(e)}|"
                try:
                    conn.sendall(error_response.encode())
                except Exception:
                    pass
    except ConnectionResetError:
        logging.info(f"Connection reset by {addr}")
    finally:
        conn.close()
        logging.info(f"Connection closed for {addr}")

def start_packet_capture():
    # Specify the WiFi interface name for packet capture
    wifi_interface = "Wi-Fi"  # Change this if your interface name is different
    packet_capture.start_capture(iface=wifi_interface)

def stop_packet_capture():
    packet_capture.stop_capture()

def get_captured_packets():
    return packet_capture.packets

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        logging.info(f"Server started on {HOST}:{PORT}")
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

if __name__ == '__main__':
    start_server()

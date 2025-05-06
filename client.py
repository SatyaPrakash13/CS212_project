import socket
import hashlib
import os
import argparse

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

def compute_file_hash(file_path, hash_algo='sha256'):
    hash_algo = hash_algo.lower()
    if hash_algo not in hashlib.algorithms_available:
        raise ValueError(f"Hash algorithm {hash_algo} is not supported.")
    hasher = hashlib.new(hash_algo)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def send_signature(file_name, signature, hash_algo, server_host, server_port):
    # Prepare request string: "file_name|signature|hash_algo"
    request = f"{file_name}|{signature}|{hash_algo}"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        s.sendall(request.encode())
        response_data = s.recv(4096)
        response_str = response_data.decode()
        # Response format: "status|message|recommendation"
        parts = response_str.split('|')
        response = {
            'status': parts[0] if len(parts) > 0 else '',
            'message': parts[1] if len(parts) > 1 else '',
            'recommendation': parts[2] if len(parts) > 2 else ''
        }
        return response

def scan_files(file_paths, hash_algo, server_host, server_port):
    results = []
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            print(f"Skipping {file_path}: Not a file.")
            continue
        try:
            signature = compute_file_hash(file_path, hash_algo)
            response = send_signature(os.path.basename(file_path), signature, hash_algo, server_host, server_port)
            results.append((file_path, response))
            print(f"Scanned {file_path}: {response}")
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
    return results

def main():
    parser = argparse.ArgumentParser(description='Client for Signature-Based Virus Detection System')
    parser.add_argument('files', nargs='+', help='Files to scan')
    parser.add_argument('--host', default=SERVER_HOST, help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=SERVER_PORT, help='Server port (default: 65432)')
    parser.add_argument('--hash', default='sha256', help='Hash algorithm to use (default: sha256)')
    args = parser.parse_args()

    scan_files(args.files, args.hash, args.host, args.port)

if __name__ == '__main__':
    main()

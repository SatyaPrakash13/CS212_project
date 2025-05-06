import tkinter as tk
from tkinter import ttk
from threading import Thread
import sys
import os

# Import virus detection GUI class
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from virus_scanner.client_gui import VirusScannerGUI

import socket
import threading
from secure_chat.crypto_utils import encrypt_message, decrypt_message

class SecureChatTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.server_host = tk.StringVar(value='127.0.0.1')
        self.server_port = tk.IntVar(value=12345)
        self.client_socket = None
        self.receive_thread = None
        self.running = False

        # Server connection frame
        conn_frame = tk.Frame(self)
        conn_frame.pack(pady=5, fill='x')

        tk.Label(conn_frame, text="Server IP:").pack(side='left')
        tk.Entry(conn_frame, textvariable=self.server_host, width=15).pack(side='left', padx=5)
        tk.Label(conn_frame, text="Port:").pack(side='left')
        tk.Entry(conn_frame, textvariable=self.server_port, width=6).pack(side='left', padx=5)
        self.connect_button = tk.Button(conn_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.pack(side='left', padx=5)

        # Username input frame
        username_frame = tk.Frame(self)
        username_frame.pack(pady=5, fill='x')

        tk.Label(username_frame, text="Your Name:").pack(side='left')
        self.username_var = tk.StringVar(value="You")
        self.username_entry = tk.Entry(username_frame, textvariable=self.username_var, width=15)
        self.username_entry.pack(side='left', padx=5)

        tk.Label(username_frame, text="Friend's Name:").pack(side='left', padx=(10,0))
        self.friendname_var = tk.StringVar(value="Friend")
        self.friendname_entry = tk.Entry(username_frame, textvariable=self.friendname_var, width=15)
        self.friendname_entry.pack(side='left', padx=5)

        # Last received message label
        self.last_received_label_var = tk.StringVar(value="Last received message: None")
        self.last_received_label = tk.Label(self, textvariable=self.last_received_label_var, fg="blue", anchor="w")
        self.last_received_label.pack(padx=10, pady=(5, 0), fill='x')

        # Chat display area
        self.chat_display = tk.Text(self, height=16, state='disabled')
        self.chat_display.pack(padx=10, pady=5, fill='both', expand=True)

        # Message entry frame
        msg_frame = tk.Frame(self)
        msg_frame.pack(pady=5, fill='x')

        self.message_var = tk.StringVar()
        self.message_entry = tk.Entry(msg_frame, textvariable=self.message_var)
        self.message_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.message_entry.bind('<Return>', lambda event: self.send_message())

        self.send_button = tk.Button(msg_frame, text="Send", command=self.send_message, state='disabled')
        self.send_button.pack(side='left', padx=5)

    def connect_to_server(self):
        if self.client_socket:
            self.append_chat("Already connected.")
            return
        host = self.server_host.get()
        port = self.server_port.get()
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.append_chat(f"Connected to server {host}:{port}")
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            self.connect_button.config(state='disabled')
            self.send_button.config(state='normal')
        except Exception as e:
            self.append_chat(f"Connection failed: {e}")
            self.client_socket = None

    def receive_messages(self):
        while self.running:
            try:
                enc_message = self.client_socket.recv(1024).decode('utf-8')
                if not enc_message:
                    self.append_chat("Disconnected from server.")
                    self.running = False
                    break
                message = decrypt_message(enc_message)
                if message is None:
                    self.append_chat("Failed to decrypt a message.")
                else:
                    friend_name = self.friendname_var.get()
                    self.append_chat(f"{friend_name}: {message}")
                    # Update last received message label
                    self.last_received_label_var.set(f"Last received message: {message}")
            except Exception as e:
                self.append_chat(f"Error receiving message: {e}")
                self.running = False
                break
        self.client_socket.close()
        self.client_socket = None
        self.connect_button.config(state='normal')
        self.send_button.config(state='disabled')

    def send_message(self):
        message = self.message_var.get().strip()
        if not message or not self.client_socket:
            return
        try:
            enc_message = encrypt_message(message)
            self.client_socket.send(enc_message.encode('utf-8'))
            user_name = self.username_var.get()
            self.append_chat(f"{user_name}: {message}")
            self.message_var.set('')
        except Exception as e:
            self.append_chat(f"Failed to send message: {e}")

    def append_chat(self, text):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, text + '\n')
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

class UnifiedApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Unified Network Application")
        self.geometry("900x700")

        self.tab_control = ttk.Notebook(self)
        self.tab_control.pack(expand=1, fill='both')

        # Virus Detection Tab
        # VirusScannerGUI expects a Tk root window, so create a Frame wrapper
        virus_frame = tk.Frame(self.tab_control)
        virus_frame.pack(fill='both', expand=True)
        self.virus_tab = VirusScannerGUI(virus_frame)
        self.tab_control.add(virus_frame, text="Virus Detection")

        # Secure Chat Tab
        self.chat_tab = SecureChatTab(self.tab_control)
        self.tab_control.add(self.chat_tab, text="Secure Chat")

if __name__ == "__main__":
    app = UnifiedApp()
    app.mainloop()

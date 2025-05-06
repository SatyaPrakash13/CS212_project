import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading
import json
import socket
import hashlib
import os
import queue
import folium
import io
import base64
from PIL import Image, ImageTk
import webbrowser
import tempfile
import time

DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_PORT = 65434

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

class VirusScannerGUI:
    def __init__(self, master):
        self.master = master
        # Removed master.title() call because master may be a Frame without title() method
        # master.title("Signature-Based Virus Detection System")

        self.files = []
        self.results = []
        self.queue = queue.Queue()

        self.frame = tk.Frame(master)
        self.frame.pack(padx=10, pady=10)

        # Remove login frame and login UI
        self.logged_in = True

        self.tab_control = ttk.Notebook(self.frame)
        self.tab_control.pack(expand=1, fill='both')

        # Virus Scan Tab
        self.scan_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.scan_tab, text='Virus Scan')

        # Packet Capture Tab
        self.packet_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.packet_tab, text='Packet Capture')

        # Virus Scan Tab UI
        self._build_scan_tab()

        # Packet Capture Tab UI
        self._build_packet_tab()

        # Show tabs immediately, no login required
        self.tab_control.pack(expand=1, fill='both')

        self.master.after(100, self.process_queue)

        self.packet_capture_running = False
        self.packet_data = []

    def _build_login_ui(self):
        pass  # Login UI removed as login page is removed

    def login(self):
        pass  # Login method removed as login page is removed

    def _build_scan_tab(self):
        # Server connection inputs
        self.server_frame = tk.Frame(self.scan_tab)
        self.server_frame.grid(row=0, column=0, columnspan=4, sticky="ew")

        self.server_ip_label = tk.Label(self.server_frame, text="Server IP:")
        self.server_ip_label.grid(row=0, column=0, sticky="w")

        self.server_ip_var = tk.StringVar(value=DEFAULT_SERVER_HOST)
        self.server_ip_entry = tk.Entry(self.server_frame, textvariable=self.server_ip_var, width=15)
        self.server_ip_entry.grid(row=0, column=1, sticky="w", padx=(0,10))

        self.server_port_label = tk.Label(self.server_frame, text="Port:")
        self.server_port_label.grid(row=0, column=2, sticky="w")

        self.server_port_var = tk.StringVar(value=str(DEFAULT_SERVER_PORT))
        self.server_port_entry = tk.Entry(self.server_frame, textvariable=self.server_port_var, width=6)
        self.server_port_entry.grid(row=0, column=3, sticky="w")

        self.select_button = tk.Button(self.scan_tab, text="Select Files", command=self.select_files)
        self.select_button.grid(row=1, column=0, sticky="ew")

        self.scan_button = tk.Button(self.scan_tab, text="Scan Files", command=self.scan_files)
        self.scan_button.grid(row=1, column=1, sticky="ew")

        self.remove_button = tk.Button(self.scan_tab, text="Remove Selected", command=self.remove_selected_files)
        self.remove_button.grid(row=1, column=2, sticky="ew")

        self.clear_button = tk.Button(self.scan_tab, text="Clear All", command=self.clear_all)
        self.clear_button.grid(row=1, column=3, sticky="ew")

        self.export_button = tk.Button(self.scan_tab, text="Export Log", command=self.export_log)
        self.export_button.grid(row=1, column=4, sticky="ew")

        self.hash_label = tk.Label(self.scan_tab, text="Hash Algorithm:")
        self.hash_label.grid(row=2, column=0, sticky="w", pady=(10,0))

        self.hash_var = tk.StringVar(value="sha256")
        self.hash_entry = tk.Entry(self.scan_tab, textvariable=self.hash_var)
        self.hash_entry.grid(row=2, column=1, sticky="ew", pady=(10,0))

        self.progress = ttk.Progressbar(self.scan_tab, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=3, column=0, columnspan=4, pady=(10,0))

        self.file_listbox = tk.Listbox(self.scan_tab, width=60, height=10, selectmode=tk.EXTENDED)
        self.file_listbox.grid(row=4, column=0, columnspan=4, pady=(10,0))

        self.result_text = scrolledtext.ScrolledText(self.scan_tab, width=60, height=15, state='disabled')
        self.result_text.grid(row=5, column=0, columnspan=4, pady=(10,0))

        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(self.scan_tab, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.grid(row=6, column=0, columnspan=4, sticky="ew")

    def _build_packet_tab(self):
        self.packet_control_frame = tk.Frame(self.packet_tab)
        self.packet_control_frame.pack(pady=10)

        self.start_capture_button = tk.Button(self.packet_control_frame, text="Start Capture", command=self.start_packet_capture)
        self.start_capture_button.grid(row=0, column=0, padx=5)

        self.pause_capture_button = tk.Button(self.packet_control_frame, text="Pause Capture", command=self.pause_packet_capture, state='disabled')
        self.pause_capture_button.grid(row=0, column=1, padx=5)

        self.resume_capture_button = tk.Button(self.packet_control_frame, text="Resume Capture", command=self.resume_packet_capture, state='disabled')
        self.resume_capture_button.grid(row=0, column=2, padx=5)

        self.stop_capture_button = tk.Button(self.packet_control_frame, text="Stop Capture", command=self.stop_packet_capture, state='disabled')
        self.stop_capture_button.grid(row=0, column=3, padx=5)

        self.search_label = tk.Label(self.packet_control_frame, text="Search:")
        self.search_label.grid(row=1, column=0, sticky='w', pady=5)

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(self.packet_control_frame, textvariable=self.search_var)
        self.search_entry.grid(row=1, column=1, columnspan=3, sticky='ew', pady=5)
        self.search_entry.bind('<KeyRelease>', self.filter_packet_data)

        self.export_button = tk.Button(self.packet_control_frame, text="Export Data", command=self.export_packet_data)
        self.export_button.grid(row=1, column=4, padx=5, pady=5)

        self.map_frame = tk.Frame(self.packet_tab)
        self.map_frame.pack(fill='both', expand=True)

        self.map_label = tk.Label(self.map_frame, text="Geo Map of Packet Sources and Destinations")
        self.map_label.pack()

        self.map_canvas = tk.Canvas(self.map_frame, width=800, height=400)
        self.map_canvas.pack()

        self.map_image = None

    def select_files(self):
        selected_files = filedialog.askopenfilenames()
        if selected_files:
            self.files.extend(selected_files)
            self.update_file_listbox()
            self.status_var.set(f"Selected {len(self.files)} files.")

    def filter_packet_data(self, event=None):
        query = self.search_var.get().lower()
        filtered_packets = []
        for pkt in self.packet_data:
            src_ip = pkt.get('src_ip', '').lower()
            dst_ip = pkt.get('dst_ip', '').lower()
            if query in src_ip or query in dst_ip:
                filtered_packets.append(pkt)
        self.display_filtered_packets(filtered_packets)

    def display_filtered_packets(self, packets):
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        for pkt in packets:
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            geo_src = pkt.get('geo_src', {})
            geo_dst = pkt.get('geo_dst', {})
            line = f"Src: {src_ip} ({geo_src.get('city', '')}, {geo_src.get('country', '')}) -> "
            line += f"Dst: {dst_ip} ({geo_dst.get('city', '')}, {geo_dst.get('country', '')})\n"
            self.result_text.insert(tk.END, line)
        self.result_text.config(state='disabled')

    def export_packet_data(self):
        if not self.packet_data:
            messagebox.showinfo("Export Packet Data", "No packet data to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.packet_data, f, indent=2)
                messagebox.showinfo("Export Packet Data", f"Packet data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Packet Data", f"Failed to export packet data: {e}")

    def update_file_listbox(self):
        self.file_listbox.delete(0, tk.END)
        for f in self.files:
            size = os.path.getsize(f)
            display_text = f"{f} ({self._sizeof_fmt(size)})"
            self.file_listbox.insert(tk.END, display_text)

    def remove_selected_files(self):
        selected_indices = list(self.file_listbox.curselection())
        if not selected_indices:
            messagebox.showinfo("Remove Files", "No files selected to remove.")
            return
        for index in reversed(selected_indices):
            del self.files[index]
        self.update_file_listbox()
        self.status_var.set(f"Removed {len(selected_indices)} files.")

    def clear_all(self):
        self.files.clear()
        self.results.clear()
        self.update_file_listbox()
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        self.progress['value'] = 0
        self.status_var.set("Cleared all files and results.")

    def export_log(self):
        if not self.results:
            messagebox.showinfo("Export Log", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for result in self.results:
                        f.write(result + "\n\n")
                messagebox.showinfo("Export Log", f"Scan log exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Log", f"Failed to export log: {e}")

    def scan_files(self):
        if not self.files:
            messagebox.showwarning("No files selected", "Please select files to scan.")
            return
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        self.results.clear()
        self.progress['value'] = 0
        self.status_var.set("Starting scan...")
        threading.Thread(target=self._scan_files_thread, daemon=True).start()

    def _scan_files_thread(self):
        hash_algo = self.hash_var.get()
        server_host = self.server_ip_var.get()
        try:
            server_port = int(self.server_port_var.get())
        except ValueError:
            self.queue.put("Invalid server port number. Using default port 65432.\n")
            server_port = 65432

        total_files = len(self.files)
        completed = 0

        def worker(file_path):
            nonlocal completed
            try:
                signature = compute_file_hash(file_path, hash_algo)
                response = send_signature(os.path.basename(file_path), signature, hash_algo, server_host, server_port)
                result_str = f"File: {file_path}\\nResult: {response}\\n"
            except Exception as e:
                result_str = f"File: {file_path}\\nError: {e}\\n"
            self.queue.put(result_str)
            completed += 1
            self.progress['value'] = (completed / total_files) * 100
            self.status_var.set(f"Scanning {completed} of {total_files} files...")

        threads = []
        for file_path in self.files:
            t = threading.Thread(target=worker, args=(file_path,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.status_var.set("Scan completed.")

    def process_queue(self):
        try:
            while True:
                result = self.queue.get_nowait()
                self._append_result(result)
                self.results.append(result)
        except queue.Empty:
            pass
        self.master.after(100, self.process_queue)

    def _append_result(self, text):
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text + "\n\n")
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    def _sizeof_fmt(self, num, suffix='B'):
        for unit in ['','K','M','G','T','P','E','Z']:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Y{suffix}"

    def start_packet_capture(self):
        if self.packet_capture_running:
            return
        self.packet_capture_running = True
        self.packet_capture_paused = False
        self.start_capture_button.config(state='disabled')
        self.pause_capture_button.config(state='normal')
        self.resume_capture_button.config(state='disabled')
        self.stop_capture_button.config(state='normal')
        threading.Thread(target=self._packet_capture_thread, daemon=True).start()

    def pause_packet_capture(self):
        if not self.packet_capture_running or self.packet_capture_paused:
            return
        self.packet_capture_paused = True
        self.pause_capture_button.config(state='disabled')
        self.resume_capture_button.config(state='normal')
        self.status_var.set("Packet capture paused.")

    def resume_packet_capture(self):
        if not self.packet_capture_running or not self.packet_capture_paused:
            return
        self.packet_capture_paused = False
        self.pause_capture_button.config(state='normal')
        self.resume_capture_button.config(state='disabled')
        self.status_var.set("Packet capture resumed.")

    def stop_packet_capture(self):
        if not self.packet_capture_running:
            return
        self.packet_capture_running = False
        self.packet_capture_paused = False
        self.start_capture_button.config(state='normal')
        self.pause_capture_button.config(state='disabled')
        self.resume_capture_button.config(state='disabled')
        self.stop_capture_button.config(state='disabled')
        self.status_var.set("Packet capture stopped.")

    def _packet_capture_thread(self):
        server_host = self.server_ip_var.get()
        try:
            server_port = int(self.server_port_var.get())
        except ValueError:
            self.status_var.set("Invalid server port number for packet capture. Using default port 65432.")
            server_port = 65432

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_host, server_port))
                s.sendall(b"START_PACKET_CAPTURE")
                self.status_var.set("Packet capture started.")
                while self.packet_capture_running:
                    if self.packet_capture_paused:
                        time.sleep(1)
                        continue
                    s.sendall(b"GET_CAPTURED_PACKETS")
                    data = s.recv(65536)
                    if not data:
                        break
                    packets_json = data.decode()
                    try:
                        packets = json.loads(packets_json)
                        self.packet_data = packets
                        self.update_map()
                    except Exception as e:
                        self.status_var.set(f"Error parsing packet data: {e}")
                    time.sleep(2)
                s.sendall(b"STOP_PACKET_CAPTURE")
                self.status_var.set("Packet capture stopped.")
        except Exception as e:
            self.status_var.set(f"Error during packet capture: {e}")
            self.packet_capture_running = False
            self.start_capture_button.config(state='normal')
            self.pause_capture_button.config(state='disabled')
            self.resume_capture_button.config(state='disabled')
            self.stop_capture_button.config(state='disabled')

    def update_map(self):
        if not self.packet_data:
            return
        # Create folium map centered at average location
        import folium
        from PIL import ImageTk, Image
        import io
        import base64
        latitudes = []
        longitudes = []
        for pkt in self.packet_data:
            geo_src = pkt.get('geo_src', {})
            geo_dst = pkt.get('geo_dst', {})
            if 'lat' in geo_src and 'lon' in geo_src:
                latitudes.append(geo_src['lat'])
                longitudes.append(geo_src['lon'])
            if 'lat' in geo_dst and 'lon' in geo_dst:
                latitudes.append(geo_dst['lat'])
                longitudes.append(geo_dst['lon'])
        if not latitudes or not longitudes:
            return
        avg_lat = sum(latitudes) / len(latitudes)
        avg_lon = sum(longitudes) / len(longitudes)
        m = folium.Map(location=[avg_lat, avg_lon], zoom_start=2)
        for pkt in self.packet_data:
            geo_src = pkt.get('geo_src', {})
            geo_dst = pkt.get('geo_dst', {})
            src_lat = geo_src.get('lat')
            src_lon = geo_src.get('lon')
            dst_lat = geo_dst.get('lat')
            dst_lon = geo_dst.get('lon')
            if src_lat and src_lon and dst_lat and dst_lon:
                folium.Marker([src_lat, src_lon], popup=f"Source: {pkt.get('src_ip', '')}").add_to(m)
                folium.Marker([dst_lat, dst_lon], popup=f"Destination: {pkt.get('dst_ip', '')}").add_to(m)
                folium.PolyLine(locations=[[src_lat, src_lon], [dst_lat, dst_lon]], color='blue').add_to(m)
        # Save map to HTML in memory
        data = io.BytesIO()
        m.save(data, close_file=False)
        html_data = data.getvalue().decode()
        # Convert HTML to image using webbrowser and screenshot is complex, so instead show map in default browser
        # Save to temp file and open in browser
        import tempfile
        import webbrowser
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
        tmp_file.write(html_data.encode())
        tmp_file.close()
        webbrowser.open(f'file://{tmp_file.name}')
        # Also update text area with packet info
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        for pkt in self.packet_data:
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            geo_src = pkt.get('geo_src', {})
            geo_dst = pkt.get('geo_dst', {})
            line = f"Src: {src_ip} ({geo_src.get('city', '')}, {geo_src.get('country', '')}) -> "
            line += f"Dst: {dst_ip} ({geo_dst.get('city', '')}, {geo_dst.get('country', '')})\n"
            self.result_text.insert(tk.END, line)
        self.result_text.config(state='disabled')

def main():
    root = tk.Tk()
    app = VirusScannerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()

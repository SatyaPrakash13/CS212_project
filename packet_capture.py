import threading
from scapy.all import sniff, IP
import requests
import logging

class PacketCapture:
    def __init__(self):
        self.packets = []
        self.sniff_thread = None
        self.running = False
        self.iface = None  # Network interface to capture on

    def start_capture(self, iface=None, filter=None):
        if self.running:
            return
        self.running = True
        self.packets.clear()
        self.iface = iface
        logging.info(f"Starting packet capture on interface: {iface}")
        self.sniff_thread = threading.Thread(target=self._sniff_packets, args=(iface, filter), daemon=True)
        self.sniff_thread.start()

    def stop_capture(self):
        self.running = False
        if self.sniff_thread:
            self.sniff_thread.join()
            self.sniff_thread = None
        logging.info("Packet capture stopped.")

    def _sniff_packets(self, iface, filter):
        sniff(iface=iface, filter=filter, prn=self._process_packet, stop_filter=lambda x: not self.running)

    def _process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            geo_src = self.geo_lookup(src_ip)
            geo_dst = self.geo_lookup(dst_ip)
            packet_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'geo_src': geo_src,
                'geo_dst': geo_dst
            }
            self.packets.append(packet_info)
            logging.debug(f"Captured packet: {packet_info}")

    def geo_lookup(self, ip):
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'city': data.get('city', ''),
                    'region': data.get('region', ''),
                    'country': data.get('country_name', ''),
                    'latitude': data.get('latitude', 0.0),
                    'longitude': data.get('longitude', 0.0)
                }
        except Exception:
            pass
        return {
            'ip': ip,
            'city': '',
            'region': '',
            'country': '',
            'latitude': 0.0,
            'longitude': 0.0
        }

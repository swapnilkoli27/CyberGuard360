import threading
import time
from scapy.all import ARP, Ether, sniff
import socket
import subprocess

class WifiMonitor:
    def __init__(self):
        self.monitoring = False
        self.detected_devices = set()  # To store unique MAC addresses
        self.threats_detected = []      # To store detected threats
        self.lock = threading.Lock()     # To handle thread-safe updates

    def start_monitoring(self):
        """Start monitoring Wi-Fi networks."""
        self.monitoring = True
        self.detected_devices.clear()    # Clear previously detected devices
        self.threats_detected.clear()     # Clear previous threats
        self.monitor_thread = threading.Thread(target=self._monitor_network)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop monitoring Wi-Fi networks."""
        self.monitoring = False
        self.monitor_thread.join()         # Wait for the thread to finish

    def _monitor_network(self):
        """Monitor the network for unauthorized access attempts."""
        connected_wifi_name, connected_wifi_ip = self.get_connected_wifi_info()
        print(f"Monitoring '{connected_wifi_name}' with IP {connected_wifi_ip}...")
        
        # Limit the duration of monitoring to avoid overload
        scan_duration = 60  # seconds
        end_time = time.time() + scan_duration

        while self.monitoring and time.time() < end_time:
            sniff(prn=self._process_packet, filter="arp", store=0, timeout=1)
            time.sleep(2)  # Introduce a delay between scans to reduce load

    def _process_packet(self, packet):
        """Process captured ARP packets to detect unauthorized devices."""
        if ARP in packet and packet[ARP].op in (1, 2):  # ARP request or reply
            source_mac = packet[ARP].hwsrc
            source_ip = packet[ARP].psrc

            with self.lock:
                # If the source MAC address is not in the list, it's a potential threat
                if source_mac not in self.detected_devices:
                    self.detected_devices.add(source_mac)
                    self.threats_detected.append((source_ip, source_mac))  # Log the threat
                    # Emit the threat detected signal
                    print(f"Threat detected! IP: {source_ip}, MAC: {source_mac}")

    def get_connected_wifi_info(self):
        """Get the connected Wi-Fi SSID and IP address."""
        try:
            # Get the Wi-Fi SSID
            ssid = subprocess.check_output(['cmd', '/c', 'netsh wlan show interfaces']).decode('utf-8')
            ssid = [line for line in ssid.split('\n') if 'SSID' in line][0].split(': ')[1]

            # Get the local IP address
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)

            return ssid, ip_address
        except Exception as e:
            print(f"Error retrieving connected Wi-Fi information: {e}")
            return "Unknown", "0.0.0.0"

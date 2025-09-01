import win32file
import win32con
import threading
import time

class UsbMonitor:
    def __init__(self):
        self.scanning = False
        self.connected_device = None

    def start_monitoring(self):
        self.scanning = True
        self.monitor_thread = threading.Thread(target=self.monitor_usb)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.scanning = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join()

    def get_connected_usb_device(self):
        return self.connected_device

    def monitor_usb(self):
        # Create a handle to the USB devices
        hDevice = win32file.CreateFile(
            r'\\.\USB',
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )

        while self.scanning:
            # Wait for a device to be connected
            result = win32file.ReadFile(hDevice, 1024, None)
            if result:
                # Check the connected devices
                self.update_connected_device()
            time.sleep(1)  # Polling interval

    def update_connected_device(self):
        drives = win32file.GetLogicalDrives()
        connected_devices = []
        for letter in range(26):  # Check all possible drive letters A-Z
            if drives & (1 << letter):
                drive_letter = f"{chr(letter + 65)}:\\"
                try:
                    volume_name = win32file.GetVolumeInformation(drive_letter)[0]
                    connected_devices.append((drive_letter, volume_name))
                except Exception as e:
                    continue
        
        if connected_devices:
            self.connected_device = f"Connected: {connected_devices[0][1]} at {connected_devices[0][0]}"
        else:
            self.connected_device = "No USB device connected."


import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QStackedWidget, QFrame, QMessageBox, QProgressBar)
from PyQt5.QtGui import QPixmap, QPainter, QColor, QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from WifiMonitor import WifiMonitor  # Import the WifiMonitor class
from UsbMonitor import UsbMonitor  # Import the UsbMonitor class
from malware_detector import scan_directory  # Import the malware scanning function

class ScanThread(QThread):
    update_status = pyqtSignal(str)
    threats_detected = pyqtSignal(list, int, int)  # Include total files scanned
    stop_scan = False  # Flag to indicate when to stop scanning

    def run(self):
        detected_files = []  # Initialize an empty list for detected files
        total_files = 0
        
        # Perform malware scanning (specify the directory to scan)
        detected_files, total_files = scan_directory(r"D:\abc")  # Change path as needed

        # Emit signal based on the results
        self.threats_detected.emit(detected_files, total_files, len(detected_files))

    def stop(self):
        self.stop_scan = True


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("CyberGuard360")
        self.setGeometry(100, 100, 1000, 600)

        # Set the overall color scheme
        self.setStyleSheet(""" 
            QWidget {
                background-color: #1e1e3d;
                color: white;
            }
            QPushButton {
                background-color: #2d2d5a;
                color: white;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #3d3d6b;
            }
            QPushButton:pressed {
                background-color: #4d4d7c;
            }
            #sidebar QPushButton {
                background-color: #6c63ff;
            }
            #sidebar QPushButton:hover {
                background-color: #5a52e6;
            }
            QPushButton#run-btn {
                background-color: #00b400;
            }
            QPushButton#run-btn:hover {
                background-color: #009f00;
            }
            QPushButton#run-btn:pressed {
                background-color: #008b00;
            }
            QLabel {
                font-size: 18px;
            }
        """)

        # Main layout
        main_layout = QHBoxLayout(self)

        # Sidebar layout
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setSpacing(20)

        # Add the logo to the sidebar
        logo_label = QLabel(self)
        pixmap = QPixmap("shield.png")  # Ensure to replace with your logo path
        pixmap = pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignCenter)

        # Create buttons for sidebar
        malware_btn = QPushButton("Malware Detection")
        usb_btn = QPushButton("USB Device Monitoring")
        phishing_btn = QPushButton("Fake Gmail - Phishing URL Detection")
        wifi_btn = QPushButton("Wi-Fi Network Monitoring")
        monitoring_btn = QPushButton("Real-Time System Monitoring")

        # Add buttons to sidebar layout
        sidebar_layout.addWidget(logo_label)
        sidebar_layout.addWidget(malware_btn)
        sidebar_layout.addWidget(usb_btn)
        sidebar_layout.addWidget(phishing_btn)
        sidebar_layout.addWidget(wifi_btn)
        sidebar_layout.addWidget(monitoring_btn)
        sidebar_layout.addStretch(1)

        # Create a frame for sidebar for aesthetics
        sidebar_frame = QFrame()
        sidebar_frame.setLayout(sidebar_layout)
        sidebar_frame.setObjectName("sidebar")
        sidebar_frame.setFixedWidth(250)
        sidebar_frame.setFrameShape(QFrame.StyledPanel)

        # Main content area (stacked widget to change views)
        self.content_area = QStackedWidget(self)

        # Create separate views for each button
        malware_view = self.create_malware_view()
        usb_view = self.create_usb_view()
        phishing_view = self.create_phishing_view()
        wifi_view = self.create_wifi_view()
        monitoring_view = self.create_monitoring_view()

        # Add views to the stacked widget
        self.content_area.addWidget(malware_view)
        self.content_area.addWidget(usb_view)
        self.content_area.addWidget(phishing_view)
        self.content_area.addWidget(wifi_view)
        self.content_area.addWidget(monitoring_view)

        # Connect buttons to change views
        malware_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(malware_view))
        usb_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(usb_view))
        phishing_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(phishing_view))
        wifi_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(wifi_view))
        monitoring_btn.clicked.connect(lambda: self.content_area.setCurrentWidget(monitoring_view))

        # Add sidebar and content area to main layout
        main_layout.addWidget(sidebar_frame)
        main_layout.addWidget(self.content_area)

    # Override paintEvent to draw a watermark
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Set watermark properties
        painter.setPen(QColor(100, 100, 100, 50))
        font = QFont("Arial", 100, QFont.Bold)
        painter.setFont(font)

        # Draw watermark text
        painter.drawText(self.rect(), Qt.AlignCenter, "CyberGuard360")
        super().paintEvent(event)

    # Create view for Wi-Fi network monitoring
    def create_wifi_view(self):
        view = QWidget()
        layout = QVBoxLayout()

        label = QLabel("Wi-Fi Network Monitoring")
        label.setAlignment(Qt.AlignCenter)

        # Create Status Label
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 24px; color: green;")

        # Create Start and Stop buttons
        start_btn = QPushButton("Start Monitoring")
        start_btn.setObjectName("run-btn")
        start_btn.clicked.connect(self.start_wifi_monitoring)

        stop_btn = QPushButton("Stop Monitoring")
        stop_btn.setObjectName("run-btn")
        stop_btn.clicked.connect(self.stop_wifi_monitoring)

        layout.addWidget(label)
        layout.addWidget(self.status_label)
        layout.addWidget(start_btn)
        layout.addWidget(stop_btn)

        view.setLayout(layout)
        return view

    def start_wifi_monitoring(self):
        self.wifi_monitor = WifiMonitor()
        self.wifi_monitor.start_monitoring()

        ssid, ip_address = self.wifi_monitor.get_connected_wifi_info()
        self.status_label.setText(f"Monitoring '{ssid}' with IP {ip_address}")

    def stop_wifi_monitoring(self):
        self.wifi_monitor.stop_monitoring()
        self.status_label.clear()

    # Create view for malware detection
    def create_malware_view(self):
        view = QWidget()
        layout = QVBoxLayout()
        
        label = QLabel("Malware Detection")
        label.setAlignment(Qt.AlignCenter)

        # Create Status Label
        self.scan_status_label = QLabel()
        self.scan_status_label.setAlignment(Qt.AlignCenter)
        self.scan_status_label.setStyleSheet("font-size: 24px; color: green;")

        # Create Start and Stop buttons
        start_btn = QPushButton("Start Scan")
        start_btn.setObjectName("run-btn")
        start_btn.clicked.connect(self.start_malware_scan)

        stop_btn = QPushButton("Stop Scan")
        stop_btn.setObjectName("run-btn")
        stop_btn.clicked.connect(self.stop_malware_scan)

        

        layout.addWidget(label)
        layout.addWidget(self.scan_status_label)
        layout.addWidget(start_btn)
        layout.addWidget(stop_btn)

        view.setLayout(layout)
        return view

    def start_malware_scan(self):
        self.scan_status_label.setText("Scanning...")
        self.scan_thread = ScanThread()
        self.scan_thread.update_status.connect(self.update_scan_status)
        self.scan_thread.threats_detected.connect(self.show_threats)
        self.scan_thread.start()

    def update_scan_status(self, message):
        self.scan_status_label.setText(message)

    def show_threats(self, detected_files, total_files, threats_count):
        if threats_count > 0:
            threat_message = f"Total files scanned: {total_files}\n" \
                             f"Total threats detected: {threats_count}\n" \
                             f"Threats: " + "\n".join(detected_files)
            self.scan_status_label.setText(threat_message)
        else:
            self.scan_status_label.setText(f"Total files scanned: {total_files}\nNo threats detected.")

    def stop_malware_scan(self):
        if hasattr(self, 'scan_thread'):
            self.scan_thread.stop()  # Signal the thread to stop
            self.scan_thread.wait()  # Wait for the thread to finish
            self.scan_status_label.clear()  # Clear the status label

    # Create view for USB monitoring
    def create_usb_view(self):
        view = QWidget()
        layout = QVBoxLayout()

        label = QLabel("USB Device Monitoring")
        label.setAlignment(Qt.AlignCenter)

        # Create Status Label
        self.usb_status_label = QLabel()
        self.usb_status_label.setAlignment(Qt.AlignCenter)
        self.usb_status_label.setStyleSheet("font-size: 24px; color: green;")

        # Create Start and Stop buttons
        start_btn = QPushButton("Start Monitoring")
        start_btn.setObjectName("run-btn")
        start_btn.clicked.connect(self.start_usb_monitoring)

        stop_btn = QPushButton("Stop Monitoring")
        stop_btn.setObjectName("run-btn")
        stop_btn.clicked.connect(self.stop_usb_monitoring)

        layout.addWidget(label)
        layout.addWidget(self.usb_status_label)
        layout.addWidget(start_btn)
        layout.addWidget(stop_btn)

        view.setLayout(layout)
        return view

    def start_usb_monitoring(self):
        self.usb_monitor = UsbMonitor()
        self.usb_monitor.start_monitoring()
        self.usb_status_label.setText("USB monitoring started...")

    def stop_usb_monitoring(self):
        if hasattr(self, 'usb_monitor'):
            self.usb_monitor.stop_monitoring()
            self.usb_status_label.setText("USB monitoring stopped.")

    # Additional views can be created similarly...

    def create_phishing_view(self):
        view = QWidget()
        layout = QVBoxLayout()
        label = QLabel("Fake Gmail - Phishing URL Detection")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        view.setLayout(layout)
        return view

    def create_monitoring_view(self):
        view = QWidget()
        layout = QVBoxLayout()
        label = QLabel("Real-Time System Monitoring")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)
        view.setLayout(layout)
        return view


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel,
    QComboBox, QHBoxLayout, QCheckBox, QSpinBox,
    QPushButton, QListWidget, QTextEdit, QApplication,
    QMessageBox
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QSystemTrayIcon
from PyQt6.QtWidgets import QGroupBox
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem
from PyQt6.QtGui import QColor
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import time
import winreg
from py3nvml import py3nvml
from datetime import datetime
import subprocess
import wmi
import psutil
import socket
import platform
import sys
import os
import re

class RootKitScannerDevKit(QMainWindow):
    def __init__(self):
        super(RootKitScannerDevKit, self).__init__()

        self.time_stamps = []
        self.cpu_temps = []
        self.gpu_temps = []

        self.net_list = QListWidget()
        self.net_list.setStyleSheet(self._list_widget_style())

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(self._list_widget_style())

        self.setWindowTitle("RootKit Scanner DevKit")
        self.setWindowIcon(QIcon("iconfile3.ico"))
        self.resize(1000, 640)
        self.setFont(QFont("Helvetica Neue", 11))

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Theme selector
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Dark", "Light"])
        self.theme_selector.setCurrentText("Dark")
        self.theme_selector.currentTextChanged.connect(self.handle_theme_change)

        # Interval units
        self.interval_units = QComboBox()
        self.interval_units.addItems(["sec", "min", "hr", "day", "month", "year"])
        self.interval_units.setCurrentText("sec")
        self.interval_units.currentTextChanged.connect(
            lambda _: self.change_scan_interval(self.interval_spinbox.value())
        )

        # Tabs
        self.logs_tab = self.create_logs_tab()
        self.dashboard_tab = self.create_dashboard_tab()
        self.process_tab = self.create_process_tab()
        self.hidden_files_tab = self.create_hidden_files_tab()
        self.network_tab = self.create_network_tab()
        self.sysinfo_tab = self.create_sysinfo_tab()
        self.startup_tab = self.create_startup_tab()
        self.services_tab = self.create_services_tab()
        self.integrity_tab = self.create_file_integrity_tab()
        self.users_tab = self.create_users_tab()
        self.hardware_monitor_tab = self.create_hardware_monitor_tab()
        self.uptime_tab = self.create_uptime_tab()
        self.disk_tab = self.create_disk_tab()
        self.network_traffic_tab = self.create_network_traffic_tab()
        self.usb_scan_tab = self.create_usb_scan_tab()
        self.software_inventory_tab = self.create_software_inventory_tab()

        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.process_tab, "Processes")
        self.tabs.addTab(self.hidden_files_tab, "Hidden Files")
        self.tabs.addTab(self.network_tab, "Network")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.sysinfo_tab, "System Info")
        self.tabs.addTab(self.services_tab, "Services")
        self.tabs.addTab(self.integrity_tab, "File Integrity")
        self.tabs.addTab(self.users_tab, "Users")
        self.tabs.addTab(self.hardware_monitor_tab, "Hardware Monitor")
        self.tabs.addTab(self.uptime_tab, "Uptime")
        self.tabs.addTab(self.disk_tab, "Disk Usage")
        self.tabs.addTab(self.network_traffic_tab, "Network Traffic")
        self.tabs.addTab(self.usb_scan_tab, "USB Scan")
        self.tabs.addTab(self.software_inventory_tab, "📦 Software Inventory")

        # Auto refresh checkbox za network
        self.auto_network_checkbox = QCheckBox("Auto-refresh Network")
        self.auto_network_checkbox.setChecked(False)
        self.auto_network_checkbox.stateChanged.connect(self.toggle_auto_network)

        self.network_timer = QTimer(self)
        self.network_timer.timeout.connect(self.update_network)

        if self.auto_network_checkbox.isChecked():
            self.network_timer.start(3000)

        # SpinBox for interval
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(1, 10000)
        self.interval_spinbox.setValue(60)
        self.interval_spinbox.valueChanged.connect(self.change_scan_interval)

        # Auto refresh checkbox
        self.auto_refresh_checkbox = QCheckBox("Auto-refresh every 10s")
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh_proc)

        # Auto refresh checkbox za network
        self.auto_network_checkbox = QCheckBox("Auto-refresh Network")
        self.auto_network_checkbox.setChecked(False)
        self.auto_network_checkbox.stateChanged.connect(self.toggle_auto_network)

        # Process timer
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.update_processes)
        if self.auto_refresh_checkbox.isChecked():
            self.process_timer.start(10000)

        # Network timer
        self.network_timer = QTimer(self)
        self.network_timer.timeout.connect(self.update_network)
        if self.auto_network_checkbox.isChecked():
            self.network_timer.start(3000)

        self.apply_theme("Dark")

        # GPU & CPU Temperature
        self.update_processes()
        self.update_network()
        self.update_temperatures()

    def _list_widget_style(self):
        return """
        QListWidget, QTextEdit, QPlainTextEdit, QTableWidget {
            background-color: #1E1E2F;
            color: #E0E0E0;
            font-family: 'Consolas', monospace;
            font-size: 14px;
            border: 2px solid #3B3B6D;
            border-radius: 12px;
            padding: 10px;
            selection-background-color: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 #4A90E2, stop:1 #1C3F94);
            selection-color: white;
            outline: none;
        }
        QListWidget::item {
            padding: 12px 15px;
            margin: 5px 0;
            border-radius: 8px;
            transition: background-color 0.25s ease;
        }
        QListWidget::item:hover {
            background-color: #3C4A9F;
            color: #FFFFFF;
            font-weight: bold;
            cursor: pointer;
        }
        QListWidget::item:selected {
            background-color: #2A3D8F;
            color: #FFFFFF;
            font-weight: bold;
            box-shadow: 0 0 12px #2A3D8F;
        }
        QTextEdit, QPlainTextEdit {
            selection-background-color: #4A90E2;
            selection-color: white;
        }
        QTableWidget {
            gridline-color: #3B3B6D;
            selection-background-color: #4A90E2;
            selection-color: white;
        }
        QTableWidget::item:hover {
            background-color: #3C4A9F;
            color: #FFFFFF;
        }
        QTableWidget::item:selected {
            background-color: #2A3D8F;
            color: #FFFFFF;
            font-weight: bold;
        }
        QListWidget::scrollbar:vertical, QTextEdit::scrollbar:vertical, QPlainTextEdit::scrollbar:vertical, QTableWidget::scrollbar:vertical {
            background: #2A2A4F;
            width: 14px;
            margin: 16px 0 16px 0;
            border-radius: 8px;
        }
        QListWidget::scrollbar::handle:vertical, QTextEdit::scrollbar::handle:vertical, QPlainTextEdit::scrollbar::handle:vertical, QTableWidget::scrollbar::handle:vertical {
            background: #4A90E2;
            min-height: 40px;
            border-radius: 8px;
        }
        QListWidget::scrollbar::handle:vertical:hover, QTextEdit::scrollbar::handle:vertical:hover, QPlainTextEdit::scrollbar::handle:vertical:hover, QTableWidget::scrollbar::handle:vertical:hover {
            background: #6BA8FF;
        }
        QListWidget::scrollbar::add-line:vertical, QListWidget::scrollbar::sub-line:vertical,
        QTextEdit::scrollbar::add-line:vertical, QTextEdit::scrollbar::sub-line:vertical,
        QPlainTextEdit::scrollbar::add-line:vertical, QPlainTextEdit::scrollbar::sub-line:vertical,
        QTableWidget::scrollbar::add-line:vertical, QTableWidget::scrollbar::sub-line:vertical {
            height: 0px;
        }
        """

    def create_software_inventory_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        title = QLabel("📦 Installed Software Inventory")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #4CAF50;")
        layout.addWidget(title)

        self.software_list = QListWidget()
        self.software_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #f1f1f1;
                border: 1px solid #444;
                padding: 6px;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 4px;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: black;
            }
        """)
        self.software_list.setFont(QFont("Consolas", 10))

        os_platform = platform.system()

        try:
            if os_platform == "Windows":
                output = subprocess.check_output(
                    'wmic product get Name,Version',
                    shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL
                ).decode(errors='ignore').split('\n')[1:]
            elif os_platform == "Linux":
                output = subprocess.check_output(
                    ['dpkg-query', '-W', '-f=${binary:Package} ${Version}\n']
                ).decode().split('\n')
            elif os_platform == "Darwin":
                output = subprocess.check_output(['brew', 'list', '--versions']).decode().split('\n')
            else:
                output = ["⚠️ Unsupported OS"]

            for line in output:
                line = line.strip()
                if line:
                    self.software_list.addItem(line)

        except Exception as e:
            self.software_list.addItem(f"❌ Error fetching software list: {e}")

        layout.addWidget(self.software_list)
        tab.setLayout(layout)
        return tab

    def create_usb_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(12)

        title = QLabel("🔍 USB Suspicious File Scanner")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #FF9800;")
        layout.addWidget(title)

        info_label = QLabel("Insert a USB device and click the button to scan for potentially suspicious files.")
        info_label.setStyleSheet("color: #dddddd; font-size: 13px;")
        layout.addWidget(info_label)

        scan_button = QPushButton("Scan USB")
        scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        scan_button.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #e68900;
            }
            QPushButton:pressed {
                background-color: #bf7200;
            }
        """)
        layout.addWidget(scan_button)

        self.usb_result_box = QTextEdit()
        self.usb_result_box.setReadOnly(True)
        self.usb_result_box.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #f1f1f1;
                border: 1px solid #444;
                padding: 8px;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.usb_result_box)

        SUSPICIOUS_KEYWORDS = [
            "unauthorized_access", "binary_anomaly", "elevated_privileges",
            "network_injection", "unknown_executable"
        ]

        def list_usb_drives():
            return [p.mountpoint for p in psutil.disk_partitions() if
                    'removable' in p.opts.lower() or 'usb' in p.device.lower()]

        def scan_files_for_suspicious_words(root_path):
            found = []
            for dirpath, _, filenames in os.walk(root_path):
                for fname in filenames:
                    if any(k in fname.lower() for k in SUSPICIOUS_KEYWORDS):
                        found.append(os.path.join(dirpath, fname))
            return found

        def usb_threat_scan():
            drives = list_usb_drives()
            if not drives:
                return None
            all_suspicious = []
            for d in drives:
                try:
                    all_suspicious += scan_files_for_suspicious_words(d)
                except PermissionError:
                    pass
            return all_suspicious

        def format_usb_scan_message(suspicious_files):
            if suspicious_files is None:
                return "⚠️ No USB drives detected. Please insert one and try again."
            if suspicious_files:
                msg = "⚠️ Potential threats detected on USB!\nReview before using:\n\n"
                msg += "\n".join(f"- {f}" for f in suspicious_files)
            else:
                msg = "✅ No suspicious files found. USB devices appear clean."
            return msg

        def on_scan_clicked():
            self.usb_result_box.clear()
            result = usb_threat_scan()
            self.usb_result_box.setPlainText(format_usb_scan_message(result))

        scan_button.clicked.connect(on_scan_clicked)

        tab.setLayout(layout)
        return tab

    def create_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)

        title = QLabel("🌐 Active Network Connections")
        title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #2196F3;
            padding-bottom: 5px;
        """)

        description = QLabel("Below is a real-time list of active internet and local network connections.")
        description.setWordWrap(True)
        description.setStyleSheet("color: #555; font-size: 14px;")

        net_list = QListWidget()
        net_list.setObjectName("netListWidget")
        net_list.setStyleSheet("""
            QListWidget#netListWidget {
                background-color: #f2f2f2;
                border: 1px solid #ccc;
                border-radius: 10px;
                padding: 10px;
                font-size: 13px;
                color: #333;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ddd;
            }
            QListWidget::item:selected {
                background-color: #D1E9FF;
                color: #000;
            }
        """)

        layout.addWidget(title)
        layout.addWidget(description)
        layout.addWidget(net_list)

        tab.setLayout(layout)
        return tab

    def update_network(self):
        self.net_list.clear()
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self.net_list.addItem("❌ Access Denied. Run as administrator/root.")
            self.log("❌ Cannot read network connections: Access Denied")
            return
        except Exception as e:
            self.net_list.addItem(f"❌ Error: {str(e)}")
            self.log(f"❌ Error reading network connections: {str(e)}")
            return

        if not conns:
            self.net_list.addItem("⚠️ No network connections found.")
            return

        for conn in conns:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status
            pid = conn.pid if conn.pid else "N/A"
            self.net_list.addItem(f"Local: {laddr} → Remote: {raddr} | Status: {status} | PID: {pid}")

    def toggle_auto_network(self, state):
        if state == Qt.Checked:
            self.network_timer.start(3000)
            self.log("✅ Auto-refresh network enabled")
        else:
            self.network_timer.stop()
            self.log("❌ Auto-refresh network disabled")

    def update_network_traffic(self):
        if not hasattr(self, 'net_traffic_list'):
            return

        self.net_traffic_list.clear()

        try:
            net_io = psutil.net_io_counters(pernic=True)
        except Exception as e:
            self.net_traffic_list.addItem(f"❌ Error reading network traffic: {str(e)}")
            self.log(f"❌ Error reading network traffic: {str(e)}")
            return

        if not net_io:
            self.net_traffic_list.addItem("⚠️ No network interfaces found.")
            self.log("⚠️ No network interfaces found.")
            return

        if not hasattr(self, 'prev_net_io'):
            self.prev_net_io = {}

        for iface, stats in net_io.items():
            sent_mb = stats.bytes_sent / (1024 ** 2)
            recv_mb = stats.bytes_recv / (1024 ** 2)

            prev_stats = self.prev_net_io.get(iface)
            if prev_stats:
                delta_sent = sent_mb - prev_stats['sent']
                delta_recv = recv_mb - prev_stats['recv']
                speed = f"📥 {delta_recv:.2f} MB/s | 📤 {delta_sent:.2f} MB/s"
            else:
                speed = "⚙️ Calculating..."

            entry = (f"🌐 Interface: {iface}\n"
                     f"    Sent: {sent_mb:.2f} MB\n"
                     f"    Received: {recv_mb:.2f} MB\n"
                     f"    Speed: {speed}")

            self.net_traffic_list.addItem(entry)

            self.prev_net_io[iface] = {'sent': sent_mb, 'recv': recv_mb}

        if hasattr(self, 'auto_scan_enabled') and self.auto_scan_enabled:
            self.log(f"✅ Auto-refreshed network traffic info.")

    def create_network_traffic_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("📡 Live Network Traffic Analyzer")
        title.setFont(QFont("Helvetica Neue", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #2196F3; margin-bottom: 12px;")
        layout.addWidget(title)

        self.net_traffic_list = QListWidget()
        self.net_traffic_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                border: 1px solid #444444;
                padding: 10px;
                font-size: 14px;
                border-radius: 8px;
            }
            QListWidget::item {
                padding: 8px;
                margin-bottom: 4px;
                border-bottom: 1px solid #333333;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
        """)
        layout.addWidget(self.net_traffic_list, 1)

        refresh_btn = QPushButton("Refresh Network Traffic")
        refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_btn.setToolTip("Click to manually refresh network traffic data.")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 15px;
                transition: background-color 0.2s ease;
                margin-top: 15px;
            }
            QPushButton:hover {
                background-color: #1769aa;
            }
            QPushButton:pressed {
                background-color: #0d47a1;
            }
        """)
        refresh_btn.clicked.connect(self.update_network_traffic)
        layout.addWidget(refresh_btn)

        tab.setLayout(layout)

        self.net_traffic_timer = QTimer()
        self.net_traffic_timer.timeout.connect(self.update_network_traffic)
        self.net_traffic_timer.start(5000)

        return tab

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_box.append(f"[{timestamp}] {message}")
        self.log_box.moveCursor(Qt.TextCursor.End)

    def show_notification(self, title: str, message: str):
        if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                title,
                message,
                QSystemTrayIcon.MessageIcon.Information,
                5000
            )
        else:
            print(f"Notification: {title} - {message}")

    def update_processes(self):
        if hasattr(self, 'auto_scan_enabled') and not self.auto_scan_enabled:
            return
        if not hasattr(self, 'proc_list'):
            return

        self.proc_list.clear()
        suspicious_count = 0

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                exe = proc.info['exe']

                if not exe:
                    suspicious_count += 1
                    entry = f"⚠️ PID {pid} - {name} - MISSING executable path"
                else:
                    entry = f"✅ PID {pid} - {name} - {exe}"

                self.proc_list.addItem(entry)
                self.log(entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if suspicious_count == 0:
            msg = "✅ All processes have valid executable paths."
            self.proc_list.addItem(msg)
            self.log(msg)
        else:
            self.log(f"⚠️ {suspicious_count} suspicious process(es) found.")

        self.proc_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                font-family: Consolas, monospace;
                font-size: 13px;
                padding: 8px;
                border-radius: 6px;
            }
            QListWidget::item:selected {
                background-color: #d32f2f;
                color: white;
            }
        """)

    def kill_selected_process(self):
        selected = self.proc_list.currentItem()
        if selected:
            pid_match = re.search(r'PID (\d+)', selected.text())
            if pid_match:
                pid = int(pid_match.group(1))
                try:
                    psutil.Process(pid).terminate()
                    self.log(f"🛑 Terminated PID {pid}")
                    self.update_processes()
                except Exception as e:
                    self.log(f"❌ Failed to terminate PID {pid}: {str(e)}")

    def update_network(self):
        if not hasattr(self, 'net_list'):
            return

        self.net_list.clear()
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self.net_list.addItem("❌ Access Denied. Run as administrator.")
            self.log("❌ Cannot read network connections (access denied).")
            return

        count = 0
        for conn in conns:
            if conn.status == "ESTABLISHED" and conn.raddr:
                try:
                    pid = conn.pid or "N/A"
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    entry = f"🔗 {proc_name} (PID {pid}) ➜ {conn.raddr.ip}:{conn.raddr.port}"
                    self.net_list.addItem(entry)
                    self.log(entry)
                    count += 1
                except Exception:
                    continue

        if count == 0:
            msg = "✅ No active external network connections found."
            self.net_list.addItem(msg)
            self.log(msg)

        self.net_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                font-size: 13px;
                padding: 8px;
                border-radius: 6px;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
        """)

    # --- Tab Creation Functions ---

    def get_uptime(self):
        boot_time_ts = psutil.boot_time()
        boot_time = datetime.fromtimestamp(boot_time_ts).strftime("%Y-%m-%d %H:%M:%S")
        now_ts = datetime.now().timestamp()

        uptime_seconds = int(now_ts - boot_time_ts)

        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

        return f"Boot time: {boot_time} | Uptime: {uptime_str}"

    def create_uptime_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Uptime & Boot Time calculation
        boot_time_ts = psutil.boot_time()
        boot_time = datetime.fromtimestamp(boot_time_ts).strftime("%Y-%m-%d %H:%M:%S")
        uptime_seconds = int(datetime.now().timestamp() - boot_time_ts)
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"

        # Main info box
        group = QGroupBox("🕒 System Uptime Overview")
        group.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: 600;
                color: #333;
                border: 2px solid #2196F3;
                border-radius: 12px;
                padding: 15px;
                background-color: #f9f9f9;
            }
        """)

        group_layout = QVBoxLayout()
        group_layout.setSpacing(15)

        uptime_label = QLabel(
            f"<span style='font-size:17px; font-weight:600; color:#4CAF50;'>⏱️ Uptime:</span><br>"
            f"<span style='font-size:15px; color:#444;'>{uptime_str}</span>"
        )
        uptime_label.setWordWrap(True)

        boot_label = QLabel(
            f"<span style='font-size:17px; font-weight:600; color:#2196F3;'>🖥️ Boot Time:</span><br>"
            f"<span style='font-size:15px; color:#444;'>{boot_time}</span>"
        )
        boot_label.setWordWrap(True)

        group_layout.addWidget(uptime_label)
        group_layout.addWidget(boot_label)
        group.setLayout(group_layout)

        layout.addWidget(group)
        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def create_disk_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        table = QTableWidget()
        partitions = psutil.disk_partitions(all=False)
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Partition", "Mount Point", "Total (GB)", "Used (GB)", "Free (GB)"])

        rows = []
        for p in partitions:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                rows.append((
                    p.device,
                    p.mountpoint,
                    f"{usage.total // (1024 ** 3)}",
                    f"{usage.used // (1024 ** 3)}",
                    f"{usage.free // (1024 ** 3)}",
                    usage.percent
                ))
            except PermissionError:
                rows.append((
                    p.device,
                    p.mountpoint,
                    "N/A",
                    "N/A",
                    "N/A",
                    None
                ))

        table.setRowCount(len(rows))
        for i, (device, mount, total, used, free, percent) in enumerate(rows):
            table.setItem(i, 0, QTableWidgetItem(device))
            table.setItem(i, 1, QTableWidgetItem(mount))
            table.setItem(i, 2, QTableWidgetItem(total))
            table.setItem(i, 3, QTableWidgetItem(used))
            table.setItem(i, 4, QTableWidgetItem(free))

            if percent is not None and percent > 90:
                for col in range(5):
                    table.item(i, col).setBackground(QColor("#ff4d4d"))
            elif percent is None:
                for col in range(5):
                    table.item(i, col).setBackground(QColor("#ffcc00"))

        table.resizeColumnsToContents()
        table.setSortingEnabled(True)
        layout.addWidget(QLabel("<h2>Disk Usage</h2>"))
        layout.addWidget(table)
        tab.setLayout(layout)
        return tab

    def create_startup_tab(self):
        import winreg

        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        startup_programs = []

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                startup_programs.append(f"{name}: {value}")
        except Exception:
            startup_programs.append("⚠️ Could not read startup programs.")

        list_widget = QListWidget()
        list_widget.addItems(startup_programs)
        list_widget.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                padding: 8px;
                border-radius: 6px;
                font-size: 13px;
            }
        """)
        layout.addWidget(QLabel("<h2>Startup Programs</h2>"))
        layout.addWidget(list_widget)

        tab.setLayout(layout)
        return tab

    def create_services_tab(self):
        import psutil

        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        services = []
        try:
            for service in psutil.win_service_iter():
                status = service.status()
                services.append(f"{service.name()} — {status}")
        except Exception:
            services.append("⚠️ Could not retrieve services.")

        list_widget = QListWidget()
        list_widget.addItems(services)
        list_widget.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                padding: 8px;
                border-radius: 6px;
                font-size: 13px;
            }
        """)
        layout.addWidget(QLabel("<h2>Services Status</h2>"))
        layout.addWidget(list_widget)

        tab.setLayout(layout)
        return tab

    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        hostname = socket.gethostname()
        ip = self.get_local_ip()

        if sys.platform == "win32":
            os_name = self.get_windows_version_accurate()
        else:
            if hasattr(os, "uname"):
                uname = os.uname()
                os_name = f"{uname.sysname} {uname.release} ({uname.machine})"
            else:
                os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"

        python_version = platform.python_version()
        processor = platform.processor()
        uptime = self.get_uptime()

        label = QLabel(f"""
            <h2 style='color:#1E88E5; margin-bottom:15px;'>Rootkit Scanner DevKit</h2>
            <p style='font-size:13px; margin-bottom:10px;'>
                Use this toolkit to inspect, audit and monitor key areas of your system.
            </p>
            <p style='font-size:13px; margin-bottom:10px;'>
                <b>System Info:</b><br>
                Hostname: {hostname}<br>
                IP Address: {ip}<br>
                OS: {os_name}<br>
                Python Version: {python_version}<br>
                Processor: {processor}<br>
                <b>Uptime:</b> {uptime}
            </p>
            <p style='font-size:13px; margin-top:20px; color:#FF5252; font-weight:bold;'>
                ⚠️ For complete analysis, run this tool as Administrator
            </p>
        """)

        label.setWordWrap(True)
        label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        refresh_button = QPushButton("Refresh System Info")
        refresh_button.clicked.connect(self.refresh_dashboard_info)

        layout.addWidget(label)
        layout.addWidget(refresh_button)

        self.dashboard_sysinfo_text = QTextEdit()
        self.dashboard_sysinfo_text.setReadOnly(True)
        self.dashboard_sysinfo_text.setPlaceholderText("📊 System info will appear here after scan...")

        layout.addWidget(self.dashboard_sysinfo_text)

        tab.setLayout(layout)

        self.refresh_dashboard_info()

        return tab

    def refresh_dashboard_info(self):
        hostname = socket.gethostname()
        ip = self.get_local_ip()
        if sys.platform == "win32":
            os_name = self.get_windows_version_accurate()
        else:
            if hasattr(os, "uname"):
                uname = os.uname()
                os_name = f"{uname.sysname} {uname.release} ({uname.machine})"
            else:
                os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
        python_version = platform.python_version()
        processor = platform.processor()
        uptime = self.get_uptime()

        info_text = (
            f"Hostname: {hostname}\n"
            f"IP Address: {ip}\n"
            f"OS: {os_name}\n"
            f"Python Version: {python_version}\n"
            f"Processor: {processor}\n"
            f"Uptime: {uptime}\n"
        )

        self.dashboard_sysinfo_text.setPlainText(info_text)

        self.dashboard_sysinfo_text.setPlainText(info_text)

    def get_interval_ms(self):
        value = self.interval_spinbox.value()
        unit = self.interval_units.currentText().lower()
        multipliers = {
            "sec": 1000,
            "min": 60 * 1000,
            "hr": 60 * 60 * 1000,
            "day": 24 * 60 * 60 * 1000,
            "month": 30 * 24 * 60 * 60 * 1000,
            "year": 365 * 24 * 60 * 60 * 1000,
        }
        multiplier = multipliers.get(unit, 1000)
        interval_ms = value * multiplier

        if interval_ms < 1000:
            interval_ms = 1000
            self.log("⚠️ Interval too low, set to minimum 1 second.")
        elif interval_ms > 24 * 60 * 60 * 1000:  # max 1 dan
            interval_ms = 24 * 60 * 60 * 1000
            self.log("⚠️ Interval too high, capped to maximum 1 day.")
        return interval_ms

    def toggle_auto_scan(self, state):
        if state == Qt.CheckState.Checked.value:
            interval_ms = self.get_interval_ms()
            if not hasattr(self, 'auto_scan_timer'):
                self.auto_scan_timer = QTimer(self)
                self.auto_scan_timer.timeout.connect(self.update_processes)
            self.auto_scan_timer.start(interval_ms)
            self.log(
                f"🕒 Auto-scan enabled. Interval: {self.interval_spinbox.value()} {self.interval_units.currentText()}")
        else:
            if hasattr(self, 'auto_scan_timer'):
                self.auto_scan_timer.stop()
            self.log("🕒 Auto-scan disabled.")

    def toggle_auto_refresh_proc(self, state):
        if state == Qt.CheckState.Checked.value:
            if not hasattr(self, 'process_timer'):
                self.process_timer = QTimer(self)
                self.process_timer.timeout.connect(self.update_processes)
            self.process_timer.start(10000)
            self.log("🔄 Auto-refresh for Processes enabled.")
        else:
            if hasattr(self, 'process_timer'):
                self.process_timer.stop()
            self.log("⏸️ Auto-refresh for Processes disabled.")

    def toggle_auto_network(self, state):
        if state == Qt.CheckState.Checked.value:
            self.update_network()
            if not hasattr(self, 'network_timer'):
                self.network_timer = QTimer(self)
                self.network_timer.timeout.connect(self.update_network)
            self.network_timer.start(10000)
            self.log("🌐 Auto-refresh for Network Connections enabled (refresh now, then every 10s).")
        else:
            if hasattr(self, 'network_timer'):
                self.network_timer.stop()
            self.log("⏸️ Auto-refresh for Network Connections disabled.")

    def change_scan_interval(self, value):
        if hasattr(self, 'auto_scan_timer') and self.auto_scan_timer.isActive():
            interval_ms = self.get_interval_ms()
            self.auto_scan_timer.start(interval_ms)
            self.log(
                f"⏱️ Auto-scan interval changed to {self.interval_spinbox.value()} {self.interval_units.currentText()}.")

    def get_cpu_temperature(self):
        try:
            w = wmi.WMI(namespace="root\\wmi")
            temperature_info = w.MSAcpi_ThermalZoneTemperature()
            if not temperature_info:
                return None
            for sensor in temperature_info:
                temp_c = (sensor.CurrentTemperature / 10.0) - 273.15
                if temp_c > 0:
                    return round(temp_c, 1)
            return None
        except Exception as e:
            self.log(f"CPU Temp error: {e}")
            return None

    def get_gpu_temperature(self):
        try:
            py3nvml.nvmlInit()
            device_count = py3nvml.nvmlDeviceGetCount()
            if device_count > 0:
                handle = py3nvml.nvmlDeviceGetHandleByIndex(0)
                temp = py3nvml.nvmlDeviceGetTemperature(handle, py3nvml.NVML_TEMPERATURE_GPU)
                py3nvml.nvmlShutdown()
                self.log(f"GPU Temp read {temp}")
                return temp
            py3nvml.nvmlShutdown()
            self.log("No Nvidia GPU found.")
            return None
        except Exception as e:
            self.log(f"GPU Temp error: {e}")
            try:
                py3nvml.nvmlShutdown()
            except Exception:
                pass
            return None

    def create_hardware_monitor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Temperature Labels
        self.cpu_temp_label = QLabel("CPU Temperature: -- °C")
        self.gpu_temp_label = QLabel("GPU Temperature: -- °C")

        font = QFont("Helvetica Neue", 16, QFont.Weight.Bold)
        self.cpu_temp_label.setFont(font)
        self.gpu_temp_label.setFont(font)

        self.cpu_temp_label.setStyleSheet("color: #4CAF50;")
        self.gpu_temp_label.setStyleSheet("color: #2196F3;")

        layout.addWidget(self.cpu_temp_label)
        layout.addWidget(self.gpu_temp_label)

        # Plotting area
        self.fig = Figure(figsize=(8, 4), dpi=100)
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)

        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("CPU & GPU Temperature Over Time")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("Temperature (°C)")
        self.ax.grid(True)

        refresh_button = QPushButton("Refresh Temperatures Now")
        refresh_button.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 14px;
                transition: background-color 0.2s ease;
            }
            QPushButton:hover {
                background-color: #1769aa;
            }
            QPushButton:pressed {
                background-color: #0d47a1;
            }
        """)
        refresh_button.clicked.connect(self.update_temperatures)
        layout.addWidget(refresh_button)

        tab.setLayout(layout)

        if not hasattr(self, 'time_stamps'):
            self.time_stamps = []
        if not hasattr(self, 'cpu_temps'):
            self.cpu_temps = []
        if not hasattr(self, 'gpu_temps'):
            self.gpu_temps = []

        self.temp_timer = QTimer(self)
        self.temp_timer.timeout.connect(self.update_temperatures)
        self.temp_timer.start(5000)

        return tab

    def update_temperatures(self):
        cpu_temp = self.get_cpu_temperature()
        gpu_temp = self.get_gpu_temperature()

        if cpu_temp is None:
            self.cpu_temp_label.setText("CPU Temperature: ❌ Not available on your system")
        else:
            self.cpu_temp_label.setText(f"CPU Temperature: {cpu_temp} °C")

        if gpu_temp is None:
            self.gpu_temp_label.setText("GPU Temperature: ❌ Not available")
        else:
            self.gpu_temp_label.setText(f"GPU Temperature: {gpu_temp} °C")
            if gpu_temp > 80:
                self.log(f"⚠️ High GPU temperature detected: {gpu_temp} °C")

        current_time = datetime.now().strftime("%H:%M:%S")

        self.time_stamps.append(current_time)
        self.cpu_temps.append(cpu_temp if cpu_temp is not None else 0)
        self.gpu_temps.append(gpu_temp if gpu_temp is not None else 0)

        if len(self.time_stamps) > 30:
            self.time_stamps.pop(0)
            self.cpu_temps.pop(0)
            self.gpu_temps.pop(0)

        self.ax.clear()

        bg_color = "#121212" if getattr(self, 'current_theme', 'Dark') == "Dark" else "#FFFFFF"
        text_color = "#EEEEEE" if bg_color == "#121212" else "#222222"

        self.fig.patch.set_facecolor(bg_color)
        self.ax.set_facecolor(bg_color)
        self.ax.set_ylim(0, 95)

        self.ax.plot(self.time_stamps, self.cpu_temps, label="CPU Temp (°C)", color="#4CAF50", linewidth=2)
        self.ax.plot(self.time_stamps, self.gpu_temps, label="GPU Temp (°C)", color="#2196F3", linewidth=2)

        self.ax.set_title("CPU & GPU Temperature Over Time", color=text_color)
        self.ax.set_xlabel("Time", color=text_color)
        self.ax.set_ylabel("Temperature (°C)", color=text_color)

        self.ax.tick_params(axis='x', colors=text_color, rotation=45)
        self.ax.tick_params(axis='y', colors=text_color)

        legend = self.ax.legend()
        frame = legend.get_frame()
        frame.set_facecolor(bg_color)
        frame.set_edgecolor(bg_color)
        for text in legend.get_texts():
            text.set_color(text_color)

        self.ax.grid(True, color="#555555" if bg_color == "#121212" else "#CCCCCC")

        self.fig.tight_layout()
        self.canvas.draw_idle()

    def handle_theme_change(self, theme_name):
        self.current_theme = theme_name
        self.apply_theme(theme_name)
        self.update_temperatures()
        self.canvas.draw_idle()

    def create_process_tab(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.proc_list = QListWidget()
        self.proc_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #eeeeee;
                font-family: Consolas, monospace;
                font-size: 13px;
                padding: 8px;
                border-radius: 6px;
            }
            QListWidget::item:selected {
                background-color: #d32f2f;
                color: white;
            }
        """)
        layout.addWidget(self.proc_list)

        self.scan_proc_button = QPushButton("Scan Running Processes")
        self.scan_proc_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_proc_button.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 14px;
                transition: background-color 0.2s ease;
            }
            QPushButton:hover {
                background-color: #9a0007;
            }
            QPushButton:pressed {
                background-color: #6b0004;
            }
        """)
        self.scan_proc_button.clicked.connect(self.update_processes)
        layout.addWidget(self.scan_proc_button)

        self.auto_refresh_proc_checkbox = QCheckBox("Enable Auto Process Scan")
        self.auto_refresh_proc_checkbox.stateChanged.connect(self.toggle_auto_refresh_proc)
        layout.addWidget(self.auto_refresh_proc_checkbox)

        widget = QWidget()
        widget.setLayout(layout)
        return widget

    def create_hidden_files_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.hidden_files_btn = QPushButton("Scan for Hidden Files")
        self.hidden_files_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.hidden_files_btn.clicked.connect(self.handle_hidden_files_scan)
        layout.addWidget(self.hidden_files_btn)

        self.hidden_files_list = QListWidget()
        self.hidden_files_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.hidden_files_list)

        tab.setLayout(layout)
        return tab

    def create_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.net_btn = QPushButton("Check Network Connections")
        self.net_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.net_btn.clicked.connect(self.handle_network_scan)
        layout.addWidget(self.net_btn)

        self.net_list = QListWidget()
        self.net_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.net_list)

        tab.setLayout(layout)
        return tab

    def create_sysinfo_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.sysinfo_btn = QPushButton("Show System Info")
        self.sysinfo_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sysinfo_btn.clicked.connect(self.handle_sysinfo_scan)
        layout.addWidget(self.sysinfo_btn)

        self.sysinfo_list = QListWidget()
        self.sysinfo_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.sysinfo_list)

        tab.setLayout(layout)
        return tab

    def create_startup_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.startup_btn = QPushButton("Scan Startup Programs")
        self.startup_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.startup_btn.clicked.connect(self.handle_startup_scan)
        layout.addWidget(self.startup_btn)

        self.startup_list = QListWidget()
        self.startup_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.startup_list)

        tab.setLayout(layout)
        return tab

    def create_services_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.services_btn = QPushButton("Scan Services")
        self.services_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.services_btn.clicked.connect(self.handle_services_scan)
        layout.addWidget(self.services_btn)

        self.services_list = QListWidget()
        self.services_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.services_list)

        tab.setLayout(layout)
        return tab

    def create_file_integrity_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.integrity_btn = QPushButton("Check File Integrity")
        self.integrity_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.integrity_btn.clicked.connect(self.handle_integrity_check)
        layout.addWidget(self.integrity_btn)

        self.integrity_list = QListWidget()
        self.integrity_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.integrity_list)

        tab.setLayout(layout)
        return tab

    def create_users_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        self.users_btn = QPushButton("List System Users")
        self.users_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.users_btn.clicked.connect(self.handle_users_scan)
        layout.addWidget(self.users_btn)

        self.users_list = QListWidget()
        self.users_list.setStyleSheet(self._list_widget_style())
        layout.addWidget(self.users_list)

        tab.setLayout(layout)
        return tab

    def apply_theme(self, theme):
        theme = theme.lower()
        if theme == "dark":
            self.setStyleSheet("""
                QWidget {
                    background-color: #121212;
                    color: #E0E0E0;
                    font-family: 'Segoe UI';
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #1E88E5;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #42A5F5;
                }
                QPushButton:pressed {
                    background-color: #1565C0;
                }
                QTextEdit, QListWidget {
                    background-color: #1A1A1A;
                    border: 1px solid #2A2A2A;
                    border-radius: 8px;
                    padding: 6px;
                }
                QTabWidget::pane {
                    border: 1px solid #2A2A2A;
                    border-radius: 10px;
                }
                QTabBar::tab {
                    background-color: #1E1E1E;
                    padding: 6px 12px;
                    border-radius: 8px;
                    margin: 2px;
                }
                QTabBar::tab:selected {
                    background-color: #333333;
                }
            """)
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #F0F0F0;
                    color: #202020;
                    font-family: 'Segoe UI';
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #1E88E5;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #42A5F5;
                }
                QPushButton:pressed {
                    background-color: #1565C0;
                }
                QTextEdit, QListWidget {
                    background-color: #FFFFFF;
                    border: 1px solid #CCCCCC;
                    border-radius: 8px;
                    padding: 6px;
                }
                QTabWidget::pane {
                    border: 1px solid #CCCCCC;
                    border-radius: 10px;
                }
                QTabBar::tab {
                    background-color: #F9F9F9;
                    padding: 6px 12px;
                    border-radius: 8px;
                    margin: 2px;
                }
                QTabBar::tab:selected {
                    background-color: #DDDDDD;
                }
            """)

    def get_windows_version_accurate(self):
        try:
            ps_cmd = [
                "powershell",
                "-Command",
                """
                $reg = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
                $props = 'ProductName', 'DisplayVersion', 'CurrentBuildNumber';
                $obj = @{};
                foreach ($p in $props) { $obj[$p] = (Get-ItemProperty -Path $reg -Name $p).$p }
                $obj | ConvertTo-Json
                """
            ]
            proc = subprocess.run(ps_cmd, capture_output=True, text=True, shell=True)
            if proc.returncode != 0 or not proc.stdout.strip():
                return "Windows (version info unavailable)"

            import json
            info = json.loads(proc.stdout)

            product_name = info.get("ProductName", "Windows")
            display_version = info.get("DisplayVersion", "")
            build_number = info.get("CurrentBuildNumber", "")

            if display_version:
                return f"{product_name} (Version {display_version}, Build {build_number})"
            else:
                return f"{product_name} (Build {build_number})"

        except Exception as e:
            return f"Windows (version info unavailable: {e})"

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "Unavailable"

    # --- Scan handlers ---

    def handle_sysinfo_scan(self):
        self.sysinfo_list.clear()
        try:
            import platform
            info = [
                f"System: {platform.system()}",
                f"Node Name: {platform.node()}",
                f"Release: {platform.release()}",
                f"Version: {platform.version()}",
                f"Machine: {platform.machine()}",
                f"Processor: {platform.processor()}",
            ]
            self.sysinfo_list.addItems(info)

            self.system_info_data = "\n".join(info)
            if hasattr(self, 'dashboard_sysinfo_text'):
                self.dashboard_sysinfo_text.setPlainText(self.system_info_data)

            self.log("🖥️ System info scanned successfully.")
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Error", f"Failed to get system info:\n{e}")
            self.log(f"❌ Failed to get system info: {e}")

    def handle_process_scan(self):
        self.proc_list.clear()
        found = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                exe = proc.info['exe'] or "UNKNOWN"
                if exe == "UNKNOWN":
                    found += 1
                    entry = f"⚠️ PID {pid} - {name} - MISSING executable path"
                    self.proc_list.addItem(entry)
                    self.log(entry)
            except Exception:
                continue
        if found == 0:
            msg = "✅ All processes have valid executable paths."
            self.proc_list.addItem(msg)
            self.log(msg)
        else:
            self.log(f"⚠️ {found} suspicious process(es) found.")

    def handle_hidden_files_scan(self):
        self.hidden_files_list.clear()
        # Check system paths depending on OS
        paths = ["/etc", "/usr/bin", "/bin"] if os.name != "nt" else ["C:\\Windows\\System32"]
        suspicious = 0
        for path in paths:
            if os.path.isdir(path):
                for fname in os.listdir(path):
                    full_path = os.path.join(path, fname)
                    if fname.startswith(".") or fname.lower() in ["svchost.exe", "lsass.exe", "systemd"]:
                        if not os.access(full_path, os.X_OK):
                            suspicious += 1
                            entry = f"⚠️ Hidden/Suspicious: {full_path}"
                            self.hidden_files_list.addItem(entry)
                            self.log(entry)
        if suspicious == 0:
            msg = "✅ No hidden or suspicious files detected."
            self.hidden_files_list.addItem(msg)
            self.log(msg)
        else:
            self.log(f"⚠️ {suspicious} suspicious file(s) found.")

    def handle_network_scan(self):
        self.net_list.clear()
        try:
            conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            self.net_list.addItem("❌ Access Denied. Run as administrator/root.")
            self.log("❌ Cannot read network connections (access denied).")
            return

        count = 0
        for conn in conns:
            if conn.status == "ESTABLISHED" and conn.raddr:
                try:
                    pid = conn.pid or "N/A"
                    proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                    entry = f"🔗 {proc_name} (PID {pid}) ➜ {conn.raddr.ip}:{conn.raddr.port}"
                    self.net_list.addItem(entry)
                    self.log(entry)
                    count += 1
                except Exception:
                    continue
        if count == 0:
            msg = "✅ No active external network connections found."
            self.net_list.addItem(msg)
            self.log(msg)

    def handle_startup_scan(self):
        self.startup_list.clear()
        if sys.platform == "win32":
            import winreg
            try:
                startup_keys = [
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"Software\Microsoft\Windows\CurrentVersion\RunServices"
                ]
                found = 0
                for key_path in startup_keys:
                    try:
                        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
                        i = 0
                        while True:
                            name, value, _ = winreg.EnumValue(reg_key, i)
                            self.startup_list.addItem(f"{name}: {value}")
                            i += 1
                            found += 1
                    except OSError:
                        # No more values
                        pass
                if found == 0:
                    self.startup_list.addItem("✅ No startup entries found.")
                self.log(f"🛠️ Startup scan completed, found {found} entries.")
            except Exception as e:
                self.startup_list.addItem(f"❌ Error: {e}")
                self.log(f"❌ Startup scan error: {e}")
        else:
            self.startup_list.addItem("⚠️ Startup scan is Windows-only.")
            self.log("⚠️ Startup scan requested on non-Windows system.")

    def handle_services_scan(self):
        self.services_list.clear()
        if sys.platform == "win32":
            try:
                import wmi
                c = wmi.WMI()
                services = c.Win32_Service()
                for service in services:
                    status = service.State
                    name = service.Name
                    self.services_list.addItem(f"{name} - {status}")
                self.log(f"🛡️ Services scan completed, {len(services)} services listed.")
            except ImportError:
                self.services_list.addItem("❌ WMI module not installed. Cannot scan services.")
                self.log("❌ WMI module missing for services scan.")
            except Exception as e:
                self.services_list.addItem(f"❌ Error scanning services: {e}")
                self.log(f"❌ Services scan error: {e}")
        else:
            self.services_list.addItem("⚠️ Services scan is Windows-only.")
            self.log("⚠️ Services scan requested on non-Windows system.")

    def handle_integrity_check(self):
        self.integrity_list.clear()
        import hashlib
        target_dir = os.path.expanduser("~")
        files_checked = 0
        errors = 0

        for root, dirs, files in os.walk(target_dir):
            for file in files:
                try:
                    full_path = os.path.join(root, file)
                    with open(full_path, "rb") as f:
                        data = f.read()
                        file_hash = hashlib.sha256(data).hexdigest()
                    self.integrity_list.addItem(f"{full_path}: {file_hash[:16]}...")
                    files_checked += 1
                    if files_checked >= 100:
                        break
                except Exception as e:
                    self.integrity_list.addItem(f"❌ Error reading {full_path}: {e}")
                    errors += 1
            if files_checked >= 100:
                break

        self.log(f"🔍 File integrity check done. Files checked: {files_checked}, errors: {errors}")

    def handle_users_scan(self):
        self.users_list.clear()
        try:
            if sys.platform == "win32":
                import subprocess
                output = subprocess.check_output("net user", shell=True, text=True)
                users = []
                collecting = False
                for line in output.splitlines():
                    if "----" in line:
                        collecting = not collecting
                        continue
                    if collecting:
                        users.extend(line.split())
                for user in users:
                    self.users_list.addItem(user)
                self.log(f"👥 User list scanned, found {len(users)} users.")
            else:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        username = line.split(":")[0]
                        self.users_list.addItem(username)
                self.log("👥 User list scanned from /etc/passwd.")
        except Exception as e:
            self.users_list.addItem(f"❌ Error listing users: {e}")
            self.log(f"❌ Users scan error: {e}")

    # Utility functions

    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        if not hasattr(self, 'log_box'):
            self.log_box = QTextEdit()
            self.log_box.setReadOnly(True)
            self.log_box.setStyleSheet(self._list_widget_style())

        layout.addWidget(self.log_box)
        tab.setLayout(layout)

        return tab

    def log(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        if hasattr(self, 'log_box') and self.log_box is not None:
            self.log_box.append(log_entry)

    def save_log_to_file(self, filename):
        if not hasattr(self, 'log_box'):
            print("log_box does not exist, cannot save.")
            return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_box.toPlainText())
            self.log(f"✅ Log saved to {filename}")
        except Exception as e:
            self.log(f"❌ Failed to save log: {e}")

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self,
            "Exit Confirmation",
            "Do you want to save the current scan history log before exiting?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.save_log_to_file("scanner_log.txt")
            event.accept()
        elif reply == QMessageBox.StandardButton.No:
            event.accept()
        else:
            event.ignore()

    def clear_all_tabs(self, delete_log_file=False):
        lists_to_clear = [
            getattr(self, 'proc_list', None),
            getattr(self, 'net_list', None),
            getattr(self, 'hidden_files_list', None),
            getattr(self, 'sysinfo_list', None),
            getattr(self, 'startup_list', None),
            getattr(self, 'services_list', None),
            getattr(self, 'integrity_list', None),
            getattr(self, 'users_list', None),
        ]
        for lst in lists_to_clear:
            if isinstance(lst, QListWidget):
                lst.clear()
        if hasattr(self, 'log_box') and isinstance(self.log_box, QTextEdit):
            self.log_box.clear()

        if delete_log_file:
            log_file = "scanner_log.txt"
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                    self.log("🧹 Log file deleted.")
                except Exception as e:
                    self.log(f"❌ Error deleting log file: {e}")

        self.log("🧹 Scan history cleared.")

        self.found_processes = []
        self.network_connections = []
        self.hidden_files = []
        self.startup_entries = []

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RootKitScannerDevKit()
    window.show()
    sys.exit(app.exec())
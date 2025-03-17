import sys
import re
import threading
import socket
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QPushButton,
    QLineEdit,
    QStatusBar,
    QFormLayout,
    QLabel,
    QListWidget,
    QRadioButton,
    QGroupBox,
    QMessageBox,
    QHeaderView,
)
from PyQt6.QtCore import Qt
from dnslib import DNSRecord, QTYPE, A, AAAA, RR, DNSHeader
from theme import stylesheet
import os
import json

IPv4_REGEX = r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
IPv6_REGEX = r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"

DOMAIN_REGEX = r"^(?!-)(?!.*-$)(?!.*\.\.)(?!\.\.)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$"

CONFIG_FILE = os.path.join(os.getenv("APPDATA"), "valleyreborn.json")


class DNSServer:
    def __init__(self, ui_callback):
        self.records = []
        self.ui_callback = ui_callback
        self.running = False
        self.socket = None
        self.thread = None

    def start(self):
        """Starts the DNS server in a separate thread and listens on port 53"""
        self.running = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(("0.0.0.0", 53))
        except OSError:
            self.ui_callback("Could not start DNS server!\nPort 53 may already be in use by another program.")
            return
        self.ui_callback("DNS Server started on port 53...")

        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)
                response = self.handleQuery(data)
                self.socket.sendto(response, addr)
            except Exception as e:
                self.ui_callback(f"Error: {str(e)}")

    def stop(self):
        """Stops the DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
        self.ui_callback("DNS Server stopped...")

    def handleQuery(self, query):
        """Process incoming DNS queries and respond accordingly"""
        try:
            dns_query = DNSRecord.parse(query)
            qname = str(dns_query.q.qname)[:-1]
            qtype = dns_query.q.qtype
            response = dns_query.reply()
            response.header = DNSHeader(id=dns_query.header.id, qr=1, aa=1, ra=1)

            try:
                ip = [x for x in self.records if x["type"] == qtype and x["domain"] == qname]
            except Exception:
                ip = None

            if len(ip) < 1 or not ip:
                response.header.rcode = 3
                return response.pack()

            if ip[0]["type"] != qtype:
                response.header.rcode = 3

            if qtype == QTYPE.A:
                answer = RR(qname, QTYPE.A, rdata=A(ip[0]["ip_address"]), ttl=1)
            elif qtype == QTYPE.AAAA:
                answer = RR(qname, QTYPE.AAAA, rdata=AAAA(ip[0]["ip_address"]), ttl=1)

            if answer:
                self.ui_callback(f"Got {'A' if qtype == QTYPE.A else 'AAAA'} query for {qname}, resolved to {ip[0]['ip_address']}")
                response.add_answer(answer)
            else:
                response.header.rcode = 3

            return response.pack()

        except Exception as e:
            self.ui_callback(f"Error processing query: {str(e)}")
            return DNSRecord().error().pack()

    def addRecord(self, domain, ip_address, record_type):
        """Add a record to the DNS server"""
        self.records.append(
            {"ip_address": ip_address, "type": record_type, "domain": domain}
        )


class DNSServerUI(QMainWindow):
    def __init__(self):
        super().__init__()


        self.setWindowTitle("ValleyReborn by @nemvince")
        self.setGeometry(100, 100, 800, 600)

        self.initUI()

        QMessageBox.information(self, "Made by @nemvince", "This wonderful piece of software, otherwise known as Valley Reborn DNS was made by a student here, specifically for Völgyi Iván.")

        self.dns_server = DNSServer(self.updateStatus)

        self.loadConfig()

        self.startServer()

    def loadConfig(self):
        """Load DNS records and server settings from the config file."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as config_file:
                    config = json.load(config_file)

                self.blockSignals(True)
                for record in config["records"]:
                    domain = record["domain"]
                    ip_address = record["ip_address"]
                    rtype = record["type"]
                    self.dns_server.addRecord(domain, ip_address, rtype)

                    row_position = self.records_table.rowCount()
                    self.records_table.insertRow(row_position)
                    self.records_table.setItem(
                        row_position, 0, QTableWidgetItem(domain)
                    )
                    self.records_table.setItem(
                        row_position, 1, QTableWidgetItem(ip_address)
                    )
                    self.records_table.setItem(
                        row_position,
                        2,
                        QTableWidgetItem("A" if rtype == QTYPE.A else "AAAA"),
                    )
                    self.records_table.item(row_position, 2).setFlags(
                        self.records_table.item(row_position, 2).flags()
                        & ~Qt.ItemFlag.ItemIsEditable
                    )

            except Exception as e:
                self.blockSignals(False)
                QMessageBox.warning(
                    self, "Config Error", "Invalid or corrupt config. Couldn't load!"
                )
                raise e
            finally:
                self.blockSignals(False)

            self.updateStatus(
                f"Loaded {len(self.dns_server.records)} records from config."
            )
        else:
            self.updateStatus("No config found.")

    def saveConfig(self):
        """Save DNS records to the config file."""
        config = {"records": self.dns_server.records}

        with open(CONFIG_FILE, "w") as configfile:
            json.dump(config, configfile, indent=2, sort_keys=True)
        self.updateStatus("DNS records saved to config file.")

    def closeEvent(self, event):
        if self.dns_server.running:
            reply = QMessageBox.question(
                self, "Confirm Exit", 
                "The DNS server is running. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
        if self.dns_server.running:
            self.dns_server.stop()
            if self.dns_thread.is_alive():
                self.dns_thread.join()

        event.accept()  # accept fate

    def initUI(self):
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout()

        form_layout = QFormLayout()
        self.domain_name_input = QLineEdit()
        self.ip_address_input = QLineEdit()

        self.record_type_group = QGroupBox("Type")
        self.radio_ipv4 = QRadioButton("A (IPv4)")
        self.radio_ipv6 = QRadioButton("AAAA (IPv6)")

        self.radio_ipv4.setChecked(True)

        radio_layout = QVBoxLayout()
        radio_layout.addWidget(self.radio_ipv4)
        radio_layout.addWidget(self.radio_ipv6)
        self.record_type_group.setLayout(radio_layout)

        form_layout.addRow("Domain Name:", self.domain_name_input)
        form_layout.addRow("IP Address:", self.ip_address_input)
        form_layout.addRow(self.record_type_group)

        add_button = QPushButton("Add Record")
        add_button.clicked.connect(self.addRecord)

        left_layout.addLayout(form_layout)
        left_layout.addWidget(add_button)

        self.records_table = QTableWidget(0, 3)  # 3 columns: Domain, IP, Type
        self.records_table.setHorizontalHeaderLabels(
            ["Domain", "IP Address", "  Type  "]
        )
        self.records_table.cellChanged.connect(self.onCellChanged)

        left_layout.addWidget(self.records_table)

        delete_button = QPushButton("Delete Selected")
        delete_button.clicked.connect(self.deleteSelectedRecords)
        left_layout.addWidget(delete_button)

        left_widget.setLayout(left_layout)

        self.records_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.records_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self.records_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )

        right_widget = QWidget()
        right_layout = QVBoxLayout()

        self.log_list_widget = QListWidget()
        right_layout.addWidget(self.log_list_widget)

        right_widget.setLayout(right_layout)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        self.setCentralWidget(splitter)

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self.server_status_label = QLabel("Server Status: Stopped")
        self.server_status_label.setStyleSheet("color: red;")
        self.record_count_label = QLabel("Records: 0")

        self.statusBar.addPermanentWidget(self.server_status_label)
        self.statusBar.addPermanentWidget(self.record_count_label)

        start_button = QPushButton("Start Server")
        start_button.clicked.connect(self.startServer)

        stop_button = QPushButton("Stop Server")
        stop_button.clicked.connect(self.stopServer)

        clear_log_button = QPushButton("Clear Log")
        clear_log_button.clicked.connect(self.clearLog)

        self.domain_name_input.returnPressed.connect(self.addRecord)
        self.ip_address_input.returnPressed.connect(self.addRecord)

        self.statusBar.addWidget(start_button)
        self.statusBar.addWidget(stop_button)
        self.statusBar.addWidget(clear_log_button)

        self.setStyleSheet(stylesheet)

    def updateStatus(self, message):
        self.log_list_widget.addItem(message)

    def deleteSelectedRecords(self):
        selected = self.records_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Selection Error", "No records selected.")
            return

        rows = set(item.row() for item in selected)
        for row in sorted(rows, reverse=True):
            self.records_table.removeRow(row)
            del self.dns_server.records[row]
        self.saveConfig()
        self.updateStatus(f"Deleted {len(rows)} records.")

    def addRecord(self):
        self.blockSignals(True)
        domain = self.domain_name_input.text()
        ip_address = self.ip_address_input.text()

        if not re.match(DOMAIN_REGEX, domain):
            QMessageBox.warning(self, "Input Error", "Invalid domain name format.")
            return

        if not domain or not ip_address:
            QMessageBox.warning(
                self, "Input Error", "Please provide both domain name and IP address."
            )
            return

        if self.radio_ipv4.isChecked():
            if not re.match(IPv4_REGEX, ip_address):
                QMessageBox.warning(self, "Input Error", "Invalid IPv4 address format.")
                return
            record_type = QTYPE.A
        elif self.radio_ipv6.isChecked():
            if not re.match(IPv6_REGEX, ip_address):
                QMessageBox.warning(self, "Input Error", "Invalid IPv6 address format.")
                return
            record_type = QTYPE.AAAA

        existing = any(r['domain'] == domain and r['type'] == record_type for r in self.dns_server.records)
        if existing:
            QMessageBox.warning(self, "Duplicate Entry", "A record with this domain and type already exists.")
            return

        self.dns_server.addRecord(domain, ip_address, record_type)

        row_position = self.records_table.rowCount()
        self.records_table.insertRow(row_position)
        self.records_table.setItem(row_position, 0, QTableWidgetItem(domain))
        self.records_table.setItem(row_position, 1, QTableWidgetItem(ip_address))
        self.records_table.setItem(
            row_position, 2, QTableWidgetItem("A" if record_type == QTYPE.A else "AAAA")
        )
        self.records_table.item(row_position, 2).setFlags(
            self.records_table.item(row_position, 2).flags() & ~Qt.ItemFlag.ItemIsEditable
        )

        self.log_list_widget.addItem(f"Added record: {domain} -> {ip_address}")

        self.saveConfig()

        self.record_count_label.setText(f"Records: {self.records_table.rowCount()}")

        self.domain_name_input.clear()
        self.ip_address_input.clear()

        self.blockSignals(False)

    def onCellChanged(self, row, column):
        if self.signalsBlocked():
            return

        if column == 0:
            new_domain = self.records_table.item(row, 0).text().strip()
            current_type = self.records_table.item(row, 2).text().strip()
            for i in range(self.records_table.rowCount()):
                if i == row:
                    continue
                other_domain = self.records_table.item(i, 0).text().strip()
                other_type = self.records_table.item(i, 2).text().strip()
                if new_domain == other_domain and current_type == other_type:
                    QMessageBox.warning(self, "Duplicate Entry", "A record with this domain and type already exists.")
                    original_domain = self.dns_server.records[row]['domain']
                    self.blockSignals(True)
                    self.records_table.item(row, 0).setText(original_domain)
                    self.blockSignals(False)
                    return


        domain = (
            self.records_table.item(row, 0).text()
            if self.records_table.item(row, 0)
            else ""
        )
        ip_address = (
            self.records_table.item(row, 1).text()
            if self.records_table.item(row, 1)
            else ""
        )
        record_type = (
            self.records_table.item(row, 2).text()
            if self.records_table.item(row, 2)
            else ""
        )

        address_valid = re.match(
            (IPv4_REGEX if record_type == "A" else IPv6_REGEX), ip_address
        )

        if not address_valid:
            QMessageBox.warning(
                self,
                "Input Error",
                f"Invalid {'IPv4' if record_type == 'A' else 'IPv6'} address format.",
            )
            return

        domain_valid = re.match(DOMAIN_REGEX, domain)

        if not domain_valid:
            QMessageBox.warning(self, "Input Error", "Invalid domain format.")
            return

        self.dns_server.records[row] = {
            "domain": domain,
            "ip_address": ip_address,
            "type": QTYPE.A if record_type == "A" else QTYPE.AAAA
        }

        self.log_list_widget.addItem(
            f"Edited {record_type} record: {domain} -> {ip_address}"
        )

        self.saveConfig()

    def startServer(self):
        self.dns_thread = threading.Thread(target=self.dns_server.start)
        self.dns_thread.start()
        self.server_status_label.setText("Server Status: Running")
        self.server_status_label.setStyleSheet("color: green;")

    def stopServer(self):
        self.dns_server.stop()
        self.server_status_label.setText("Server Status: Stopped")
        self.server_status_label.setStyleSheet("color: red;")

    def clearLog(self):
        self.log_list_widget.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DNSServerUI()
    window.show()
    sys.exit(app.exec())

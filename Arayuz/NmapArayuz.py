import asyncio
import socket

from PyQt5 import QtWidgets
import pyqtgraph as pg

from Backend.NmapScanner import NmapScanner


class PostScanDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Post-Scan Options")

        self.layout = QtWidgets.QVBoxLayout(self)

        self.save_button = QtWidgets.QPushButton("Save Results to File")
        self.save_button.clicked.connect(self.save_results)

        self.redirect_button = QtWidgets.QPushButton("Redirect Open Ports to Another Tool")
        self.redirect_button.clicked.connect(self.redirect_ports)

        self.layout.addWidget(self.save_button)
        self.layout.addWidget(self.redirect_button)

    def save_results(self):
        file_dialog = QtWidgets.QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(self, "Save Results", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.results)

    def redirect_ports(self):
        ###
        pass


class HelpDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nmap GUI Scanner - Help")

        self.layout = QtWidgets.QVBoxLayout(self)

        help_text = (
            "Welcome to Nmap GUI Scanner!\n\n"
            "This application allows you to perform Nmap scans using a graphical user interface. "
            "Follow these steps to use the application:\n\n"
            "1. Enter the target IP range(s) in the 'Target IP Range(s)' field. You can enter multiple targets, each on a new line.\n"
            "2. Select the Nmap command category using the 'Nmap Command' dropdown. Available options include TCP Scan Options, UDP Scan Options, and Service Version Detection Options.\n"
            "3. Choose a sub-command from the 'Sub Command' dropdown. This further specifies the Nmap command.\n"
            "4. Optionally, provide advanced options such as IP range, custom ports, and additional options.\n"
            "5. Click the 'Scan' button to start the scan.\n\n"
            "After the scan is complete, you can choose post-scan options, such as saving results to a file or redirecting open ports to another tool.\n"
            "For additional help and information, refer to the documentation or visit the Nmap website: https://nmap.org\n"
        )

        self.help_label = QtWidgets.QLabel(help_text)
        self.layout.addWidget(self.help_label)


class NmapApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()

        self.setupUi()
        self.setWindowTitle("NMAP GUI Scanner")

    def setupUi(self):
        self.layout = QtWidgets.QVBoxLayout(self)

        self.target_label = QtWidgets.QLabel("Target IP Range(s):")
        self.target_input = QtWidgets.QTextEdit()

        self.command_label = QtWidgets.QLabel("Nmap Command:")
        self.command_combos = []

        self.main_command_combo = QtWidgets.QComboBox()
        self.main_command_combo.addItem("TCP Scan Options", "tcp")
        self.main_command_combo.addItem("UDP Scan Options", "udp")
        self.main_command_combo.addItem("Service Version Detection Options", "svd")
        self.main_command_combo.currentIndexChanged.connect(self.update_sub_commands)
        self.layout.addWidget(self.command_label)
        self.layout.addWidget(self.main_command_combo)

        self.sub_command_label = QtWidgets.QLabel("Sub Command:")
        self.sub_command_combo = QtWidgets.QComboBox()
        self.sub_command_combos = {
            "tcp": ["-p 1-1024 -sS", "-p 80 -sS", "-p 443 -sS"],
            "udp": ["-p 1-1024 -sU", "-p 53,67,123 -sU"],
            "svd": ["-p- -sV", "-p 80,443 -sV"]
        }
        self.layout.addWidget(self.sub_command_label)
        self.layout.addWidget(self.sub_command_combo)

        self.advanced_options_label = QtWidgets.QLabel("Advanced Options:")
        self.range_label = QtWidgets.QLabel("IP Range:")
        self.range_input = QtWidgets.QLineEdit()
        self.port_label = QtWidgets.QLabel("Custom Ports (comma separated):")
        self.port_input = QtWidgets.QLineEdit()

        self.layout.addWidget(self.advanced_options_label)
        self.layout.addWidget(self.range_label)
        self.layout.addWidget(self.range_input)
        self.layout.addWidget(self.port_label)
        self.layout.addWidget(self.port_input)

        self.options_label = QtWidgets.QLabel("Additional Options:")
        self.options_input = QtWidgets.QLineEdit()
        self.options_input.setPlaceholderText("e.g., -T4 -O --script=default")

        self.scan_button = QtWidgets.QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)

        self.result_label = QtWidgets.QLabel("Scan Result:")
        self.result_text = QtWidgets.QPlainTextEdit()
        self.result_text.setReadOnly(True)

        self.open_ports_label = QtWidgets.QLabel("Open Ports:")
        self.open_ports_plot = pg.PlotWidget()
        self.layout.addWidget(self.open_ports_label)
        self.layout.addWidget(self.open_ports_plot)

        self.layout.addWidget(self.target_label)
        self.layout.addWidget(self.target_input)
        self.layout.addWidget(self.options_label)
        self.layout.addWidget(self.options_input)
        self.layout.addWidget(self.scan_button)
        self.layout.addWidget(self.result_label)
        self.layout.addWidget(self.result_text)
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.layout.addWidget(self.progress_bar)

        # Help button to show information about using the application
        self.help_button = QtWidgets.QPushButton("Help")
        self.help_button.clicked.connect(self.show_help)
        self.layout.addWidget(self.help_button)

    def update_sub_commands(self, index):
        command_key = self.main_command_combo.currentData()
        sub_commands = self.sub_command_combos.get(command_key, [])
        self.sub_command_combo.clear()
        self.sub_command_combo.addItems(sub_commands)

    def start_scan(self):
        targets_text = self.target_input.toPlainText()
        targets = [target.strip() for target in targets_text.split('\n') if target.strip()]

        for target in targets:
            if not self.is_valid_ip_range(target):
                self.show_error_message(f"Invalid IP Range: {target}")
                return

        target_ports = self.port_input.text()

        main_command = self.main_command_combo.currentText()
        sub_command = self.sub_command_combo.currentText()

        nmap_commands = [f"{main_command} {sub_command} {self.options_input.text()} {target}" for target in targets]

        scanner = NmapScanner(targets, nmap_commands)
        scanner.resultReceived.connect(self.display_result)
        scanner.progressUpdated.connect(self.update_progress)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(scanner.start_scan())



        open_ports = scanner.get_open_ports(targets[-1]) if targets else []
        post_scan_dialog = PostScanDialog(self)
        post_scan_dialog.results = "\n".join(map(str, open_ports))
        post_scan_dialog.exec_()

        self.plot_open_ports(open_ports)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def display_result(self, result):
        self.result_text.setPlainText(result)

    def plot_open_ports(self, open_ports):
        x = list(range(len(open_ports)))
        y = open_ports

        self.open_ports_plot.clear()

        self.open_ports_plot.plot(x, y, pen='b', symbol='o', symbolPen='b', symbolBrush='r')

    def is_valid_ip_range(self, ip_range):
        try:
            socket.inet_aton(ip_range.split('-')[0])
            socket.inet_aton(ip_range.split('-')[1])
            return True
        except (socket.error, IndexError):
            return False

    def show_error_message(self, message):
        error_message = QtWidgets.QMessageBox()
        error_message.setIcon(QtWidgets.QMessageBox.Critical)
        error_message.setText(message)
        error_message.setWindowTitle("Error")
        error_message.exec_()

    def show_help(self):
        help_dialog = HelpDialog(self)
        help_dialog.exec_()


def main():
    app = QtWidgets.QApplication([])
    window = NmapApp()
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()

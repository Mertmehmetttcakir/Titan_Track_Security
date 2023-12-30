from PyQt5 import QtCore
import nmap
import re
import asyncio


class NmapScanner(QtCore.QObject):
    resultReceived = QtCore.pyqtSignal(str)
    progressUpdated = QtCore.pyqtSignal(int)

    def __init__(self, targets, nmap_commands):
        super().__init__()
        self.targets = targets
        self.nmap_commands = nmap_commands
        self.total_progress = len(targets)

    async def scan(self, target, nmap_command):
        nm = nmap.PortScannerAsync()
        scan_command = f"{nmap_command} {target}"
        start_time = QtCore.QTime.currentTime()

        def update_progress(_, remaining):
            elapsed_time = start_time.elapsed()
            total_time = (elapsed_time / self.total_progress) * 100
            self.progressUpdated.emit(total_time)

        await nm.scan(hosts=target, arguments=scan_command, callback=update_progress)
        result = self.parse_nmap_output(nm.csv())
        self.results += result
        self.resultReceived.emit(result)


    def parse_nmap_output(self, raw_output):
        parsed_output = ""
        for line in raw_output.splitlines():
            if line.startswith("host;hostname;hostname_type;protocol;name;state;reason;"):
                continue
            parsed_output += line.replace(";", "\t") + "\n"
        return parsed_output

    def get_open_ports(self, target):
        open_ports = re.findall(r"(\d+)/open", target)
        return [int(port) for port in open_ports]

    async def start_scan(self):
        tasks = []

        for target, nmap_command in zip(self.targets, self.nmap_commands):
            tasks.append(self.scan(target, nmap_command))

        await asyncio.gather(*tasks)


if __name__ == "__main__":

    pass

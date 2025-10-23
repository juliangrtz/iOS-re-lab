import json

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel,
    QTreeWidget, QTreeWidgetItem, QFileDialog, QHBoxLayout
)

from core import logger
from core.concurrency.subprocess import Subprocess
from core.macho.macho import is_macho_file
from core.scan import MachOScanner


def run_scan_process(file_path: str, verbose: bool = True):
    scanner = MachOScanner()
    results = scanner.analyze(file_path, verbose=verbose, out_path=None)
    return json.dumps(results)


class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.qvBoxLayout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        self.label = QLabel("🔍 Mach-O Scanner")
        self.open_button = QPushButton("📂 Open Binary")
        self.open_button.clicked.connect(self._open_file)
        header_layout.addWidget(self.label)
        header_layout.addStretch()
        header_layout.addWidget(self.open_button)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category", "Details"])
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 220)
        self.tree.setAlternatingRowColors(True)

        # todo add spinner

        self.scan_button = QPushButton("Run Scan")
        self.scan_button.setMinimumHeight(30)
        self.scan_button.setStyleSheet("font-weight: bold")
        self.scan_button.clicked.connect(self._on_scan_clicked)
        self.scan_button.setEnabled(False)

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addWidget(self.scan_button)
        self.qvBoxLayout.addWidget(self.tree)

        self.setAcceptDrops(True)

        self.file_path = None
        self.worker = Subprocess()

    def _toggle_button_states(self, on):
        self.scan_button.setEnabled(on)
        self.open_button.setEnabled(on)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if any(url.toLocalFile().endswith((".macho", "")) for url in urls):
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    def dropEvent(self, event):
        # todo forbid drop when already scanning
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if file_path and is_macho_file(file_path):
                self._handle_dropped_file(file_path)
                event.acceptProposedAction()

    def _handle_dropped_file(self, file_path: str):
        self.file_path = file_path
        self._run_scan()

    def _open_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Mach-O File", "", "Mach-O Files (*)"
        )
        if file and is_macho_file(file):
            self.file_path = file
            self.scan_button.setEnabled(True)
            self.label.setText(f"🔍 Mach-O Scanner — {file.split('/')[-1]}")
            self.tree.clear()
            root = QTreeWidgetItem(["Selected File", file])
            self.tree.addTopLevelItem(root)

    def _on_scan_clicked(self):
        if not self.file_path:
            return
        self._run_scan()

    def _run_scan(self):
        if not self.file_path:
            return

        logger.info("Mach-O scanner started :: " + self.file_path)

        self._toggle_button_states(False)
        self.tree.clear()
        status_root = QTreeWidgetItem(["Status", "Scanning..."])
        self.tree.addTopLevelItem(status_root)

        self.worker.submit(
            run_scan_process,
            self.file_path,
            True,
            on_done=self._on_finish,
            on_error=self._display_error
        )

    def _on_finish(self, json_results):
        logger.info("Mach-O scanner finished!")

        self.tree.clear()
        root = QTreeWidgetItem(["Scan Results", self.file_path])
        self.tree.addTopLevelItem(root)

        for i, result in enumerate(json.loads(json_results), 1):
            result_item = QTreeWidgetItem(["Binary"])
            root.addChild(result_item)

            for category, data in result.items():
                cat_item = QTreeWidgetItem([category])
                result_item.addChild(cat_item)

                if category == "syscalls" and isinstance(data, list):
                    for s in data:
                        syscall_item = QTreeWidgetItem([
                            f"{s.get('name', 'unknown')}",
                            f"section: {s.get('section', '')}, offset: {s.get('offset', '')}"
                        ])
                        cat_item.addChild(syscall_item)
                elif isinstance(data, dict):
                    for k, v in data.items():
                        sub_item = QTreeWidgetItem([str(k), str(v)])
                        cat_item.addChild(sub_item)
                elif isinstance(data, list):
                    for v in data:
                        sub_item = QTreeWidgetItem(["Entry", str(v)])
                        cat_item.addChild(sub_item)
                else:
                    cat_item.addChild(QTreeWidgetItem(["Value", str(data)]))

        root.setExpanded(True)
        self.tree.expandAll()
        self._toggle_button_states(True)

    def _display_error(self, error):
        self.tree.clear()
        self.tree.addTopLevelItem(QTreeWidgetItem(["Error", str(error)]))
        self._toggle_button_states(True)
        logger.error(f"Mach-O scanner failed: {error}")

    def closeEvent(self, event):
        self.worker.shutdown(wait=False, cancel_futures=True)
        super().closeEvent(event)

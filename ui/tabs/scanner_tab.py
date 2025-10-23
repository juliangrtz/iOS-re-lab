import json

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QHBoxLayout
)

from core import logger
from core.concurrency.subprocess import Subprocess
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
        header_layout.addWidget(self.label)
        header_layout.addStretch()

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category", "Details"])
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 220)
        self.tree.setAlternatingRowColors(True)

        # todo add spinner

        self.qvBoxLayout.addLayout(header_layout)
        self.qvBoxLayout.addWidget(self.tree)

        self.setAcceptDrops(True)

        self.file_path = None
        self.worker = Subprocess()

    def run_scan(self, file_path):
        if not file_path:
            return

        self.file_path = file_path
        logger.info("Mach-O scanner started :: " + file_path)

        self.tree.clear()
        status_root = QTreeWidgetItem(["Status", "Scanning..."])
        self.tree.addTopLevelItem(status_root)

        self.worker.submit(
            run_scan_process,
            file_path,
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

    def _display_error(self, error):
        self.tree.clear()
        self.tree.addTopLevelItem(QTreeWidgetItem(["Error", str(error)]))
        logger.error(f"Mach-O scanner failed: {error}")

    def closeEvent(self, event):
        self.worker.shutdown(wait=False, cancel_futures=True)
        super().closeEvent(event)

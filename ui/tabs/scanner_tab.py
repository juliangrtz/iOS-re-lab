from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem, QFileDialog, QHBoxLayout
)
from core.scan import MachOScanner


class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        self.label = QLabel("🔍 Mach-O Scanner")
        self.open_button = QPushButton("📂 Open File")
        self.open_button.clicked.connect(self._open_file)
        header_layout.addWidget(self.label)
        header_layout.addStretch()
        header_layout.addWidget(self.open_button)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category", "Details"])
        self.tree.header().setStretchLastSection(True)
        self.tree.setColumnWidth(0, 220)
        self.tree.setAlternatingRowColors(True)

        self.scan_button = QPushButton("Run Scan")
        self.scan_button.clicked.connect(self._on_scan_clicked)
        self.scan_button.setEnabled(False)

        self.layout.addLayout(header_layout)
        self.layout.addWidget(self.scan_button)
        self.layout.addWidget(self.tree)

        self.file_path = None
        self.scanner = MachOScanner()

    def _open_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Mach-O File", "", "Mach-O Files (*)"
        )
        if file:
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
        self.scan_button.setEnabled(False)
        self.tree.clear()
        status_root = QTreeWidgetItem(["Status", "Scanning..."])
        self.tree.addTopLevelItem(status_root)

        # TODO: This is a blocking call, UI will freeze here for large files!
        results = self.scanner.analyze(self.file_path, verbose=True)

        print(results)

        self.tree.clear()
        root = QTreeWidgetItem(["Scan Results", self.file_path])
        self.tree.addTopLevelItem(root)

        for i, result in enumerate(results, 1):
            result_item = QTreeWidgetItem([f"Binary"])
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

                        # context = s.get("context", [])
                        # for ins in context[-12:]:  # last 12 instructions
                        #    ctx_item = QTreeWidgetItem([
                        #        f"0x{ins['address']:x} {ins['mnemonic']}",
                        #        ins.get("op_str", "")
                        #    ])
                        #    syscall_item.addChild(ctx_item)

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
        self.scan_button.setEnabled(True)

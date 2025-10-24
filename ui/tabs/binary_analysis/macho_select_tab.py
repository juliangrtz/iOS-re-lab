from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QCheckBox, QFrame, QGroupBox, QPushButton, QFileDialog
)

from core import logger
from core.analysis_config import ANALYSIS_CONFIG
from core.macho.macho import is_macho_file


class MachOSelectTab(QWidget):
    def __init__(self, scanner_tab=None, disasm_tab=None, info_tab=None):
        super().__init__()
        self.setAcceptDrops(True)
        self.disasm_tab = disasm_tab
        self.scanner_tab = scanner_tab
        self.info_tab = info_tab

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)

        self.drag_drop_frame = QFrame()
        self.drag_drop_frame.setFrameShape(QFrame.StyledPanel)
        self.drag_drop_frame.setStyleSheet(
            "QFrame {border: 2px dashed gray; border-radius: 8px;}"
            "QFrame:hover {border-color: #0078d7;}"
        )
        drag_layout = QVBoxLayout(self.drag_drop_frame)
        drag_layout.setContentsMargins(10, 20, 10, 20)

        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignCenter)
        self.file_label.setStyleSheet("font-weight: bold; font-size: 15px; color: #555;")
        drag_layout.addWidget(self.file_label)

        main_layout.addWidget(self.drag_drop_frame)

        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout(options_group)

        self.scan_checkbox = QCheckBox("Scan binary for suspicious artifacts")
        options_layout.addWidget(self.scan_checkbox)
        self.scan_checkbox.setChecked(True)

        self.disasm_checkbox = QCheckBox("Disassemble binary")
        options_layout.addWidget(self.disasm_checkbox)
        self.disasm_checkbox.setChecked(True)

        self.scan_checkbox.stateChanged.connect(self._update_config)
        self.disasm_checkbox.stateChanged.connect(self._update_config)

        main_layout.addWidget(options_group)

        self.start_btn = QPushButton("Start")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.setStyleSheet("font-weight: bold; font-size: 20px;")
        self.start_btn.clicked.connect(self._on_start)
        self.start_btn.setEnabled(False)
        main_layout.addWidget(self.start_btn)

    def mousePressEvent(self, event):
        if self.drag_drop_frame.geometry().contains(event.position().toPoint()):
            self._open_file()
        super().mousePressEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if file_path and is_macho_file(file_path):
                self.set_file(file_path)
                event.acceptProposedAction()

    def _open_file(self):
        file, _ = QFileDialog.getOpenFileName(
            self, "Select Mach-O File", "", "Mach-O Files (*)"
        )
        if file and is_macho_file(file):
            self.set_file(file)

    def set_file(self, file_path: str):
        ANALYSIS_CONFIG.file_path = file_path
        self.file_label.setText(f"Selected File: {file_path.split('/')[-1]}")
        self._update_config()
        self.start_btn.setEnabled(True)

    def _update_config(self):
        ANALYSIS_CONFIG.options = {
            "scan": self.scan_checkbox.isChecked(),
            "disasm": self.disasm_checkbox.isChecked(),
        }

    def _on_start(self):
        file_path = ANALYSIS_CONFIG.file_path
        if not file_path:
            logger.warn("No Mach-O file selected!")
            return

        self.info_tab.load_macho(file_path)

        if ANALYSIS_CONFIG.options.get("disasm") and self.disasm_tab:
            self.disasm_tab.start_disassembly(file_path)

        if ANALYSIS_CONFIG.options.get("scan") and self.scanner_tab:
            self.scanner_tab.run_scan(file_path)
